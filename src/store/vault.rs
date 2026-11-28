//! The 1Password store (docs/adr/0001): a vault, reached through opcore
//! (docs/adr/0004) as a service account. Selected by
//! `SESAME_1PASSWORD_VAULT`; the token is `OP_SERVICE_ACCOUNT_TOKEN`.
//!
//! - `sesame.<provider>`: the provider's client and token, one item each, so
//!   two machines writing different providers never overwrite each other.
//!   How its values lie in it is `item`'s.
//! - `sesame-providers`: the person's provider fields, one text field per
//!   provider holding them as JSON. One item, so every command reads all
//!   definitions in one request.
//!
//! Each item is tagged `sesame`, a Secure Note.
//!
//! Reads answer from opcore's Copy of the vault, on demand (docs/adr/0006):
//! no sign-in, at any age of the Copy. It syncs (one list, one `get_all` of
//! what moved) only before a refresh (`latest_token`), for `sesame
//! providers` (`Store::open_current`), and when there is no Copy. Each
//! write is staged on the Copy and pushed in the same process; one
//! 1Password cannot take now waits in the Copy's pending writes, which the
//! next sync pushes first, and reads see it meanwhile.
mod item;
mod old_copy;
#[cfg(debug_assertions)]
mod stand_in;

use super::{Client, Token};
use crate::providers::Fields;
use item::{Kept, is_provider_field, kept};
use opcore::core::{Core, Failure, Wasm};
use opcore::{Category, Copy, Error, Item, ItemParams, Syncs};
use std::cell::{Cell, RefCell, RefMut};
use std::collections::BTreeMap;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::SystemTime;

pub const VAULT_VAR: &str = "SESAME_1PASSWORD_VAULT";
pub const TOKEN_VAR: &str = "OP_SERVICE_ACCOUNT_TOKEN";
const TAG: &str = "sesame";
/// The item holding every provider's fields. Not `sesame.<x>`, so it is no
/// provider's.
const DEFINITIONS: &str = "sesame-providers";
/// The Copy's file in the config dir; its pending writes are beside it, with
/// `.pending` after the name.
const COPY_FILE: &str = "vault-copy";
/// The command that syncs, so pushes what waits: what opcore's warnings name.
const PUSH: &str = "sesame providers";
/// The service account token, taken out of the environment (`take_token`).
static SERVICE_TOKEN: OnceLock<Option<String>> = OnceLock::new();

/// Takes the service account token out of this process's environment, so
/// that no child gets it (a browser sesame opens). Called first thing in
/// `main`, before any thread or child.
pub fn take_token() {
    let token = std::env::var(TOKEN_VAR).ok().filter(|t| !t.is_empty());
    // SAFETY: called at the start of main, before any other thread exists.
    unsafe { std::env::remove_var(TOKEN_VAR) };
    let _ = SERVICE_TOKEN.set(token);
}

fn service_token() -> Option<String> {
    SERVICE_TOKEN.get().cloned().flatten()
}

fn vault_name() -> Option<String> {
    std::env::var(VAULT_VAR).ok().filter(|v| !v.is_empty())
}

/// The Core the Copy signs in on: 1Password's, made at the first sign-in
/// (a command the Copy answers never makes one); in a debug build with
/// `stand_in::DIR_VAR` set, the tests' stand-in.
pub enum Backend {
    Wasm(Option<Box<Wasm>>),
    #[cfg(debug_assertions)]
    Stand(stand_in::Stand),
}

impl Backend {
    fn from_env() -> Backend {
        #[cfg(debug_assertions)]
        if let Some(dir) = std::env::var_os(stand_in::DIR_VAR) {
            return Backend::Stand(stand_in::Stand::new(dir.into()));
        }
        Backend::Wasm(None)
    }

    fn core(&mut self) -> Result<&mut dyn Core, Failure> {
        match self {
            Backend::Wasm(made) => {
                if made.is_none() {
                    *made = Some(Box::new(Wasm::new()?));
                }
                Ok(made.as_deref_mut().expect("made above"))
            }
            #[cfg(debug_assertions)]
            Backend::Stand(s) => Ok(s),
        }
    }
}

impl Core for Backend {
    fn init_client(&mut self, config: &str) -> Result<String, Failure> {
        self.core()?.init_client(config)
    }

    fn invoke(&mut self, invocation: &str) -> Result<String, Failure> {
        self.core()?.invoke(invocation)
    }

    fn release_client(&mut self, id: &str) {
        if let Ok(core) = self.core() {
            core.release_client(id);
        }
    }
}

/// A file's length and modification time, if it is there.
type Seen = Option<(u64, Option<SystemTime>)>;

pub struct Vault {
    name: String,
    token: String,
    /// The config dir: the Copy, its pending writes and the lock.
    dir: PathBuf,
    /// A Core for each Copy opened.
    core: Box<dyn Fn() -> Backend>,
    copy: RefCell<Copy<Backend>>,
    /// The Copy's items as its last read answered them, until anything
    /// changes it: one read (and one warning of what waits) a process.
    items: RefCell<Option<Vec<Item>>>,
    /// The Copy's file and its pending writes' as this process last left
    /// them: changed when the lock is taken, another process wrote them.
    seen: Cell<(Seen, Seen)>,
    /// Whether this vault holds the lock (a nested `locked` runs inside it).
    held: Cell<bool>,
    /// Whether the Copy as this process holds it synced in this process:
    /// as current as this process can make it.
    synced: Cell<bool>,
}

/// How a write went.
enum Pushed {
    /// In the vault, or nothing to write.
    Landed,
    /// Still pending, and why.
    Waits(String),
    /// Refused by 1Password and dropped (as opcore drops it), and why.
    Refused(String),
}

impl Vault {
    /// The vault `SESAME_1PASSWORD_VAULT` names, if any. Named, it must be
    /// usable: a missing token is an error naming it. `current`: sync the
    /// Copy first (a status listing).
    pub fn from_env(current: bool) -> Result<Option<Vault>, String> {
        let Some(name) = vault_name() else {
            return Ok(None);
        };
        let token = service_token().ok_or_else(|| {
            format!(
                "{VAULT_VAR} is set (`{name}`), so sesame keeps its clients and tokens in that \
                 1Password vault, but {TOKEN_VAR} is not set: give it the service account's \
                 token, or unset {VAULT_VAR} to use sesame.db"
            )
        })?;
        let v = Vault::new(
            name,
            token,
            super::config_dir(),
            Box::new(Backend::from_env),
        );
        v.retire_old_copy()?;
        if current {
            v.locked(|| v.sync())?;
        }
        Ok(Some(v))
    }

    /// Vault `name` as service account `token`, its Copy in `dir`, each
    /// Copy signing in on a Core `core` makes.
    fn new(name: String, token: String, dir: PathBuf, core: Box<dyn Fn() -> Backend>) -> Vault {
        let copy = open_copy(&dir, &token, &name, core());
        let v = Vault {
            name,
            token,
            dir,
            core,
            copy: RefCell::new(copy),
            items: RefCell::new(None),
            seen: Cell::new((None, None)),
            held: Cell::new(false),
            synced: Cell::new(false),
        };
        v.seen.set(v.files());
        v
    }

    /// The Copy, for a call that may change it: its items are read again.
    fn copy(&self) -> RefMut<'_, Copy<Backend>> {
        *self.items.borrow_mut() = None;
        self.copy.borrow_mut()
    }

    fn copy_path(&self) -> PathBuf {
        self.dir.join(COPY_FILE)
    }

    fn pending_path(&self) -> PathBuf {
        self.dir.join(format!("{COPY_FILE}.pending"))
    }

    /// The Copy's file and its pending writes' as they are on disk now.
    fn files(&self) -> (Seen, Seen) {
        let seen = |p: PathBuf| {
            std::fs::metadata(p)
                .ok()
                .map(|m| (m.len(), m.modified().ok()))
        };
        (seen(self.copy_path()), seen(self.pending_path()))
    }

    /// Makes the Copy the vault's: one list, one `get_all` of the items
    /// that moved, after pushing what waits.
    pub fn sync(&self) -> Result<(), String> {
        self.copy().sync().map_err(|e| self.failed(e))?;
        self.synced.set(true);
        Ok(())
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn failed(&self, e: Error) -> String {
        format!("1Password vault `{}`: {e}", self.name)
    }

    /// The old format's Copy (`old_copy`) is not opened: the tokens it holds
    /// unwritten are written to the vault (the Copy synced first), then it
    /// is removed. One that does not open goes at once.
    fn retire_old_copy(&self) -> Result<(), String> {
        let old = old_copy::path(&self.dir);
        if !old.exists() {
            return Ok(());
        }
        let unwritten = old_copy::unwritten_tokens(&old, &self.name, &self.token);
        if !unwritten.is_empty() {
            self.locked(|| {
                for (provider, t) in &unwritten {
                    let put = |k: &mut Kept| item::put_token(k, t);
                    let (_, pushed) = self.write(&title(provider), &is_provider_field, &put)?;
                    self.warn_unless_landed(provider, pushed);
                }
                Ok(())
            })?;
        }
        std::fs::remove_file(&old).map_err(|e| format!("{}: {e}", old.display()))
    }

    /// The item titled `title` as the Copy holds it, its pending writes
    /// made; the Copy is synced first only if there is none.
    fn item(&self, title: &str) -> Result<Option<Item>, String> {
        let find = |items: &[Item]| items.iter().find(|i| i.title == title).cloned();
        if let Some(items) = self.items.borrow().as_deref() {
            return Ok(find(items));
        }
        let before = self.files();
        let items: Vec<Item> = {
            let mut copy = self.copy.borrow_mut();
            let items = copy.items().map_err(|e| self.failed(e))?;
            items.into_iter().cloned().collect()
        };
        // A first sync here, outside the lock, is this process's own write:
        // the lock need not reopen the Copy for it (and sign in again).
        // With no Copy before, it synced.
        self.synced.set(self.synced.get() || before.0.is_none());
        if before == self.seen.get() {
            self.seen.set(self.files());
        }
        let found = find(&items);
        *self.items.borrow_mut() = Some(items);
        Ok(found)
    }

    /// What sesame keeps in item `title`, of the fields `ours` names.
    fn kept(&self, title: &str, ours: impl Fn(&str) -> bool) -> Result<Kept, String> {
        Ok(self
            .item(title)?
            .map(|i| kept(&i, ours))
            .unwrap_or_default())
    }

    /// Runs `f` holding this machine's lock, with the Copy as another
    /// process may have left it: 1Password has no lock, so this keeps two
    /// processes here from both refreshing one token.
    pub fn locked<T>(&self, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        if self.held.replace(true) {
            return f();
        }
        let result = (|| {
            let lock = lock_file(&self.dir)?;
            lock.lock().map_err(|e| format!("locking: {e}"))?;
            if self.files() != self.seen.get() {
                *self.copy() = open_copy(&self.dir, &self.token, &self.name, (self.core)());
                self.synced.set(false);
            }
            let result = f();
            self.seen.set(self.files());
            result
        })();
        self.held.set(false);
        result
    }

    /// Changes what sesame keeps in the item `title` with `change`, and,
    /// if that changed it, writes it through (`write`). Refused, or waiting
    /// because 1Password cannot take it now, an error says so. What sesame
    /// kept in it before.
    fn update(
        &self,
        title: &str,
        ours: impl Fn(&str) -> bool,
        change: impl Fn(&mut Kept),
    ) -> Result<Kept, String> {
        self.locked(|| {
            let (had, pushed) = self.write(title, &ours, &change)?;
            let failed =
                |why: String| format!("1Password vault `{}`: writing `{title}`: {why}", self.name);
            match pushed {
                Pushed::Landed => Ok(had),
                Pushed::Waits(why) => Err(failed(format!(
                    "{why}; the write waits in `{}`, and the next sync (`{PUSH}`) pushes it",
                    self.pending_path().display()
                ))),
                Pushed::Refused(why) => Err(failed(why)),
            }
        })
    }

    /// Writes `change` to what sesame keeps in item `title`: staged, then
    /// pushed at once. An item gone from the vault since the Copy read it
    /// (archived elsewhere) refuses the edit: it is made anew. What sesame
    /// kept in it before, and how the write went.
    fn write(
        &self,
        title: &str,
        ours: &dyn Fn(&str) -> bool,
        change: &dyn Fn(&mut Kept),
    ) -> Result<(Kept, Pushed), String> {
        let (had, Some(want)) = self.stage(title, ours, change)? else {
            return Ok((self.kept(title, ours)?, Pushed::Landed));
        };
        let pushed = self.push(title, ours, &want)?;
        if !matches!(pushed, Pushed::Refused(_)) || self.item(title)?.is_some() {
            return Ok((had, pushed));
        }
        match self.stage(title, ours, change)? {
            (_, Some(want)) => Ok((had, self.push(title, ours, &want)?)),
            (_, None) => Ok((had, pushed)),
        }
    }

    /// Stages the write of item `title` that `change` makes to what sesame
    /// keeps in it: created when new, archived when left with nothing in
    /// it, else edited keeping what others put there. None when nothing
    /// changes. What sesame kept in it before, and what it is to keep now if
    /// a write was staged.
    fn stage(
        &self,
        title: &str,
        ours: &dyn Fn(&str) -> bool,
        change: &dyn Fn(&mut Kept),
    ) -> Result<(Kept, Option<Kept>), String> {
        let wants = |current: &Option<Item>| {
            let have = current.as_ref().map(|i| kept(i, ours)).unwrap_or_default();
            let mut want = have.clone();
            change(&mut want);
            (have, want)
        };
        let mut current = self.item(title)?;
        let (mut have, mut want) = wants(&current);
        if current.is_none() && want != have && !self.synced.get() {
            // Another machine may have made it since this Copy synced: a
            // create would make a second item of the title.
            self.sync()?;
            current = self.item(title)?;
            (have, want) = wants(&current);
        }
        if want == have {
            return Ok((have, None));
        }
        let mut copy = self.copy();
        let staged = match current {
            None => {
                let params = ItemParams {
                    title: title.into(),
                    category: Category::SecureNote,
                    tags: vec![TAG.into()],
                    fields: item::fields(&want),
                    ..Default::default()
                };
                copy.create_all(&[params]).map(drop)
            }
            // Archived, not deleted: it can be restored in 1Password.
            Some(i) if want.is_empty() && kept(&i, |l| !ours(l)).is_empty() => {
                copy.archive_all(&[&i.id])
            }
            Some(mut i) => {
                if !i.tags.iter().any(|t| t == TAG) {
                    i.tags.push(TAG.into());
                }
                i.fields.retain(|f| !item::is_ours(f, ours));
                i.fields.extend(item::fields(&want));
                let params = ItemParams {
                    title: title.into(),
                    category: i.category,
                    fields: i.fields,
                    sections: i.sections,
                    notes: i.notes,
                    tags: i.tags,
                };
                copy.edit(&i.id, &params).map(drop)
            }
        };
        staged.map_err(|e| self.failed(e))?;
        Ok((have, Some(want)))
    }

    /// Pushes every write staged on this machine, in one sync: how the one
    /// of item `title`, to keep `want`, went. Landed when the Copy, synced
    /// by the push, holds it and nothing of it waits.
    fn push(
        &self,
        title: &str,
        ours: &dyn Fn(&str) -> bool,
        want: &Kept,
    ) -> Result<Pushed, String> {
        let (failed, refused, waits) = {
            let mut copy = self.copy();
            let before = copy.write_warnings().len();
            let failed = copy.push().err();
            // A push is a sync (opcore's `push`, on demand).
            self.synced.set(self.synced.get() || failed.is_none());
            let refused: Vec<String> = copy.write_warnings()[before..]
                .iter()
                .filter(|w| w.contains("refused"))
                .cloned()
                .collect();
            let pending = copy.pending().map_err(|e| self.failed(e))?;
            (failed, refused, pending.iter().any(|p| p.title == title))
        };
        Ok(match (failed, waits) {
            (Some(e), _) => Pushed::Waits(e.to_string()),
            (None, true) => Pushed::Waits("1Password did not take it now".into()),
            (None, false) if self.kept(title, ours)? == *want => Pushed::Landed,
            (None, false) => Pushed::Refused(
                refused
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| "1Password did not take it".into()),
            ),
        })
    }

    /// Says on stderr how `provider`'s new token's write went, unless it
    /// landed: it waits (this machine uses it meanwhile), or was refused.
    fn warn_unless_landed(&self, provider: &str, pushed: Pushed) {
        match pushed {
            Pushed::Landed => {}
            Pushed::Waits(why) => eprintln!(
                "sesame: warning: could not write the new `{provider}` token to the vault: {why}\n\
                 This machine keeps it in `{}` and uses it; the next sync pushes it first.",
                self.pending_path().display()
            ),
            Pushed::Refused(why) => eprintln!(
                "sesame: warning: could not write the new `{provider}` token to the vault: {why}\n\
                 This command's token is valid; the next refresh uses the vault's."
            ),
        }
    }

    pub fn client(&self, provider: &str) -> Result<Option<Client>, String> {
        Ok(item::client_of(
            &self.kept(&title(provider), is_provider_field)?,
        ))
    }

    pub fn save_client(&self, provider: &str, c: &Client) -> Result<(), String> {
        self.save_login(provider, Some(c), None)
    }

    /// Stores whichever of the provider's client and token are given, in one
    /// write (none if nothing changes).
    pub fn save_login(
        &self,
        provider: &str,
        c: Option<&Client>,
        t: Option<&Token>,
    ) -> Result<(), String> {
        self.update(&title(provider), is_provider_field, |k| {
            if let Some(c) = c {
                item::put_client(k, c);
            }
            if let Some(t) = t {
                item::put_token(k, t);
            }
        })
        .map(drop)
    }

    pub fn delete_client(&self, provider: &str) -> Result<bool, String> {
        let had = self.update(&title(provider), is_provider_field, |k| {
            k.retain(|l, _| !item::CLIENT_FIELDS.contains(&l.as_str()));
        })?;
        Ok(item::client_of(&had).is_some())
    }

    /// `provider`'s token after a sync: what a refresh decides on. A sync
    /// that cannot reach 1Password now (the network, the rate limit) leaves
    /// the Copy's, with a warning: this machine refreshes with its own.
    pub fn latest_token(&self, provider: &str) -> Result<Option<Token>, String> {
        self.locked(|| {
            let synced = self.copy().sync();
            self.synced.set(self.synced.get() || synced.is_ok());
            match synced {
                Err(e) if e.is_transient() => eprintln!(
                    "sesame: warning: 1Password could not be synced ({e}); the `{provider}` \
                     token is this machine's"
                ),
                synced => synced.map_err(|e| self.failed(e))?,
            }
            self.token(provider)
        })
    }

    pub fn token(&self, provider: &str) -> Result<Option<Token>, String> {
        let t = title(provider);
        item::token_of(&self.kept(&t, is_provider_field)?)
            .map_err(|e| format!("1Password vault `{}`: {t}/{e}", self.name))
    }

    pub fn save_token(&self, provider: &str, t: &Token) -> Result<(), String> {
        self.save_login(provider, None, Some(t))
    }

    /// Stores `t`, a token the provider issued in place of the stored one,
    /// staged and pushed at once: another machine needs it now where the
    /// provider rotates its refresh token. One 1Password cannot take now
    /// waits staged; the command still has it, with a warning, and this
    /// machine uses it until the next sync pushes it (docs/adr/0006).
    pub fn keep_token(&self, provider: &str, t: &Token) -> Result<(), String> {
        let Some(t) = self.as_kept_token(t) else {
            return self.save_token(provider, t);
        };
        self.locked(|| {
            let put = |k: &mut Kept| item::put_token(k, &t);
            let (_, pushed) = self.write(&title(provider), &is_provider_field, &put)?;
            self.warn_unless_landed(provider, pushed);
            Ok(())
        })
    }

    pub fn delete_token(&self, provider: &str) -> Result<(), String> {
        self.update(&title(provider), is_provider_field, |k| {
            k.retain(|l, _| !item::TOKEN_FIELDS.contains(&l.as_str()));
        })
        .map(drop)
    }

    pub fn provider_fields(&self) -> Result<BTreeMap<String, Fields>, String> {
        item::definitions(&self.kept(DEFINITIONS, |_| true)?)
            .map_err(|e| format!("1Password vault `{}`: {DEFINITIONS}/{e}", self.name))
    }

    /// Replaces the provider's stored fields; none removes its field.
    pub fn save_provider_fields(&self, provider: &str, fields: &Fields) -> Result<(), String> {
        self.save_many_provider_fields(&BTreeMap::from([(provider.to_string(), fields.clone())]))
    }

    /// Replaces the stored fields of each provider in `all`, in one write.
    pub fn save_many_provider_fields(&self, all: &BTreeMap<String, Fields>) -> Result<(), String> {
        self.update(
            DEFINITIONS,
            |_| true,
            |k| {
                for (provider, fields) in all {
                    item::put_definition(k, provider, fields);
                }
            },
        )
        .map(drop)
    }

    /// `c` as the vault keeps it, what `client` reads back after
    /// `save_client(c)`: an empty value is no value, so none without an id.
    pub fn as_kept_client(&self, c: &Client) -> Option<Client> {
        let mut k = Kept::new();
        item::put_client(&mut k, c);
        item::client_of(&k)
    }

    /// `t` as the vault keeps it, what `token` reads back after
    /// `save_token(t)`: an empty value is no value, so none without an
    /// access token.
    pub fn as_kept_token(&self, t: &Token) -> Option<Token> {
        let mut k = Kept::new();
        item::put_token(&mut k, t);
        // What `put_token` wrote reads back: its expiry is a number.
        item::token_of(&k).ok().flatten()
    }
}

/// Vault `name`'s Copy in `dir`, sealed under `token`, syncing on demand.
fn open_copy(dir: &Path, token: &str, name: &str, core: Backend) -> Copy<Backend> {
    let syncs = Syncs::OnDemand { push: PUSH.into() };
    Copy::with_core(core, &dir.join(COPY_FILE), token, name, TAG, syncs)
}

/// `<config_dir>/sesame.lock`, made 0600 in a 0700 directory. It holds nothing.
fn lock_file(dir: &Path) -> Result<std::fs::File, String> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join("sesame.lock");
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// The item holding a provider's client and token.
fn title(provider: &str) -> String {
    format!("sesame.{provider}")
}

#[cfg(test)]
mod tests {
    use super::stand_in::{self, Stand};
    use super::*;
    use opcore::{FieldType, ItemField, ItemSection};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SA: &str = "sa-token";

    fn scratch_dir(what: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("sesame-vault-{}-{n}-{what}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The vault `v` on the stand-in Core, in a dir of its own.
    struct OnePassword(PathBuf);

    impl OnePassword {
        fn new() -> OnePassword {
            static TOKEN: std::sync::Once = std::sync::Once::new();
            // SAFETY: set once, to the one value every test reads.
            TOKEN.call_once(|| unsafe { std::env::set_var(stand_in::TOKEN_VAR, SA) });
            OnePassword(scratch_dir("1password"))
        }

        fn stand(&self) -> Stand {
            Stand::on(self.0.clone(), "v")
        }

        /// The Core methods called since the last `calls`.
        fn calls(&self) -> Vec<String> {
            let log = self.0.join("calls.log");
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            let _ = std::fs::remove_file(&log);
            text.lines().map(String::from).collect()
        }

        /// Creates an item as another machine would, calling it no call of
        /// this test's; its id.
        fn add(&self, params: ItemParams) -> String {
            let mut c = opcore::Client::with_core(self.stand(), SA, "v").unwrap();
            let id = c.create_all(&[params]).unwrap().remove(0).id;
            self.calls();
            id
        }

        /// Changes item `id` as another machine would.
        fn change(&self, id: &str, f: impl FnOnce(&mut Item)) {
            let mut c = opcore::Client::with_core(self.stand(), SA, "v").unwrap();
            let mut item = c.get_all(&[id]).unwrap().remove(0);
            f(&mut item);
            let params = ItemParams {
                title: item.title,
                category: item.category,
                fields: item.fields,
                sections: item.sections,
                notes: item.notes,
                tags: item.tags,
            };
            c.edit(id, &params).unwrap();
            self.calls();
        }

        /// The item titled `title`, as 1Password holds it.
        fn item(&self, title: &str) -> Option<Item> {
            let mut c = opcore::Client::with_core(self.stand(), SA, "v").unwrap();
            let listed = c.list(TAG).unwrap();
            let id = listed.into_iter().find(|l| l.title == title).map(|l| l.id);
            let item = id.map(|id| c.get_all(&[&id]).unwrap().remove(0));
            self.calls();
            item
        }
    }

    impl Drop for OnePassword {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A machine: its config dir, and the process now running sesame there.
    struct Machine {
        vault: Vault,
        dir: PathBuf,
        op: PathBuf,
    }

    impl Machine {
        fn new(op: &OnePassword) -> Machine {
            Machine::in_dir(op, scratch_dir("machine"))
        }

        fn in_dir(op: &OnePassword, dir: PathBuf) -> Machine {
            let at = op.0.clone();
            let core = Box::new(move || Backend::Stand(Stand::on(at.clone(), "v")));
            let vault = Vault::new("v".into(), SA.into(), dir.clone(), core);
            Machine {
                vault,
                dir,
                op: op.0.clone(),
            }
        }

        /// The next process on this machine.
        fn again(&self) -> Machine {
            self.again_with(None)
        }

        /// The next process on this machine, 1Password answering it with
        /// `fault` (`stand_in::Stand::with_fault`).
        fn again_with(&self, fault: Option<&'static str>) -> Machine {
            let core = {
                let at = self.op.clone();
                Box::new(move || {
                    let stand = Stand::on(at.clone(), "v");
                    Backend::Stand(
                        fault.map_or(Stand::on(at.clone(), "v"), |f| stand.with_fault(f)),
                    )
                })
            };
            Machine {
                vault: Vault::new("v".into(), SA.into(), self.dir.clone(), core),
                dir: self.dir.clone(),
                op: self.op.clone(),
            }
        }
    }

    impl std::ops::Deref for Machine {
        type Target = Vault;
        fn deref(&self) -> &Vault {
            &self.vault
        }
    }

    fn client(id: &str) -> Client {
        Client {
            client_id: id.into(),
            client_secret: Some(format!("{id}-secret")),
        }
    }

    fn token(access: &str) -> Token {
        Token {
            access_token: access.into(),
            refresh_token: Some("refresh".into()),
            expires_at: Some(1_800_000_000),
            scope: Some("repo".into()),
            resource_id: None,
            resource_name: None,
            pasted: false,
            account: Some("octo".into()),
        }
    }

    fn text(title: &str, value: &str) -> ItemField {
        ItemField {
            id: title.into(),
            title: title.into(),
            field_type: FieldType::Text,
            value: value.into(),
            ..Default::default()
        }
    }

    fn note(title: &str, fields: Vec<ItemField>) -> ItemParams {
        ItemParams {
            title: title.into(),
            category: Category::SecureNote,
            tags: vec![TAG.into()],
            fields,
            ..Default::default()
        }
    }

    /// A first sync on a machine with no Copy: the sign-in, the vault
    /// found, the list, and a read of what it lacks (if anything).
    const FIRST_SYNC: [&str; 4] = ["init_client", "VaultsList", "ItemsList", "ItemsGetAll"];
    /// A write staged and pushed by a process signed in: the list, a read of
    /// the item as 1Password holds it now, then the write.
    const PUSHED_EDIT: [&str; 3] = ["ItemsList", "ItemsGetAll", "ItemsPut"];

    #[test]
    fn a_value_sesame_cannot_read_is_an_error_naming_the_vault_item_and_field() {
        let op = OnePassword::new();
        op.add(note(
            "sesame.x",
            vec![text("access_token", "a"), text("expires_at", "soon")],
        ));
        let a = Machine::new(&op);
        let e = a.token("x").unwrap_err();
        assert!(
            e.starts_with("1Password vault `v`: sesame.x/expires_at: `soon`: "),
            "{e}"
        );
    }

    #[test]
    fn reads_answer_from_the_copy_at_any_age_with_no_core_call() {
        let op = OnePassword::new();
        let a = Machine::new(&op);
        a.save_login("x", Some(&client("x-1")), Some(&token("t-1")))
            .unwrap();
        a.save_provider_fields("x", json!({"about": "first"}).as_object().unwrap())
            .unwrap();
        op.calls();

        // The Copy last synced in 1970, as far as it says.
        let path = a.dir.join(COPY_FILE);
        let sealer = opcore::Sealer::new(SA, "sesame's copy of 1Password vault v");
        let plain = sealer.open(&std::fs::read(&path).unwrap()).unwrap();
        let mut held: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert!(held["synced_at"].as_u64().unwrap() > 1);
        held["synced_at"] = 1.into();
        let aged = sealer.seal(held.to_string().as_bytes());
        std::fs::write(&path, aged).unwrap();

        // The next process reads all of it from the Copy, no sign-in.
        let a = a.again();
        assert_eq!(a.client("x").unwrap(), Some(client("x-1")));
        assert_eq!(a.token("x").unwrap(), Some(token("t-1")));
        assert_eq!(a.provider_fields().unwrap()["x"]["about"], "first");
        assert_eq!(a.token("y").unwrap(), None);
        assert_eq!(op.calls(), Vec::<String>::new());

        // A machine with no Copy syncs once, then reads from it too.
        let b = Machine::new(&op);
        assert_eq!(b.client("x").unwrap(), Some(client("x-1")));
        assert_eq!(op.calls(), FIRST_SYNC);
        assert_eq!(b.again().token("x").unwrap(), Some(token("t-1")));
        assert_eq!(op.calls(), Vec::<String>::new());
    }

    #[test]
    fn another_machines_write_is_read_at_a_sync_not_before() {
        let op = OnePassword::new();
        let a = Machine::new(&op);
        let b = Machine::new(&op);
        a.save_token("x", &token("t-1")).unwrap();
        assert_eq!(b.token("x").unwrap(), Some(token("t-1")));
        a.save_token("x", &token("t-2")).unwrap();
        op.calls();

        let b = b.again();
        assert_eq!(b.token("x").unwrap(), Some(token("t-1")));
        assert_eq!(op.calls(), Vec::<String>::new());
        assert_eq!(b.latest_token("x").unwrap(), Some(token("t-2")));
        // Signed in to the vault the Copy knows: no `VaultsList`.
        assert_eq!(op.calls(), ["init_client", "ItemsList", "ItemsGetAll"]);
    }

    #[test]
    fn a_write_is_pushed_at_once_keeping_other_peoples_fields() {
        let op = OnePassword::new();
        let in_section = ItemField {
            id: "n".into(),
            section_id: Some("s".into()),
            ..text("client_id", "theirs")
        };
        let theirs = vec![text("url", "https://x"), in_section];
        let sections = vec![ItemSection {
            id: "s".into(),
            title: "Theirs".into(),
        }];
        op.add(ItemParams {
            title: "sesame.x".into(),
            category: Category::Login,
            tags: vec!["mine".into(), TAG.into()],
            sections: sections.clone(),
            notes: "hello".into(),
            fields: theirs.clone(),
        });
        let a = Machine::new(&op);
        a.client("x").unwrap();
        op.calls();

        a.save_client("x", &client("x-1")).unwrap();
        assert_eq!(op.calls(), PUSHED_EDIT);
        let item = op.item("sesame.x").unwrap();
        assert_eq!(item.tags, ["mine", "sesame"]);
        assert_eq!(item.sections, sections);
        assert_eq!(
            (item.category, item.notes.as_str()),
            (Category::Login, "hello")
        );
        for f in &theirs {
            assert!(item.fields.contains(f), "{f:?} kept");
        }
        assert_eq!(item.fields.len(), 4, "{:?}", item.fields);
        assert_eq!(a.again().client("x").unwrap(), Some(client("x-1")));

        // Changed elsewhere since this Copy read it: the edit is merged on
        // the item as 1Password holds it now.
        let id = item.id.clone();
        op.change(&id, |i| i.fields.push(text("added", "elsewhere")));
        a.save_token("x", &token("t-1")).unwrap();
        let item = op.item("sesame.x").unwrap();
        assert!(item.fields.iter().any(|f| f.title == "added"), "{item:?}");
        assert!(item.fields.iter().any(|f| f.title == "access_token"));
    }

    #[test]
    fn an_unchanged_update_calls_nothing_and_the_normal_form_is_what_reads_back() {
        let op = OnePassword::new();
        let a = Machine::new(&op);
        a.save_login("x", Some(&client("x-1")), Some(&token("t-1")))
            .unwrap();
        op.calls();

        // The same login again: nothing to write, no call.
        a.save_login("x", Some(&client("x-1")), Some(&token("t-1")))
            .unwrap();
        assert_eq!(op.calls(), Vec::<String>::new());
        // An empty secret is no secret, so no change either.
        let no_secret = Client {
            client_id: "y-1".into(),
            client_secret: None,
        };
        a.save_client("y", &no_secret).unwrap();
        op.calls();
        let empty_secret = Client {
            client_secret: Some(String::new()),
            ..no_secret
        };
        a.save_client("y", &empty_secret).unwrap();
        // Removing what is not there writes nothing.
        assert!(!a.delete_client("z").unwrap());
        assert_eq!(op.calls(), Vec::<String>::new());
        assert!(op.item("sesame.z").is_none());

        // The normal form is what reads back.
        let c = Client {
            client_id: "id".into(),
            client_secret: Some(String::new()),
        };
        let t = Token {
            scope: Some(String::new()),
            pasted: true,
            ..token("t")
        };
        a.save_login("n", Some(&c), Some(&t)).unwrap();
        let kept_c = a.as_kept_client(&c).unwrap();
        assert_eq!(kept_c.client_secret, None);
        assert_eq!(a.client("n").unwrap(), Some(kept_c));
        let kept_t = a.as_kept_token(&t).unwrap();
        assert_eq!(kept_t.scope, None);
        assert_eq!(a.token("n").unwrap(), Some(kept_t));
        // No id, no access token: nothing kept.
        assert!(
            a.as_kept_client(&Client {
                client_id: String::new(),
                client_secret: None
            })
            .is_none()
        );
        assert!(a.as_kept_token(&token("")).is_none());
    }

    #[test]
    fn an_item_left_empty_is_archived() {
        let op = OnePassword::new();
        let a = Machine::new(&op);
        a.save_login("x", Some(&client("x-1")), Some(&token("t-1")))
            .unwrap();
        op.calls();

        // A token left: edited.
        assert!(a.delete_client("x").unwrap());
        assert_eq!(op.calls(), PUSHED_EDIT);
        // Nothing left: archived.
        a.delete_token("x").unwrap();
        assert_eq!(op.calls(), ["ItemsList", "ItemsArchive"]);
        assert!(op.item("sesame.x").is_none());
        assert_eq!(
            (a.client("x").unwrap(), a.token("x").unwrap()),
            (None, None)
        );

        // Another's field left: edited, not archived. The next process
        // finds the item another machine made, and edits it.
        op.add(note("sesame.y", vec![text("url", "https://y")]));
        let a = a.again();
        a.save_client("y", &client("y-1")).unwrap();
        a.delete_client("y").unwrap();
        assert_eq!(op.item("sesame.y").unwrap().fields.len(), 1);
    }

    #[test]
    fn the_lock_reopens_a_copy_another_process_wrote_and_keeps_its_own() {
        let op = OnePassword::new();
        let a = Machine::new(&op);
        a.save_token("x", &token("t-1")).unwrap();
        let other = a.again();
        other.save_token("x", &token("t-2")).unwrap();

        // Unlocked, this process answers from the Copy as it opened it;
        // under the lock, as the other left it.
        assert_eq!(a.token("x").unwrap(), Some(token("t-1")));
        assert_eq!(a.locked(|| a.token("x")).unwrap(), Some(token("t-2")));

        // Its own writes leave the Copy as it holds it: the next lock keeps
        // it, and the sign-in with it.
        op.calls();
        a.save_token("x", &token("t-3")).unwrap();
        a.save_token("x", &token("t-4")).unwrap();
        let calls = op.calls();
        assert_eq!(
            calls.iter().filter(|c| *c == "init_client").count(),
            1,
            "{calls:?}"
        );
    }

    #[test]
    fn a_sync_before_a_refresh_refused_by_1password_is_the_error() {
        let op = OnePassword::new();
        let a = Machine::new(&op);
        a.save_token("x", &token("t-1")).unwrap();
        // Refused (a revoked service account): the error, not the Copy's token.
        let e = a.again_with(Some("sign-in-refused")).latest_token("x");
        assert!(e.unwrap_err().contains("authentication failed"));
    }

    #[test]
    fn a_write_1password_cannot_take_now_fails_naming_where_it_waits() {
        let op = OnePassword::new();
        let a = Machine::new(&op);
        a.save_token("x", &token("t-1")).unwrap();
        let limited = a.again_with(Some("over-budget"));
        let e = limited.save_client("x", &client("x-1")).unwrap_err();
        let pending = a.dir.join("vault-copy.pending");
        assert!(
            e.contains(&format!("waits in `{}`", pending.display())),
            "{e}"
        );
        // This machine reads it meanwhile; the vault does not hold it.
        assert_eq!(a.again().client("x").unwrap(), Some(client("x-1")));
        let vault_x = kept(&op.item("sesame.x").unwrap(), is_provider_field);
        assert_eq!(item::client_of(&vault_x), None);
    }

    /// `tests/fixtures/1password-copy-55d7766`: sesame's own Copy as its code
    /// at 55d7766 sealed it (vault `v`, token `sa-token`): x's client, and
    /// x's token kept unwritten.
    #[test]
    fn an_old_copy_is_not_opened_but_its_unwritten_token_reaches_the_vault_first() {
        let op = OnePassword::new();
        let mut k = Kept::new();
        item::put_client(&mut k, &client("x-1"));
        op.add(note("sesame.x", item::fields(&k)));
        let dir = scratch_dir("old-copy");
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/1password-copy-55d7766"
        );
        let old = old_copy::path(&dir);
        std::fs::copy(fixture, &old).unwrap();
        let kept_token = Token {
            access_token: "kept-access".into(),
            refresh_token: Some("kept-refresh".into()),
            scope: None,
            account: None,
            ..token("")
        };
        let unwritten = old_copy::unwritten_tokens(&old, "v", SA);
        assert_eq!(unwritten, [("x".to_string(), kept_token.clone())]);

        let a = Machine::in_dir(&op, dir);
        a.retire_old_copy().unwrap();
        // A sync builds the new Copy; the token is staged and pushed.
        let calls = op.calls();
        assert_eq!(&calls[..4], FIRST_SYNC, "{calls:?}");
        assert_eq!(&calls[4..], PUSHED_EDIT, "{calls:?}");
        let vault_x = kept(&op.item("sesame.x").unwrap(), is_provider_field);
        assert_eq!(item::token_of(&vault_x).unwrap(), Some(kept_token.clone()));
        assert_eq!(item::client_of(&vault_x), Some(client("x-1")));
        assert!(!old.exists());

        // The new Copy holds both; the next process reads them, no call.
        let a = a.again();
        assert_eq!(a.client("x").unwrap(), Some(client("x-1")));
        assert_eq!(a.token("x").unwrap(), Some(kept_token));
        assert_eq!(op.calls(), Vec::<String>::new());
    }

    #[test]
    fn an_old_copy_that_does_not_open_is_removed_with_no_call() {
        let op = OnePassword::new();
        let dir = scratch_dir("old-other");
        let old = old_copy::path(&dir);
        std::fs::write(&old, b"sealed under another token").unwrap();
        let a = Machine::in_dir(&op, dir);
        a.retire_old_copy().unwrap();
        assert!(!old.exists());
        assert_eq!(op.calls(), Vec::<String>::new());
    }
}
