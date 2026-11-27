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
//! A sign-in takes seconds and every request about one, so sesame reads from
//! a **local copy** of the vault (`copy`, docs/adr/0002) and signs in only
//! when it must reach the vault. The vault is the truth: a write goes to the
//! item first, then the copy. The copy syncs (one list, then one `get_all`
//! of every item whose `updatedAt` moved) when a token must be refreshed,
//! when it is older than `COPY_LIFE`, for `sesame providers`, and when there
//! is none that opens.
mod copy;
mod item;
mod op;
#[cfg(debug_assertions)]
mod stand_in;

use super::{Client, Token};
use crate::providers::Fields;
use copy::LocalCopy;
use item::{Kept, is_provider_field, kept};
use op::{Op, OpError, Opcore};
use opcore::{Category, Item, ItemParams};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

pub const VAULT_VAR: &str = "SESAME_1PASSWORD_VAULT";
pub const TOKEN_VAR: &str = "OP_SERVICE_ACCOUNT_TOKEN";
const TAG: &str = "sesame";
/// The item holding every provider's fields. Not `sesame.<x>`, so it is no
/// provider's.
const DEFINITIONS: &str = "sesame-providers";
/// The longest the copy is used without a sync, even where no token expires
/// (a pasted token, GitHub's): another machine's change arrives within it.
const COPY_LIFE: u64 = 3600;
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

/// A listing of the vault: title → (id, `updatedAt`).
type Listing = BTreeMap<String, (String, String)>;

pub struct Vault {
    name: String,
    /// What answers the vault's requests: opcore, or the tests' vault.
    op: Box<dyn Op>,
    /// The local copy, as last loaded from disk or written.
    copy: Mutex<LocalCopy>,
    /// What has been read of the vault under the lock, by item title; `None`:
    /// no such item. Cleared on taking the lock, so a read-then-write sees
    /// other processes' writes.
    items: Mutex<BTreeMap<String, Option<Item>>>,
    /// The vault's listing under the lock, kept up with this process's
    /// writes; cleared with `items`.
    listing: Mutex<Option<Listing>>,
    /// Whether this vault holds the lock (a nested `locked` runs inside it).
    held: AtomicBool,
}

/// opcore on vault `name` as service account `token`; in a debug build with
/// `stand_in::DIR_VAR` set, on the tests' stand-in Core instead.
fn opcore(token: &str, name: &str) -> Box<dyn Op> {
    #[cfg(debug_assertions)]
    if let Some(dir) = std::env::var_os(stand_in::DIR_VAR) {
        return Box::new(Opcore::with(stand_in::sign_in(dir.into(), token, name)));
    }
    Box::new(Opcore::new(token, name))
}

impl Vault {
    /// The vault `SESAME_1PASSWORD_VAULT` names, if any. Named, it must be
    /// usable: a missing token is an error naming it. `current`: sync the
    /// copy even if it is young (a status listing).
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
        let op = opcore(&token, &name);
        let (v, opened) = Vault::new(name, &token, super::config_dir(), op)?;
        let stale = v
            .copy()
            .synced_at()?
            .is_none_or(|t| t + COPY_LIFE <= crate::oauth::now());
        if !opened || stale || current {
            v.locked(|| v.sync(None))?;
        }
        Ok(Some(v))
    }

    /// Vault `name` through `op` (opcore, or the tests' vault), its copy (and whether one opened) sealed
    /// under `token` in `dir`.
    fn new(
        name: String,
        token: &str,
        dir: PathBuf,
        op: Box<dyn Op>,
    ) -> Result<(Vault, bool), String> {
        let (copy, opened) = LocalCopy::load(&name, token, dir)?;
        let v = Vault {
            name,
            op,
            copy: Mutex::new(copy),
            items: Mutex::new(BTreeMap::new()),
            listing: Mutex::new(None),
            held: AtomicBool::new(false),
        };
        Ok((v, opened))
    }

    fn copy(&self) -> MutexGuard<'_, LocalCopy> {
        self.copy.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Brings the copy up to the vault: one list, then one `get_all` of
    /// each `sesame` item whose `updatedAt` is not the copy's, and of
    /// `provider`'s item whatever it is (a refresh is about to decide on
    /// it). An item the copy holds that the list lacks is asked for by id in
    /// the same `get_all` before its rows go: 1Password may list a new item
    /// late. What was read under this lock is not read again.
    pub fn sync(&self, provider: Option<&str>) -> Result<(), String> {
        let unwritten = self.copy().unwritten()?;
        for p in unwritten {
            if let Err(e) = self.update_locked(&title(&p), is_provider_field, |_| {}) {
                warn_unwritten(&p, &e);
            }
        }
        let listed = self.listing()?;
        let copied = self.copy().items()?;
        let forced = provider.map(title);
        let read = self.items().clone();
        let mut wanted: Vec<(&str, &str)> = Vec::new();
        for (t, (id, at)) in &listed {
            let moved = copied
                .get(t)
                .and_then(|(_, i)| i.as_ref())
                .is_none_or(|i| i.id != *id || i.updated_at != *at);
            if (moved || forced.as_ref() == Some(t)) && !read.contains_key(t) {
                wanted.push((t, id));
            }
        }
        for (t, (id, _)) in &copied {
            if !listed.contains_key(t) && !read.contains_key(t) {
                wanted.push((t, id));
            }
        }
        for (t, item) in self.read_all(&wanted)? {
            self.copy().apply(t, item.as_ref())?;
        }
        let mut copy = self.copy();
        copy.mark_synced(crate::oauth::now())?;
        copy.save()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn failed(&self, what: &str, e: OpError) -> String {
        match e {
            OpError::NoItem => format!("1Password vault `{}`: {what}: no such item", self.name),
            OpError::Failed(e) => format!("1Password vault `{}`: {what}: {e}", self.name),
        }
    }

    /// The vault's `sesame` items, listed once per lock.
    fn listing(&self) -> Result<Listing, String> {
        if let Some(l) = self.listing_slot().as_ref() {
            return Ok(l.clone());
        }
        let listed: Listing = self
            .op
            .list(TAG)
            .map_err(|e| self.failed("listing items", e))?
            .into_iter()
            .filter(|i| is_ours_title(&i.title))
            .map(|i| (i.title, (i.id, i.updated_at)))
            .collect();
        *self.listing_slot() = Some(listed.clone());
        Ok(listed)
    }

    fn listing_slot(&self) -> MutexGuard<'_, Option<Listing>> {
        self.listing.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The items `wanted` (title, id) in one `get_all`, each remembered for
    /// this lock. An id now titled otherwise is no longer that item.
    fn read_all<'t>(
        &self,
        wanted: &[(&'t str, &str)],
    ) -> Result<Vec<(&'t str, Option<Item>)>, String> {
        if wanted.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<&str> = wanted.iter().map(|(_, id)| *id).collect();
        let got = self.op.get_all(&ids).map_err(|e| {
            let titles: Vec<&str> = wanted.iter().map(|(t, _)| *t).collect();
            self.failed(&format!("reading `{}`", titles.join("`, `")), e)
        })?;
        let mut items = self.items();
        Ok(wanted
            .iter()
            .zip(got)
            .map(|((t, _), item)| {
                let item = item.filter(|i| i.title == *t);
                items.insert(t.to_string(), item.clone());
                (*t, item)
            })
            .collect())
    }

    /// The item titled `title` as the vault holds it: the copy's when the
    /// listing shows it unchanged since, else read once per lock (by id).
    fn current(&self, title: &str) -> Result<Option<Item>, String> {
        if let Some(hit) = self.items().get(title) {
            return Ok(hit.clone());
        }
        let listed = self.listing()?.remove(title);
        let copied = self.copy().items()?.remove(title);
        let id = match (listed, copied) {
            (Some((id, at)), Some((_, Some(item)))) if item.id == id && item.updated_at == at => {
                self.items().insert(title.into(), Some(item.clone()));
                return Ok(Some(item));
            }
            (Some((id, _)), _) => id,
            // Listed late, or gone since the copy had it.
            (None, Some((id, _))) => id,
            (None, None) => {
                self.items().insert(title.into(), None);
                return Ok(None);
            }
        };
        Ok(self.read_all(&[(title, &id)])?.remove(0).1)
    }

    /// Runs `f` holding this machine's lock, with the copy as another
    /// process may have left it and nothing remembered of the vault:
    /// 1Password has no lock, so this keeps two processes here from both
    /// refreshing or overwriting each other's copy.
    pub fn locked<T>(&self, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        if self.held.swap(true, Ordering::SeqCst) {
            return f();
        }
        let result = (|| {
            let _lock = self.copy().lock()?;
            self.items().clear();
            *self.listing_slot() = None;
            f()
        })();
        self.held.store(false, Ordering::SeqCst);
        result
    }

    fn items(&self) -> MutexGuard<'_, BTreeMap<String, Option<Item>>> {
        self.items.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Changes what sesame keeps in the item `title` with `change`, and writes
    /// the item only if that changed: created when new, archived when left
    /// with nothing in it, else edited keeping what others put there. The
    /// item is the copy's if the listing shows it unchanged, else read
    /// afresh; the copy is then made what the write answered. What sesame
    /// kept in it before.
    fn update(
        &self,
        title: &str,
        ours: impl Fn(&str) -> bool,
        change: impl FnOnce(&mut Kept),
    ) -> Result<Kept, String> {
        self.locked(|| self.update_locked(title, ours, change))
    }

    fn update_locked(
        &self,
        title: &str,
        ours: impl Fn(&str) -> bool,
        change: impl FnOnce(&mut Kept),
    ) -> Result<Kept, String> {
        let current = self.current(title)?;
        let have = current.as_ref().map(|i| kept(i, &ours)).unwrap_or_default();
        let mut want = have.clone();
        let provider = title.strip_prefix("sesame.").unwrap_or_default();
        if let Some(t) = self.copy().unwritten_token(provider)? {
            item::put_token(&mut want, &t);
        }
        change(&mut want);
        let written = if want == have {
            current
        } else {
            self.write(title, current, &want, &ours)
                .map_err(|e| self.failed(&format!("writing `{title}`"), e))?
        };
        self.items().insert(title.into(), written.clone());
        if let Some(listing) = self.listing_slot().as_mut() {
            match &written {
                Some(i) => listing.insert(title.into(), (i.id.clone(), i.updated_at.clone())),
                None => listing.remove(title),
            };
        }
        let mut copy = self.copy();
        copy.set_unwritten(provider, false)?;
        copy.apply(title, written.as_ref())?;
        copy.save()?;
        Ok(have)
    }

    /// Writes item `title` (now `current`) to keep `want`: one create, edit
    /// or archive. The item as the write answered it.
    fn write(
        &self,
        title: &str,
        current: Option<Item>,
        want: &Kept,
        ours: impl Fn(&str) -> bool,
    ) -> Result<Option<Item>, OpError> {
        let Some(item) = current else {
            let params = ItemParams {
                title: title.into(),
                category: Category::SecureNote,
                tags: vec![TAG.into()],
                fields: item::fields(want),
                ..Default::default()
            };
            return self.op.create(&params).map(Some);
        };
        if want.is_empty() && kept(&item, |l| !ours(l)).is_empty() {
            // Archived, not deleted: it can be restored in 1Password.
            return self.op.archive(&item.id).map(|()| None);
        }
        let mut tags = item.tags.clone();
        if !tags.iter().any(|t| t == TAG) {
            tags.push(TAG.into());
        }
        let mut fields: Vec<_> = item
            .fields
            .iter()
            .filter(|f| !item::is_ours(f, &ours))
            .cloned()
            .collect();
        fields.extend(item::fields(want));
        let params = ItemParams {
            title: title.into(),
            category: item.category,
            fields,
            sections: item.sections.clone(),
            notes: item.notes.clone(),
            tags,
        };
        self.op.edit(&item.id, &params).map(Some)
    }

    pub fn client(&self, provider: &str) -> Result<Option<Client>, String> {
        self.copy().rows().client(provider)
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

    /// `provider`'s token after a sync that reads its item whatever its
    /// version: what a refresh decides on.
    pub fn latest_token(&self, provider: &str) -> Result<Option<Token>, String> {
        self.locked(|| {
            self.sync(Some(provider))?;
            self.token(provider)
        })
    }

    pub fn token(&self, provider: &str) -> Result<Option<Token>, String> {
        self.copy().rows().token(provider)
    }

    pub fn save_token(&self, provider: &str, t: &Token) -> Result<(), String> {
        self.save_login(provider, None, Some(t))
    }

    /// Stores `t`, a token the provider issued in place of the stored one:
    /// it is kept in the copy first, so a vault that refuses the write loses
    /// nothing. Refused, the copy marks it unwritten: reads and syncs keep it
    /// over the vault's, and the next write of its item, or the next sync
    /// (both under the lock), writes it. A provider that rotates its refresh
    /// token honours only this one (docs/adr/0002).
    pub fn keep_token(&self, provider: &str, t: &Token) -> Result<(), String> {
        let Some(t) = self.as_kept_token(t) else {
            return self.save_token(provider, t);
        };
        self.locked(|| {
            self.copy().keep_unwritten(provider, &t)?;
            if let Err(e) = self.update_locked(&title(provider), is_provider_field, |_| {}) {
                warn_unwritten(provider, &e);
            }
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
        self.copy().rows().provider_fields()
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

/// Says on stderr that `provider`'s token stays unwritten, and why.
fn warn_unwritten(provider: &str, e: &str) {
    eprintln!(
        "sesame: warning: could not write the new `{provider}` token to the vault: {e}\n\
         This machine keeps it and writes it with its next write to the vault."
    );
}

/// Whether an item with this title is sesame's to copy.
fn is_ours_title(t: &str) -> bool {
    t == DEFINITIONS || t.starts_with("sesame.")
}

/// The item holding a provider's client and token.
fn title(provider: &str) -> String {
    format!("sesame.{provider}")
}

#[cfg(test)]
mod tests {
    use super::op::Memory;
    use super::*;
    use opcore::{FieldType, ItemField, ItemSection};
    use serde_json::json;

    /// A machine's vault: `mem` through the `Op` seam, its copy in a dir of
    /// its own, removed when it drops.
    struct Machine {
        vault: Vault,
        dir: PathBuf,
    }

    impl Drop for Machine {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    impl std::ops::Deref for Machine {
        type Target = Vault;
        fn deref(&self) -> &Vault {
            &self.vault
        }
    }

    fn scratch_dir() -> PathBuf {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sesame-vault-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn machine(mem: &Memory) -> Machine {
        let dir = scratch_dir();
        let (vault, opened) =
            Vault::new("v".into(), "sa-token", dir.clone(), Box::new(mem.clone())).unwrap();
        assert!(!opened);
        Machine { vault, dir }
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

    fn id(mem: &Memory, title: &str) -> String {
        mem.item(title).unwrap().id
    }

    fn calls(mem: &Memory) -> Vec<String> {
        mem.take_calls()
    }

    #[test]
    fn a_value_sesame_cannot_read_is_an_error_naming_the_vault_item_and_field() {
        let mem = Memory::default();
        mem.add(ItemParams {
            title: "sesame.x".into(),
            tags: vec![TAG.into()],
            fields: vec![text("access_token", "a"), text("expires_at", "soon")],
            ..Default::default()
        });
        let a = machine(&mem);
        let e = a.locked(|| a.sync(None)).unwrap_err();
        assert!(
            e.starts_with("1Password vault `v`: sesame.x/expires_at: `soon`: "),
            "{e}"
        );
    }

    #[test]
    fn sync_rereads_only_items_whose_version_moved_plus_the_forced_one() {
        let mem = Memory::default();
        let a = machine(&mem);
        a.save_client("x", &client("x-1")).unwrap();
        a.save_client("y", &client("y-1")).unwrap();
        a.save_provider_fields("x", &json!({"about": "first"}).as_object().unwrap().clone())
            .unwrap();
        // A new item: listed (absent), created; no read.
        assert_eq!(
            calls(&mem),
            [
                "list sesame",
                "create sesame.x",
                "list sesame",
                "create sesame.y",
                "list sesame",
                "create sesame-providers",
            ]
        );
        let (x, y, defs) = (
            id(&mem, "sesame.x"),
            id(&mem, "sesame.y"),
            id(&mem, "sesame-providers"),
        );

        // B has no copy: it reads every item, in one get_all.
        let b = machine(&mem);
        b.locked(|| b.sync(None)).unwrap();
        assert_eq!(
            calls(&mem),
            ["list sesame".into(), format!("get_all {defs} {x} {y}")]
        );
        assert_eq!(b.client("y").unwrap(), Some(client("y-1")));
        assert_eq!(b.provider_fields().unwrap()["x"]["about"], "first");

        // A writes x: B reads x (moved) and y (forced), not the definitions.
        a.save_client("x", &client("x-2")).unwrap();
        calls(&mem);
        b.locked(|| b.sync(Some("y"))).unwrap();
        assert_eq!(
            calls(&mem),
            ["list sesame".into(), format!("get_all {x} {y}")]
        );
        assert_eq!(b.client("x").unwrap(), Some(client("x-2")));

        // Nothing moved, nothing forced: the list alone.
        b.locked(|| b.sync(None)).unwrap();
        assert_eq!(calls(&mem), ["list sesame"]);
    }

    #[test]
    fn a_write_whose_item_is_unchanged_since_the_copy_reads_nothing() {
        let mem = Memory::default();
        let a = machine(&mem);
        a.save_client("x", &client("x-1")).unwrap();
        let x = id(&mem, "sesame.x");
        calls(&mem);

        // The copy's item is the vault's: one list, then one write.
        a.save_token("x", &token("t-1")).unwrap();
        assert_eq!(calls(&mem), ["list sesame".into(), format!("edit {x}")]);
        // Changed elsewhere since: read once, then written.
        mem.change("sesame.x", |i| i.fields.push(text("url", "https://x")));
        a.save_token("x", &token("t-2")).unwrap();
        assert_eq!(
            calls(&mem),
            [
                "list sesame".into(),
                format!("get_all {x}"),
                format!("edit {x}")
            ]
        );
        assert!(
            mem.item("sesame.x")
                .unwrap()
                .fields
                .iter()
                .any(|f| f.title == "url")
        );
    }

    #[test]
    fn an_item_the_list_lacks_is_asked_for_by_id_and_an_edit_keeps_other_peoples_fields() {
        let mem = Memory::default();
        let a = machine(&mem);
        a.save_client("y", &client("y-1")).unwrap();
        let y = id(&mem, "sesame.y");
        calls(&mem);

        // Listed late: still there when asked for, so its rows stay.
        mem.state().unlisted.push(y.clone());
        a.locked(|| a.sync(None)).unwrap();
        assert_eq!(calls(&mem), ["list sesame".into(), format!("get_all {y}")]);
        assert_eq!(a.client("y").unwrap(), Some(client("y-1")));

        // Gone: its rows go, and it is not asked for again.
        mem.state().items.clear();
        a.locked(|| a.sync(None)).unwrap();
        assert_eq!(calls(&mem), ["list sesame".into(), format!("get_all {y}")]);
        assert_eq!(a.client("y").unwrap(), None);
        a.locked(|| a.sync(None)).unwrap();
        assert_eq!(calls(&mem), ["list sesame"]);

        // An edit keeps other people's fields, sections, notes, tags and
        // category.
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
        let x = mem.add(ItemParams {
            title: "sesame.x".into(),
            category: Category::Login,
            tags: vec!["mine".into(), TAG.into()],
            sections: sections.clone(),
            notes: "hello".into(),
            fields: theirs.clone(),
        });
        a.save_client("x", &client("x-1")).unwrap();
        assert_eq!(
            calls(&mem),
            [
                "list sesame".into(),
                format!("get_all {x}"),
                format!("edit {x}")
            ]
        );

        let item = mem.item("sesame.x").unwrap();
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
        assert_eq!(a.client("x").unwrap(), Some(client("x-1")));
    }

    #[test]
    fn an_unchanged_update_writes_nothing_and_the_normal_form_is_what_reads_back() {
        let mem = Memory::default();
        let a = machine(&mem);
        a.save_login("x", Some(&client("x-1")), Some(&token("t-1")))
            .unwrap();
        calls(&mem);

        // The same login again: listed, not written.
        a.save_login("x", Some(&client("x-1")), Some(&token("t-1")))
            .unwrap();
        assert_eq!(calls(&mem), ["list sesame"]);
        // An empty secret is no secret, so no change either.
        let no_secret = Client {
            client_id: "y-1".into(),
            client_secret: None,
        };
        a.save_client("y", &no_secret).unwrap();
        calls(&mem);
        let empty_secret = Client {
            client_secret: Some(String::new()),
            ..no_secret
        };
        a.save_client("y", &empty_secret).unwrap();
        assert_eq!(calls(&mem), ["list sesame"]);
        // Removing what is not there writes nothing.
        assert!(!a.delete_client("z").unwrap());
        assert_eq!(calls(&mem), ["list sesame"]);
        assert!(mem.item("sesame.z").is_none());

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
        let mem = Memory::default();
        let a = machine(&mem);
        a.save_login("x", Some(&client("x-1")), Some(&token("t-1")))
            .unwrap();
        let x = id(&mem, "sesame.x");
        calls(&mem);

        // A token left: edited.
        assert!(a.delete_client("x").unwrap());
        assert_eq!(calls(&mem), ["list sesame".into(), format!("edit {x}")]);
        // Nothing left: archived.
        a.delete_token("x").unwrap();
        assert_eq!(calls(&mem), ["list sesame".into(), format!("archive {x}")]);
        assert!(mem.item("sesame.x").is_none());
        assert_eq!(
            (a.client("x").unwrap(), a.token("x").unwrap()),
            (None, None)
        );

        // Another's field left: edited, not archived.
        let y = mem.add(ItemParams {
            title: "sesame.y".into(),
            tags: vec![TAG.into()],
            fields: vec![text("url", "https://y")],
            ..Default::default()
        });
        a.save_client("y", &client("y-1")).unwrap();
        calls(&mem);
        a.delete_client("y").unwrap();
        assert_eq!(calls(&mem), ["list sesame".into(), format!("edit {y}")]);
        assert_eq!(mem.item("sesame.y").unwrap().fields.len(), 1);
    }

    #[test]
    fn a_read_is_cached_once_per_lock_and_forgotten_when_the_lock_is_taken_again() {
        let mem = Memory::default();
        let a = machine(&mem);
        a.save_client("x", &client("x-1")).unwrap();
        let x = id(&mem, "sesame.x");
        calls(&mem);

        a.locked(|| {
            a.save_token("x", &token("t-1"))?;
            a.save_token("x", &token("t-2"))?;
            a.latest_token("x")
        })
        .unwrap();
        // One list under the lock, then the writes; the sync reads nothing
        // it wrote.
        assert_eq!(
            calls(&mem),
            [
                "list sesame".into(),
                format!("edit {x}"),
                format!("edit {x}"),
            ]
        );

        // Another machine writes; the next lock reads the item afresh.
        mem.change("sesame.x", |i| {
            i.fields.retain(|f| f.title != "access_token")
        });
        a.save_token("x", &token("t-2")).unwrap();
        assert_eq!(
            calls(&mem),
            [
                "list sesame".into(),
                format!("get_all {x}"),
                format!("edit {x}")
            ]
        );
        assert_eq!(a.token("x").unwrap(), Some(token("t-2")));
    }

    /// `tests/fixtures/1password-copy-55d7766`: sealed by sesame's code at
    /// 55d7766 (vault `v`, token `sa-token`), before the copy kept items:
    /// x's client, and x's token kept unwritten.
    #[test]
    fn a_copy_sealed_before_the_move_to_opcore_opens_with_its_unwritten_tokens() {
        let dir = scratch_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/1password-copy-55d7766"
        );
        std::fs::copy(fixture, dir.join("1password-copy")).unwrap();
        let mem = Memory::default();
        let x = mem.add(ItemParams {
            title: "sesame.x".into(),
            tags: vec![TAG.into()],
            fields: item::fields(&{
                let mut k = Kept::new();
                item::put_client(&mut k, &client("x-1"));
                k
            }),
            ..Default::default()
        });
        let (a, opened) =
            Vault::new("v".into(), "sa-token", dir.clone(), Box::new(mem.clone())).unwrap();
        let a = Machine { vault: a, dir };
        assert!(opened);
        let kept = Token {
            access_token: "kept-access".into(),
            refresh_token: Some("kept-refresh".into()),
            scope: None,
            account: None,
            ..token("")
        };
        assert_eq!(a.client("x").unwrap(), Some(client("x-1")));
        assert_eq!(a.token("x").unwrap(), Some(kept.clone()));
        assert_eq!(a.copy().unwritten().unwrap(), ["x"]);

        // The next sync writes the kept token, then reads nothing more.
        a.locked(|| a.sync(None)).unwrap();
        assert_eq!(
            calls(&mem),
            [
                "list sesame".into(),
                format!("get_all {x}"),
                format!("edit {x}")
            ]
        );
        let vault_x = mem.item("sesame.x").unwrap();
        let k = kept_of(&vault_x);
        assert_eq!(item::token_of(&k).unwrap(), Some(kept));
        assert!(a.copy().unwritten().unwrap().is_empty());
    }

    fn kept_of(i: &Item) -> Kept {
        kept(i, is_provider_field)
    }

    #[test]
    fn opcore_signs_in_on_the_first_request_only() {
        let dir = scratch_dir();
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY: the stand-in reads it; no other test sets or reads it.
        unsafe { std::env::set_var(stand_in::TOKEN_VAR, "sa-token") };
        let op = Opcore::with(stand_in::sign_in(dir.clone(), "sa-token", "scratch"));
        let log = || std::fs::read_to_string(dir.join("calls.log")).unwrap_or_default();
        assert_eq!(log(), "");
        assert!(op.list(TAG).unwrap().is_empty());
        assert!(op.get_all(&["a"]).unwrap()[0].is_none());
        assert_eq!(log(), "init_client\nVaultsList\nItemsList\nItemsGetAll\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
