//! The 1Password store (docs/adr/0001): a vault, read and written with the
//! `op` CLI as a service account. Selected by `SESAME_1PASSWORD_VAULT`; the
//! token is `OP_SERVICE_ACCOUNT_TOKEN`.
//!
//! - `sesame.<provider>`: the provider's client and token, one item each, so
//!   two machines writing different providers never overwrite each other.
//!   How its values lie in it is `item`'s.
//! - `sesame-providers`: the person's provider fields, one text field per
//!   provider holding them as JSON. One item, so every command reads all
//!   definitions in one request.
//!
//! Each item is tagged `sesame`, a Secure Note. Values reach `op` only on its
//! stdin, the token only in its environment.
//!
//! Every request counts against the service account's budget and takes about
//! a second, so sesame reads from a **local copy** of the vault (docs/adr/0002):
//! `sesame.db`'s tables in memory, plus each item's id and `version` at the
//! last sync, kept on disk only sealed (`sealed`) under a key derived from the
//! service account token (`<config_dir>/1password-copy`). The vault is the
//! truth: a write goes to the item first, then the copy. The copy syncs (one
//! `op item list`, then a read of each item whose version moved) when a token
//! must be refreshed, when it is older than `COPY_LIFE`, for `sesame
//! providers`, and when there is none that opens.
mod item;
mod op;

use super::sealed::Sealer;
use super::sqlite::Sqlite;
use super::{Client, Token};
use crate::providers::Fields;
use item::{Kept, is_provider_field, kept};
use op::{Item, Op, OpCli, OpError};
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
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
/// The copy's own tables, beside `sesame.db`'s: which item each provider's
/// rows came from and its version then, when the copy last synced, and the
/// providers whose token row the vault does not hold yet (`keep_token`).
const COPY_TABLES: &str = "
    CREATE TABLE IF NOT EXISTS vault_items (
        title TEXT PRIMARY KEY,
        id TEXT NOT NULL,
        version INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS copy_synced (at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS unwritten_tokens (provider TEXT PRIMARY KEY);
";
/// The service account token, taken out of the environment (`take_token`).
static SERVICE_TOKEN: OnceLock<Option<String>> = OnceLock::new();

/// Takes the service account token out of this process's environment, so
/// that only `op` children get it (a browser sesame opens does not). Called
/// first thing in `main`, before any thread or child.
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
pub struct Vault {
    name: String,
    /// What answers the vault's requests: `op`, or the tests' vault in memory.
    op: Box<dyn Op>,
    sealer: Sealer,
    /// Where the copy and the lock live: the config dir.
    dir: PathBuf,
    /// The local copy, as last loaded from disk or written.
    copy: Mutex<Sqlite>,
    /// What has been read of the vault under the lock, by item title; `None`:
    /// no such item. Cleared on taking the lock, so a read-then-write sees
    /// other processes' writes.
    items: Mutex<BTreeMap<String, Option<Item>>>,
    /// Whether this vault holds the lock (a nested `locked` runs inside it).
    held: AtomicBool,
}

impl Vault {
    /// The vault `SESAME_1PASSWORD_VAULT` names, if any. Named, it must be
    /// usable: a missing token or a missing `op` is an error naming it.
    /// `current`: sync the copy even if it is young (a status listing).
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
        if !on_path("op") {
            return Err(format!(
                "{VAULT_VAR} is set (`{name}`), so sesame keeps its clients and tokens in that \
                 1Password vault, but the 1Password CLI `op` is not on PATH: install it \
                 (`brew install 1password-cli`), or unset {VAULT_VAR} to use sesame.db"
            ));
        }
        let op = OpCli {
            vault: name.clone(),
            token: token.clone(),
        };
        let (v, opened) = Vault::new(name, &token, super::config_dir(), Box::new(op))?;
        let stale = v
            .synced_at()?
            .is_none_or(|t| t + COPY_LIFE <= crate::oauth::now());
        if !opened || stale || current {
            v.locked(|| v.sync(None))?;
        }
        Ok(Some(v))
    }

    /// Vault `name` through `op`, its copy (and whether one opened) sealed
    /// under `token` in `dir`.
    fn new(
        name: String,
        token: &str,
        dir: PathBuf,
        op: Box<dyn Op>,
    ) -> Result<(Vault, bool), String> {
        let sealer = Sealer::new(token, &format!("sesame's copy of 1Password vault {name}"));
        let (copy, opened) = load(&sealer, &dir)?;
        let v = Vault {
            name,
            op,
            sealer,
            dir,
            copy: Mutex::new(copy),
            items: Mutex::new(BTreeMap::new()),
            held: AtomicBool::new(false),
        };
        Ok((v, opened))
    }

    fn copy(&self) -> MutexGuard<'_, Sqlite> {
        self.copy.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn copy_err(&self, e: rusqlite::Error) -> String {
        format!("sesame's copy of 1Password vault `{}`: {e}", self.name)
    }

    /// When the copy last synced, if it ever did.
    fn synced_at(&self) -> Result<Option<u64>, String> {
        self.copy()
            .conn()
            .query_row("SELECT at FROM copy_synced", [], |r| r.get::<_, i64>(0))
            .optional()
            .map(|t| t.map(|t| t as u64))
            .map_err(|e| self.copy_err(e))
    }

    /// Each item the copy holds rows of: title → (id, version).
    fn copied(&self) -> Result<BTreeMap<String, (String, u64)>, String> {
        let copy = self.copy();
        let mut stmt = copy
            .conn()
            .prepare("SELECT title, id, version FROM vault_items")
            .map_err(|e| self.copy_err(e))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, (r.get(1)?, r.get::<_, i64>(2)? as u64)))
            })
            .map_err(|e| self.copy_err(e))?;
        rows.collect::<Result<_, _>>().map_err(|e| self.copy_err(e))
    }

    /// Writes the copy to disk, sealed: to a file beside it, then renamed
    /// over it, so a reader sees the old copy or the new, never half.
    fn save(&self) -> Result<(), String> {
        let image = self.copy().image()?;
        let path = copy_path(&self.dir);
        let tmp = path.with_extension("tmp");
        let at = |e: std::io::Error, p: &PathBuf| format!("{}: {e}", p.display());
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| at(e, &tmp))?;
        f.write_all(&self.sealer.seal(&image))
            .map_err(|e| at(e, &tmp))?;
        drop(f);
        std::fs::rename(&tmp, &path).map_err(|e| at(e, &path))
    }

    /// Brings the copy up to the vault: one `op item list`, then a read of
    /// each `sesame` item whose version is not the copy's, and of
    /// `provider`'s item whatever its version (a refresh is about to decide on
    /// it). An item the copy holds that the list lacks is asked for by id
    /// before its rows go: 1Password may list a new item late.
    pub fn sync(&self, provider: Option<&str>) -> Result<(), String> {
        let unwritten = self.unwritten(&self.copy())?;
        for p in unwritten {
            if let Err(e) = self.update_locked(&title(&p), is_provider_field, |_| {}) {
                warn_unwritten(&p, &e);
            }
        }
        let listed: BTreeMap<String, (String, u64)> = self
            .op
            .list(TAG)
            .map_err(|e| self.failed("listing items", e))?
            .into_iter()
            .filter(|i| is_ours_title(&i.title))
            .map(|i| (i.title, (i.id, i.version)))
            .collect();
        let copied = self.copied()?;
        let forced = provider.map(title);
        for (t, (id, version)) in &listed {
            let moved = copied.get(t).map(|(_, v)| v) != Some(version);
            if moved || forced.as_ref() == Some(t) {
                let item = self.get(t, Some(id))?;
                self.apply(t, item.as_ref())?;
            }
        }
        for (t, (id, _)) in &copied {
            if !listed.contains_key(t) {
                let item = self.get(t, Some(id))?;
                self.apply(t, item.as_ref())?;
            }
        }
        {
            let copy = self.copy();
            let now = crate::oauth::now() as i64;
            copy.conn()
                .execute_batch("DELETE FROM copy_synced")
                .and_then(|_| {
                    copy.conn()
                        .execute("INSERT INTO copy_synced (at) VALUES (?1)", [now])
                })
                .map_err(|e| self.copy_err(e))?;
        }
        self.save()
    }

    /// Makes the copy's rows of item `title` what `item` holds (none: the
    /// item is gone), and records its id and version.
    fn apply(&self, title: &str, item: Option<&Item>) -> Result<(), String> {
        let copy = self.copy();
        if title == DEFINITIONS {
            for provider in copy.provider_fields()?.into_keys() {
                copy.delete_provider_fields(&provider)?;
            }
            if let Some(item) = item {
                for (provider, fields) in item::definitions(&kept(&item.json, |_| true))
                    .map_err(|e| self.bad_item(DEFINITIONS, &e))?
                {
                    copy.save_provider_fields(&provider, &fields)?;
                }
            }
        } else if let Some(provider) = title.strip_prefix("sesame.") {
            // A token the vault does not hold yet stays as it is.
            let unwritten = self.unwritten(&copy)?.iter().any(|p| p == provider);
            copy.delete_client(provider)?;
            if !unwritten {
                copy.delete_token(provider)?;
            }
            if let Some(item) = item {
                let k = kept(&item.json, is_provider_field);
                if let Some(c) = item::client_of(&k) {
                    copy.save_client(provider, &c)?;
                }
                if let Some(t) = item::token_of(&k).map_err(|e| self.bad_item(title, &e))?
                    && !unwritten
                {
                    copy.save_token(provider, &t)?;
                }
            }
        } else {
            return Ok(());
        }
        let conn = copy.conn();
        match item {
            Some(item) => conn.execute(
                "INSERT OR REPLACE INTO vault_items (title, id, version) VALUES (?1, ?2, ?3)",
                params![title, item.id, item.json["version"].as_i64().unwrap_or(0)],
            ),
            None => conn.execute("DELETE FROM vault_items WHERE title = ?1", [title]),
        }
        .map(drop)
        .map_err(|e| self.copy_err(e))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// What item `title` holds that sesame cannot read, `e` saying which field.
    fn bad_item(&self, title: &str, e: &str) -> String {
        format!("1Password vault `{}`: {title}/{e}", self.name)
    }

    fn failed(&self, what: &str, e: OpError) -> String {
        match e {
            OpError::NoItem => format!("1Password vault `{}`: {what}: no such item", self.name),
            OpError::Failed(e) if e.contains(VAULT_VAR) => e,
            OpError::Failed(e) => format!("1Password vault `{}`: {what}: {e}", self.name),
        }
    }

    /// The item titled `title` (asked for by `id` where known), read from
    /// the vault once per lock.
    fn get(&self, title: &str, id: Option<&str>) -> Result<Option<Item>, String> {
        if let Some(hit) = self.items().get(title) {
            return Ok(hit.clone());
        }
        let item = match self.op.get(id.unwrap_or(title)) {
            // An id now titled otherwise is no longer that item.
            Ok(item) => (item.json["title"].as_str().is_none_or(|t| t == title)).then_some(item),
            Err(OpError::NoItem) => None,
            Err(e) => return Err(self.failed(&format!("reading `{title}`"), e)),
        };
        self.items().insert(title.into(), item.clone());
        Ok(item)
    }

    /// Runs `f` holding this machine's lock (a file in the config dir that
    /// holds nothing), with the copy as another process may have left it and
    /// nothing remembered of the vault: 1Password has no lock, so this keeps
    /// two processes here from both refreshing or overwriting each other's copy.
    pub fn locked<T>(&self, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        if self.held.swap(true, Ordering::SeqCst) {
            return f();
        }
        let result = (|| {
            let file = lock_file(&self.dir)?;
            file.lock().map_err(|e| format!("locking: {e}"))?;
            self.items().clear();
            *self.copy() = load(&self.sealer, &self.dir)?.0;
            f()
            // Dropping `file` unlocks it.
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
    /// item is read afresh first, and the copy then made what was written.
    /// What sesame kept in it before.
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
        let id = self.copied()?.remove(title).map(|(id, _)| id);
        let current = self.get(title, id.as_deref())?;
        let have = current
            .as_ref()
            .map(|i| kept(&i.json, &ours))
            .unwrap_or_default();
        let mut want = have.clone();
        let provider = title.strip_prefix("sesame.").unwrap_or_default();
        if let Some(t) = self.unwritten_token(&self.copy(), provider)? {
            item::put_token(&mut want, &t);
        }
        change(&mut want);
        let written = if want == have {
            current
        } else {
            let what = format!("writing `{title}`");
            let id = current.as_ref().map(|i| i.id.clone());
            let written = match current {
                None => {
                    let template = json!({
                        "title": title,
                        "category": "SECURE_NOTE",
                        "tags": [TAG],
                        "fields": item::fields(&want),
                    });
                    Some(
                        self.op
                            .create(&template)
                            .map_err(|e| self.failed(&what, e))?,
                    )
                }
                Some(item) if want.is_empty() && kept(&item.json, |l| !ours(l)).is_empty() => {
                    // Archived, not deleted: it can be restored in 1Password.
                    self.op
                        .archive(&item.id)
                        .map_err(|e| self.failed(&what, e))?;
                    None
                }
                Some(item) => {
                    let mut tags: Vec<Value> =
                        item.json["tags"].as_array().cloned().unwrap_or_default();
                    if !tags.iter().any(|t| t == TAG) {
                        tags.push(TAG.into());
                    }
                    let mut all: Vec<Value> = item.json["fields"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|f| !item::is_ours(f, &ours))
                        .cloned()
                        .collect();
                    all.extend(item::fields(&want));
                    let mut template = json!({ "title": title, "tags": tags, "fields": all });
                    if let Some(sections) = item.json.get("sections") {
                        template["sections"] = sections.clone();
                    }
                    Some(
                        self.op
                            .edit(&item.id, &template)
                            .map_err(|e| self.failed(&what, e))?,
                    )
                }
            };

            match written {
                Some(Some(item)) => Some(item),
                // What op printed was not the item: read it again.
                Some(None) => {
                    self.items().remove(title);
                    self.get(title, id.as_deref())?
                }
                None => None,
            }
        };
        self.items().insert(title.into(), written.clone());
        self.set_unwritten(provider, false)?;
        self.apply(title, written.as_ref())?;
        self.save()?;
        Ok(have)
    }

    pub fn client(&self, provider: &str) -> Result<Option<Client>, String> {
        self.copy().client(provider)
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
            item::remove_client(k);
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
        self.copy().token(provider)
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
            self.copy().save_token(provider, &t)?;
            self.set_unwritten(provider, true)?;
            self.save()?;
            if let Err(e) = self.update_locked(&title(provider), is_provider_field, |_| {}) {
                warn_unwritten(provider, &e);
            }
            Ok(())
        })
    }

    /// The providers whose token in the copy the vault does not hold yet.
    fn unwritten(&self, copy: &Sqlite) -> Result<Vec<String>, String> {
        let mut stmt = copy
            .conn()
            .prepare("SELECT provider FROM unwritten_tokens")
            .map_err(|e| self.copy_err(e))?;
        let rows = stmt
            .query_map([], |r| r.get(0))
            .map_err(|e| self.copy_err(e))?;
        rows.collect::<Result<_, _>>().map_err(|e| self.copy_err(e))
    }

    /// `provider`'s token in the copy, if the vault does not hold it yet.
    fn unwritten_token(&self, copy: &Sqlite, provider: &str) -> Result<Option<Token>, String> {
        match self.unwritten(copy)?.iter().any(|p| p == provider) {
            true => copy.token(provider),
            false => Ok(None),
        }
    }

    fn set_unwritten(&self, provider: &str, unwritten: bool) -> Result<(), String> {
        let sql = match unwritten {
            true => "INSERT OR IGNORE INTO unwritten_tokens (provider) VALUES (?1)",
            false => "DELETE FROM unwritten_tokens WHERE provider = ?1",
        };
        self.copy()
            .conn()
            .execute(sql, [provider])
            .map(drop)
            .map_err(|e| self.copy_err(e))
    }

    pub fn delete_token(&self, provider: &str) -> Result<(), String> {
        self.update(&title(provider), is_provider_field, |k| {
            item::remove_token(k);
        })
        .map(drop)
    }

    pub fn provider_fields(&self) -> Result<BTreeMap<String, Fields>, String> {
        self.copy().provider_fields()
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

/// The copy on disk if it opens under this token and vault (and whether it
/// did), else an empty one: one sealed under another token, or damaged, is
/// dropped, and the next sync fills its successor from the vault.
fn load(sealer: &Sealer, dir: &Path) -> Result<(Sqlite, bool), String> {
    let image = std::fs::read(copy_path(dir))
        .ok()
        .and_then(|b| sealer.open(&b));
    if let Some(copy) = image.and_then(|i| open_copy(Some(&i)).ok()) {
        return Ok((copy, true));
    }
    Ok((open_copy(None)?, false))
}

fn open_copy(image: Option<&[u8]>) -> Result<Sqlite, String> {
    let copy = Sqlite::in_memory("sesame's copy of the 1Password vault", image)?;
    copy.conn()
        .execute_batch(COPY_TABLES)
        .map_err(|e| format!("sesame's copy of the 1Password vault: {e}"))?;
    Ok(copy)
}

/// `<config_dir>/1password-copy`: the copy, sealed.
fn copy_path(dir: &Path) -> PathBuf {
    dir.join("1password-copy")
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

fn on_path(cmd: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|d| {
            std::fs::metadata(d.join(cmd))
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
    })
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

#[cfg(test)]
mod tests {
    use super::op::Memory;
    use super::*;

    /// A machine's vault: `mem` through the `Op` seam, its copy in a dir of
    /// its own, removed when it drops.
    struct Machine {
        vault: Vault,
    }

    impl Drop for Machine {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.vault.dir);
        }
    }

    impl std::ops::Deref for Machine {
        type Target = Vault;
        fn deref(&self) -> &Vault {
            &self.vault
        }
    }

    fn machine(mem: &Memory) -> Machine {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sesame-vault-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (vault, opened) =
            Vault::new("v".into(), "sa-token", dir, Box::new(mem.clone())).unwrap();
        assert!(!opened);
        Machine { vault }
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

    fn id(mem: &Memory, title: &str) -> String {
        mem.item(title).unwrap()["id"].as_str().unwrap().into()
    }

    fn calls(mem: &Memory) -> Vec<String> {
        mem.take_calls()
    }

    #[test]
    fn sync_rereads_only_items_whose_version_moved_plus_the_forced_one() {
        let mem = Memory::default();
        let a = machine(&mem);
        a.save_client("x", &client("x-1")).unwrap();
        a.save_client("y", &client("y-1")).unwrap();
        a.save_provider_fields("x", &json!({"about": "first"}).as_object().unwrap().clone())
            .unwrap();
        assert_eq!(
            calls(&mem),
            [
                "get sesame.x",
                "create sesame.x",
                "get sesame.y",
                "create sesame.y",
                "get sesame-providers",
                "create sesame-providers",
            ]
        );
        let (x, y, defs) = (
            id(&mem, "sesame.x"),
            id(&mem, "sesame.y"),
            id(&mem, "sesame-providers"),
        );

        // B has no copy: it reads every item.
        let b = machine(&mem);
        b.locked(|| b.sync(None)).unwrap();
        let mut c = calls(&mem);
        c[1..].sort();
        let mut want = vec![
            format!("get {x}"),
            format!("get {y}"),
            format!("get {defs}"),
        ];
        want.sort();
        want.insert(0, "list sesame".into());
        assert_eq!(c, want);
        assert_eq!(b.client("y").unwrap(), Some(client("y-1")));
        assert_eq!(b.provider_fields().unwrap()["x"]["about"], "first");

        // A writes x: B reads x (moved) and y (forced), not the definitions.
        a.save_client("x", &client("x-2")).unwrap();
        calls(&mem);
        b.locked(|| b.sync(Some("y"))).unwrap();
        assert_eq!(
            calls(&mem),
            ["list sesame".into(), format!("get {x}"), format!("get {y}")]
        );
        assert_eq!(b.client("x").unwrap(), Some(client("x-2")));

        // Nothing moved, nothing forced: the list alone.
        b.locked(|| b.sync(None)).unwrap();
        assert_eq!(calls(&mem), ["list sesame"]);
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
        assert_eq!(calls(&mem), ["list sesame".into(), format!("get {y}")]);
        assert_eq!(a.client("y").unwrap(), Some(client("y-1")));

        // Gone: its rows go, and it is not asked for again.
        mem.state().items.clear();
        a.locked(|| a.sync(None)).unwrap();
        assert_eq!(calls(&mem), ["list sesame".into(), format!("get {y}")]);
        assert_eq!(a.client("y").unwrap(), None);
        a.locked(|| a.sync(None)).unwrap();
        assert_eq!(calls(&mem), ["list sesame"]);

        // An edit keeps other people's fields, sections and tags.
        let theirs = json!([
            {"id": "url", "label": "url", "type": "STRING", "value": "https://x"},
            {"id": "n", "label": "client_id", "type": "STRING", "value": "theirs", "section": {"id": "s"}},
            {"id": "notesPlain", "label": "notesPlain", "purpose": "NOTES", "type": "STRING", "value": "hello"},
        ]);
        let x = mem.add(json!({
            "title": "sesame.x",
            "category": "LOGIN",
            "tags": ["mine"],
            "sections": [{"id": "s", "label": "Theirs"}],
            "fields": theirs,
        }));
        a.save_client("x", &client("x-1")).unwrap();
        assert_eq!(
            calls(&mem),
            ["get sesame.x".to_string(), format!("edit {x}")]
        );

        let item = mem.item("sesame.x").unwrap();
        assert_eq!(item["tags"], json!(["mine", "sesame"]));
        assert_eq!(item["sections"], json!([{"id": "s", "label": "Theirs"}]));
        assert_eq!(item["category"], "LOGIN");
        let fields = item["fields"].as_array().unwrap();
        for f in theirs.as_array().unwrap() {
            assert!(fields.contains(f), "{f} kept");
        }
        assert_eq!(fields.len(), 5, "{fields:?}");
        assert_eq!(a.client("x").unwrap(), Some(client("x-1")));
    }

    #[test]
    fn an_unchanged_update_writes_nothing_and_the_normal_form_is_what_reads_back() {
        let mem = Memory::default();
        let a = machine(&mem);
        a.save_login("x", Some(&client("x-1")), Some(&token("t-1")))
            .unwrap();
        let x = id(&mem, "sesame.x");
        calls(&mem);

        // The same login again: the item is read, not written.
        a.save_login("x", Some(&client("x-1")), Some(&token("t-1")))
            .unwrap();
        assert_eq!(calls(&mem), [format!("get {x}")]);
        // An empty secret is no secret, so no change either.
        let no_secret = Client {
            client_id: "y-1".into(),
            client_secret: None,
        };
        a.save_client("y", &no_secret).unwrap();
        let y = id(&mem, "sesame.y");
        calls(&mem);
        let empty_secret = Client {
            client_secret: Some(String::new()),
            ..no_secret
        };
        a.save_client("y", &empty_secret).unwrap();
        assert_eq!(calls(&mem), [format!("get {y}")]);
        // Removing what is not there writes nothing.
        assert!(!a.delete_client("z").unwrap());
        assert_eq!(calls(&mem), ["get sesame.z"]);
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
        assert_eq!(calls(&mem), [format!("get {x}"), format!("edit {x}")]);
        // Nothing left: archived.
        a.delete_token("x").unwrap();
        assert_eq!(calls(&mem), [format!("get {x}"), format!("archive {x}")]);
        assert!(mem.item("sesame.x").is_none());
        assert_eq!(
            (a.client("x").unwrap(), a.token("x").unwrap()),
            (None, None)
        );

        // Another's field left: edited, not archived.
        let y = mem.add(json!({
            "title": "sesame.y",
            "tags": ["sesame"],
            "fields": [{"id": "url", "label": "url", "type": "STRING", "value": "https://y"}],
        }));
        a.save_client("y", &client("y-1")).unwrap();
        calls(&mem);
        a.delete_client("y").unwrap();
        assert_eq!(calls(&mem), [format!("get {y}"), format!("edit {y}")]);
        assert_eq!(
            mem.item("sesame.y").unwrap()["fields"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
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
        // One read of the item, then the writes and the sync's list.
        assert_eq!(
            calls(&mem),
            [
                format!("get {x}"),
                format!("edit {x}"),
                format!("edit {x}"),
                "list sesame".into(),
            ]
        );

        // Another machine writes; the next lock reads the item afresh.
        mem.change("sesame.x", |i| {
            i["fields"]
                .as_array_mut()
                .unwrap()
                .retain(|f| f["label"] != "access_token");
        });
        a.save_token("x", &token("t-2")).unwrap();
        assert_eq!(calls(&mem), [format!("get {x}"), format!("edit {x}")]);
        assert_eq!(a.token("x").unwrap(), Some(token("t-2")));
    }
}
