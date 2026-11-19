//! The 1Password store (docs/adr/0001): a vault, read and written with the
//! `op` CLI as a service account. Selected by `SESAME_1PASSWORD_VAULT`; the
//! token is `OP_SERVICE_ACCOUNT_TOKEN`.
//!
//! - `sesame.<provider>`: the provider's client and token, one item each, so
//!   two machines writing different providers never overwrite each other.
//!   Every value is a top-level field labelled as below (`op read
//!   op://<vault>/sesame.<provider>/refresh_token`); secrets are concealed.
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
use super::sealed::Sealer;
use super::sqlite::Sqlite;
use super::{Client, Token};
use crate::providers::Fields;
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
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
/// rows came from and its version then, and when the copy last synced.
const COPY_TABLES: &str = "
    CREATE TABLE IF NOT EXISTS vault_items (
        title TEXT PRIMARY KEY,
        id TEXT NOT NULL,
        version INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS copy_synced (at INTEGER NOT NULL);
";

const CLIENT_ID: &str = "client_id";
const CLIENT_SECRET: &str = "client_secret";
const CLIENT_FIELDS: [&str; 2] = [CLIENT_ID, CLIENT_SECRET];
const ACCESS_TOKEN: &str = "access_token";
const REFRESH_TOKEN: &str = "refresh_token";
const EXPIRES_AT: &str = "expires_at";
const SCOPE: &str = "scope";
const RESOURCE_ID: &str = "resource_id";
const RESOURCE_NAME: &str = "resource_name";
const ACCOUNT: &str = "account";
const PASTED: &str = "pasted";
const TOKEN_FIELDS: [&str; 8] = [
    ACCESS_TOKEN,
    REFRESH_TOKEN,
    EXPIRES_AT,
    SCOPE,
    RESOURCE_ID,
    RESOURCE_NAME,
    ACCOUNT,
    PASTED,
];

/// The service account token, taken out of the environment (`take_token`).
static SERVICE_TOKEN: OnceLock<Option<String>> = OnceLock::new();

/// Takes the service account token out of this process's environment when a
/// vault is selected, so that only `op` children get it (a browser sesame
/// opens does not). Called first thing in `main`, before any thread or child.
pub fn take_token() {
    let token = std::env::var(TOKEN_VAR).ok().filter(|t| !t.is_empty());
    if vault_name().is_some() && token.is_some() {
        // SAFETY: called at the start of main, before any other thread exists.
        unsafe { std::env::remove_var(TOKEN_VAR) };
    }
    let _ = SERVICE_TOKEN.set(token);
}

fn service_token() -> Option<String> {
    SERVICE_TOKEN
        .get_or_init(|| std::env::var(TOKEN_VAR).ok().filter(|t| !t.is_empty()))
        .clone()
}

fn vault_name() -> Option<String> {
    std::env::var(VAULT_VAR).ok().filter(|v| !v.is_empty())
}

/// An item as `op item get --format json` prints it.
#[derive(Clone)]
struct Item {
    id: String,
    json: Value,
}

/// What a process has read of the vault under the lock, by item title;
/// `None`: no such item. Cleared on taking the lock, so a read-then-write sees
/// other processes' writes.
static ITEMS: Mutex<BTreeMap<String, Option<Item>>> = Mutex::new(BTreeMap::new());
/// Whether this process holds the lock (a nested `locked` runs inside it).
static HELD: AtomicBool = AtomicBool::new(false);

/// What sesame keeps in an item: field label → (concealed, value).
type Kept = BTreeMap<String, (bool, String)>;

pub struct Vault {
    name: String,
    token: String,
    sealer: Sealer,
    /// The local copy, as last loaded from disk or written.
    copy: Mutex<Sqlite>,
}

enum OpError {
    /// The item does not exist.
    NoItem,
    Failed(String),
}

impl Vault {
    /// The vault `SESAME_1PASSWORD_VAULT` names, if any. Named, it must be
    /// usable: a missing token or a missing `op` is an error naming it.
    pub fn from_env() -> Result<Option<Vault>, String> {
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
        let sealer = Sealer::new(&token, &format!("sesame's copy of 1Password vault {name}"));
        let (copy, opened) = load(&sealer)?;
        let v = Vault {
            name,
            token,
            sealer,
            copy: Mutex::new(copy),
        };
        let stale = v
            .synced_at()?
            .is_none_or(|t| t + COPY_LIFE <= crate::oauth::now());
        if !opened || stale {
            v.locked(|| v.sync(None))?;
        }
        Ok(Some(v))
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
        let path = copy_path();
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
        let args = [
            "item", "list", "--vault", &self.name, "--tags", TAG, "--format", "json",
        ];
        let out = self
            .op(&args, None)
            .map_err(|e| self.failed("listing items", e))?;
        let items: Vec<Value> = serde_json::from_str(&out)
            .map_err(|e| format!("1Password vault `{}`: listing items: {e}", self.name))?;
        let listed: BTreeMap<String, (String, u64)> = items
            .iter()
            .filter_map(|i| {
                let title = i["title"].as_str().filter(|t| is_ours_title(t))?;
                let id = i["id"].as_str()?;
                Some((
                    title.into(),
                    (id.into(), i["version"].as_u64().unwrap_or(0)),
                ))
            })
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
                for (provider, fields) in self.definitions(&kept(&item.json, |_| true))? {
                    copy.save_provider_fields(&provider, &fields)?;
                }
            }
        } else if let Some(provider) = title.strip_prefix("sesame.") {
            copy.delete_client(provider)?;
            copy.delete_token(provider)?;
            if let Some(item) = item {
                let k = kept(&item.json, is_provider_field);
                if let Some(c) = client_of(&k) {
                    copy.save_client(provider, &c)?;
                }
                if let Some(t) = self.token_of(provider, &k)? {
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

    /// Runs `op` with `args`, `input` on its stdin, the token in its
    /// environment; its stdout.
    fn op(&self, args: &[&str], input: Option<&[u8]>) -> Result<String, OpError> {
        let mut child = Command::new("op")
            .args(args)
            .env(TOKEN_VAR, &self.token)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| OpError::Failed(format!("running `op`: {e}")))?;
        if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
            // op takes an item template from stdin only when it is a pipe.
            stdin
                .write_all(input)
                .map_err(|e| OpError::Failed(format!("writing to `op`: {e}")))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| OpError::Failed(format!("running `op`: {e}")))?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        let err = op_message(&String::from_utf8_lossy(&out.stderr));
        if err.contains("isn't an item") {
            return Err(OpError::NoItem);
        }
        if err.contains("isn't a vault") {
            return Err(OpError::Failed(format!(
                "the service account cannot read the 1Password vault `{}` ({VAULT_VAR}): \
                 check its name and that the service account has access to it ({err})",
                self.name
            )));
        }
        Err(OpError::Failed(err))
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
        if let Some(hit) = ITEMS.lock().unwrap().get(title) {
            return Ok(hit.clone());
        }
        let query = id.unwrap_or(title);
        let args = [
            "item", "get", query, "--vault", &self.name, "--format", "json",
        ];
        let item = match self.op(&args, None) {
            Ok(out) => {
                let item = parse_item(&out).map_err(|e| format!("reading `{title}`: {e}"))?;
                // An id now titled otherwise is no longer that item.
                (item.json["title"].as_str().is_none_or(|t| t == title)).then_some(item)
            }
            Err(OpError::NoItem) => None,
            Err(e) => return Err(self.failed(&format!("reading `{title}`"), e)),
        };
        ITEMS.lock().unwrap().insert(title.into(), item.clone());
        Ok(item)
    }

    /// Runs `f` holding this machine's lock (a file in the config dir that
    /// holds nothing), with the copy as another process may have left it and
    /// nothing remembered of the vault: 1Password has no lock, so this keeps
    /// two processes here from both refreshing or overwriting each other's copy.
    pub fn locked<T>(&self, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        if HELD.swap(true, Ordering::SeqCst) {
            return f();
        }
        let result = (|| {
            let file = lock_file()?;
            file.lock().map_err(|e| format!("locking: {e}"))?;
            ITEMS.lock().unwrap().clear();
            *self.copy() = load(&self.sealer)?.0;
            f()
            // Dropping `file` unlocks it.
        })();
        HELD.store(false, Ordering::SeqCst);
        result
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
        change(&mut want);
        if want == have {
            self.apply(title, current.as_ref())?;
            self.save()?;
            return Ok(have);
        }
        let what = format!("writing `{title}`");
        let id = current.as_ref().map(|i| i.id.clone());
        let written = match current {
            None => {
                let template = json!({
                    "title": title,
                    "category": "SECURE_NOTE",
                    "tags": [TAG],
                    "fields": fields(&want),
                });
                let args = ["item", "create", "--vault", &self.name, "--format", "json"];
                Some(self.write(&what, &args, &template)?)
            }
            Some(item) if want.is_empty() && kept(&item.json, |l| !ours(l)).is_empty() => {
                // Archived, not deleted: it can be restored in 1Password.
                let args = [
                    "item",
                    "delete",
                    &item.id,
                    "--vault",
                    &self.name,
                    "--archive",
                ];
                self.op(&args, None).map_err(|e| self.failed(&what, e))?;
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
                    .filter(|f| !is_ours(f, &ours))
                    .cloned()
                    .collect();
                all.extend(fields(&want));
                let mut template = json!({ "title": title, "tags": tags, "fields": all });
                if let Some(sections) = item.json.get("sections") {
                    template["sections"] = sections.clone();
                }
                // Without `tags` an edit wipes them; without a category it keeps its own.
                let args = [
                    "item", "edit", &item.id, "--vault", &self.name, "--format", "json",
                ];
                Some(self.write(&what, &args, &template)?)
            }
        };

        let written = match written {
            Some(Some(item)) => Some(item),
            // What op printed was not the item: read it again.
            Some(None) => {
                ITEMS.lock().unwrap().remove(title);
                self.get(title, id.as_deref())?
            }
            None => None,
        };
        ITEMS.lock().unwrap().insert(title.into(), written.clone());
        self.apply(title, written.as_ref())?;
        self.save()?;
        Ok(have)
    }

    /// A create or edit, the item's template on stdin; the item written, if
    /// op printed it.
    fn write(&self, what: &str, args: &[&str], template: &Value) -> Result<Option<Item>, String> {
        let out = self
            .op(args, Some(template.to_string().as_bytes()))
            .map_err(|e| self.failed(what, e))?;
        Ok(parse_item(&out).ok())
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
                put_client(k, c);
            }
            if let Some(t) = t {
                put_token(k, t);
            }
        })
        .map(drop)
    }

    pub fn delete_client(&self, provider: &str) -> Result<bool, String> {
        let had = self.update(&title(provider), is_provider_field, |k| {
            k.retain(|l, _| !CLIENT_FIELDS.contains(&l.as_str()));
        })?;
        Ok(had.contains_key(CLIENT_ID))
    }

    pub fn token(&self, provider: &str) -> Result<Option<Token>, String> {
        self.copy().token(provider)
    }

    pub fn save_token(&self, provider: &str, t: &Token) -> Result<(), String> {
        self.save_login(provider, None, Some(t))
    }

    pub fn delete_token(&self, provider: &str) -> Result<(), String> {
        self.update(&title(provider), is_provider_field, |k| {
            k.retain(|l, _| !TOKEN_FIELDS.contains(&l.as_str()));
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
                    k.remove(provider);
                    let value =
                        (!fields.is_empty()).then(|| Value::Object(fields.clone()).to_string());
                    put(k, provider, false, value);
                }
            },
        )
        .map(drop)
    }

    /// The token kept in a provider's item, if it holds one.
    fn token_of(&self, provider: &str, k: &Kept) -> Result<Option<Token>, String> {
        let Some(access_token) = value(k, ACCESS_TOKEN) else {
            return Ok(None);
        };
        let expires_at = value(k, EXPIRES_AT)
            .map(|t| {
                t.parse().map_err(|e| {
                    format!(
                        "1Password vault `{}`: {}/{EXPIRES_AT}: `{t}`: {e}",
                        self.name,
                        title(provider)
                    )
                })
            })
            .transpose()?;
        Ok(Some(Token {
            access_token,
            refresh_token: value(k, REFRESH_TOKEN),
            expires_at,
            scope: value(k, SCOPE),
            resource_id: value(k, RESOURCE_ID),
            resource_name: value(k, RESOURCE_NAME),
            account: value(k, ACCOUNT),
            pasted: value(k, PASTED).is_some_and(|p| p == "true"),
        }))
    }

    /// Every provider's fields kept in the definitions item.
    fn definitions(&self, k: &Kept) -> Result<BTreeMap<String, Fields>, String> {
        k.iter()
            .map(|(provider, (_, v))| {
                let fields = serde_json::from_str(v).map_err(|e| {
                    format!(
                        "1Password vault `{}`: {DEFINITIONS}/{provider}: {e}",
                        self.name
                    )
                })?;
                Ok((provider.clone(), fields))
            })
            .collect()
    }
}

/// The copy on disk if it opens under this token and vault (and whether it
/// did), else an empty one: one sealed under another token, or damaged, is
/// dropped, and the next sync fills its successor from the vault.
fn load(sealer: &Sealer) -> Result<(Sqlite, bool), String> {
    let image = std::fs::read(copy_path())
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
fn copy_path() -> PathBuf {
    crate::providers::config_dir().join("1password-copy")
}

/// Whether an item with this title is sesame's to copy.
fn is_ours_title(t: &str) -> bool {
    t == DEFINITIONS || t.starts_with("sesame.")
}

fn client_of(k: &Kept) -> Option<Client> {
    value(k, CLIENT_ID).map(|client_id| Client {
        client_id,
        client_secret: value(k, CLIENT_SECRET),
    })
}

/// The item holding a provider's client and token.
fn title(provider: &str) -> String {
    format!("sesame.{provider}")
}

fn is_provider_field(label: &str) -> bool {
    CLIENT_FIELDS.contains(&label) || TOKEN_FIELDS.contains(&label)
}

fn put_client(k: &mut Kept, c: &Client) {
    k.retain(|l, _| !CLIENT_FIELDS.contains(&l.as_str()));
    put(k, CLIENT_ID, false, Some(c.client_id.clone()));
    put(k, CLIENT_SECRET, true, c.client_secret.clone());
}

fn put_token(k: &mut Kept, t: &Token) {
    k.retain(|l, _| !TOKEN_FIELDS.contains(&l.as_str()));
    put(k, ACCESS_TOKEN, true, Some(t.access_token.clone()));
    put(k, REFRESH_TOKEN, true, t.refresh_token.clone());
    put(k, EXPIRES_AT, false, t.expires_at.map(|e| e.to_string()));
    put(k, SCOPE, false, t.scope.clone());
    put(k, RESOURCE_ID, false, t.resource_id.clone());
    put(k, RESOURCE_NAME, false, t.resource_name.clone());
    put(k, ACCOUNT, false, t.account.clone());
    put(k, PASTED, false, t.pasted.then(|| "true".into()));
}

fn put(k: &mut Kept, label: &str, concealed: bool, value: Option<String>) {
    if let Some(v) = value {
        k.insert(label.into(), (concealed, v));
    }
}

fn value(k: &Kept, label: &str) -> Option<String> {
    k.get(label).map(|(_, v)| v.clone())
}

/// Whether an item's field is one sesame keeps: top level (no section), not
/// one of the item's own (the notes), labelled as `ours` says.
fn is_ours(f: &Value, ours: impl Fn(&str) -> bool) -> bool {
    let in_section = f["section"]["id"].as_str().is_some_and(|s| !s.is_empty());
    let label = f["label"].as_str().unwrap_or_default();
    !in_section && f.get("purpose").is_none_or(Value::is_null) && !label.is_empty() && ours(label)
}

fn kept(item: &Value, ours: impl Fn(&str) -> bool) -> Kept {
    item["fields"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| is_ours(f, &ours))
        .filter_map(|f| {
            let v = f["value"].as_str().filter(|v| !v.is_empty())?;
            let concealed = f["type"] == "CONCEALED";
            Some((f["label"].as_str()?.to_string(), (concealed, v.to_string())))
        })
        .collect()
}

/// The item template's fields for `k`; each field's id is its label, so
/// `op://<vault>/<title>/<label>` reads it.
fn fields(k: &Kept) -> Vec<Value> {
    k.iter()
        .map(|(label, (concealed, v))| {
            let kind = if *concealed { "CONCEALED" } else { "STRING" };
            json!({ "id": label, "label": label, "type": kind, "value": v })
        })
        .collect()
}

fn parse_item(out: &str) -> Result<Item, String> {
    let json: Value = serde_json::from_str(out).map_err(|e| format!("op printed no item: {e}"))?;
    let id = json["id"]
        .as_str()
        .ok_or("op printed an item without an id")?
        .to_string();
    Ok(Item { id, json })
}

/// op's error without its `[ERROR] <date> <time> ` prefix.
fn op_message(stderr: &str) -> String {
    let s = stderr.trim();
    match s.strip_prefix("[ERROR] ") {
        Some(rest) => rest.splitn(3, ' ').nth(2).unwrap_or(rest).to_string(),
        None => s.to_string(),
    }
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
fn lock_file() -> Result<std::fs::File, String> {
    let dir = crate::providers::config_dir();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
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
    use super::*;

    #[test]
    fn op_message_drops_the_prefix() {
        assert_eq!(
            op_message(
                "[ERROR] 2026/11/20 10:00:00 \"sesame.x\" isn't an item in the \"v\" vault.\n"
            ),
            "\"sesame.x\" isn't an item in the \"v\" vault."
        );
        assert_eq!(op_message("plain\n"), "plain");
    }

    #[test]
    fn kept_reads_only_sesames_top_level_fields() {
        let item = json!({"id": "i", "fields": [
            {"id": "notesPlain", "label": "notesPlain", "purpose": "NOTES", "type": "STRING", "value": "n"},
            {"id": "access_token", "label": "access_token", "type": "CONCEALED", "value": "a"},
            {"id": "x", "label": "access_token", "type": "STRING", "value": "s", "section": {"id": "other"}},
            {"id": "mine", "label": "mine", "type": "STRING", "value": "m"},
            {"id": "scope", "label": "scope", "type": "STRING", "value": ""},
        ]});
        let k = kept(&item, is_provider_field);
        assert_eq!(
            k,
            BTreeMap::from([("access_token".into(), (true, "a".into()))])
        );
        // And the template keeps the labels as ids.
        assert_eq!(fields(&k)[0]["id"], "access_token");
        assert_eq!(fields(&k)[0]["type"], "CONCEALED");
    }
}
