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
//! stdin, the token only in its environment. Every request counts against the
//! service account's budget, so an item is read at most once per process
//! (again only under the lock, `locked`), and written only when what sesame
//! keeps in it changed.
use super::{Client, Token};
use crate::providers::Fields;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

pub const VAULT_VAR: &str = "SESAME_1PASSWORD_VAULT";
pub const TOKEN_VAR: &str = "OP_SERVICE_ACCOUNT_TOKEN";
const TAG: &str = "sesame";
/// The item holding every provider's fields. Not `sesame.<x>`, so it is no
/// provider's.
const DEFINITIONS: &str = "sesame-providers";

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

/// What a process has read of the vault, by item title; `None`: no such item.
/// Cleared on taking the lock, so a read-then-write sees other processes' writes.
static ITEMS: Mutex<BTreeMap<String, Option<Item>>> = Mutex::new(BTreeMap::new());
/// The titles `op item list` showed (`list`), when it was asked: an item not
/// among them is not read.
static LISTED: Mutex<Option<BTreeSet<String>>> = Mutex::new(None);
/// Whether this process holds the lock (a nested `locked` runs inside it).
static HELD: AtomicBool = AtomicBool::new(false);

/// What sesame keeps in an item: field label → (concealed, value).
type Kept = BTreeMap<String, (bool, String)>;

pub struct Vault {
    name: String,
    token: String,
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
        Ok(Some(Vault { name, token }))
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

    /// The item titled `title`, read once per process (and once per lock).
    fn get(&self, title: &str) -> Result<Option<Item>, String> {
        if let Some(hit) = ITEMS.lock().unwrap().get(title) {
            return Ok(hit.clone());
        }
        let listed = LISTED.lock().unwrap().as_ref().map(|l| l.contains(title));
        let item = if listed == Some(false) {
            None
        } else {
            let args = [
                "item", "get", title, "--vault", &self.name, "--format", "json",
            ];
            match self.op(&args, None) {
                Ok(out) => Some(parse_item(&out).map_err(|e| format!("reading `{title}`: {e}"))?),
                Err(OpError::NoItem) => None,
                Err(e) => return Err(self.failed(&format!("reading `{title}`"), e)),
            }
        };
        ITEMS.lock().unwrap().insert(title.into(), item.clone());
        Ok(item)
    }

    /// Asks the vault once which `sesame` items it holds, so reading one it
    /// does not costs no request.
    pub fn list(&self) -> Result<(), String> {
        let args = [
            "item", "list", "--vault", &self.name, "--tags", TAG, "--format", "json",
        ];
        let out = self
            .op(&args, None)
            .map_err(|e| self.failed("listing items", e))?;
        let items: Vec<Value> = serde_json::from_str(&out)
            .map_err(|e| format!("1Password vault `{}`: listing items: {e}", self.name))?;
        let titles = items
            .iter()
            .filter_map(|i| i["title"].as_str().map(String::from))
            .collect();
        *LISTED.lock().unwrap() = Some(titles);
        Ok(())
    }

    /// Runs `f` holding this machine's lock (a file in the config dir that
    /// holds nothing), having forgotten what was read before: 1Password has no
    /// lock, so this keeps two processes here from both refreshing.
    pub fn locked<T>(&self, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        if HELD.swap(true, Ordering::SeqCst) {
            return f();
        }
        let result = (|| {
            let file = lock_file()?;
            file.lock().map_err(|e| format!("locking: {e}"))?;
            ITEMS.lock().unwrap().clear();
            *LISTED.lock().unwrap() = None;
            f()
            // Dropping `file` unlocks it.
        })();
        HELD.store(false, Ordering::SeqCst);
        result
    }

    /// What sesame keeps in the item, empty if there is none.
    fn kept(&self, title: &str, ours: impl Fn(&str) -> bool) -> Result<Kept, String> {
        Ok(self
            .get(title)?
            .map(|i| kept(&i.json, ours))
            .unwrap_or_default())
    }

    /// Changes what sesame keeps in the item `title` with `change`, and writes
    /// the item only if that changed: created when new, archived when left
    /// with nothing in it, else edited keeping what others put there.
    fn update(
        &self,
        title: &str,
        ours: impl Fn(&str) -> bool,
        change: impl FnOnce(&mut Kept),
    ) -> Result<(), String> {
        let current = self.get(title)?;
        let have = current
            .as_ref()
            .map(|i| kept(&i.json, &ours))
            .unwrap_or_default();
        let mut want = have.clone();
        change(&mut want);
        if want == have {
            return Ok(());
        }
        let what = format!("writing `{title}`");
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
        let mut items = ITEMS.lock().unwrap();
        match written {
            Some(Some(item)) => {
                items.insert(title.into(), Some(item));
            }
            // What op printed was not the item: read it again if needed.
            Some(None) => {
                items.remove(title);
            }
            None => {
                items.insert(title.into(), None);
            }
        }
        Ok(())
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
        let k = self.kept(&title(provider), is_provider_field)?;
        Ok(value(&k, CLIENT_ID).map(|client_id| Client {
            client_id,
            client_secret: value(&k, CLIENT_SECRET),
        }))
    }

    pub fn save_client(&self, provider: &str, c: &Client) -> Result<(), String> {
        self.update(&title(provider), is_provider_field, |k| {
            k.retain(|l, _| !CLIENT_FIELDS.contains(&l.as_str()));
            put(k, CLIENT_ID, false, Some(c.client_id.clone()));
            put(k, CLIENT_SECRET, true, c.client_secret.clone());
        })
    }

    pub fn delete_client(&self, provider: &str) -> Result<bool, String> {
        let had = self.client(provider)?.is_some();
        self.update(&title(provider), is_provider_field, |k| {
            k.retain(|l, _| !CLIENT_FIELDS.contains(&l.as_str()));
        })?;
        Ok(had)
    }

    pub fn token(&self, provider: &str) -> Result<Option<Token>, String> {
        let k = self.kept(&title(provider), is_provider_field)?;
        let Some(access_token) = value(&k, ACCESS_TOKEN) else {
            return Ok(None);
        };
        let expires_at = value(&k, EXPIRES_AT)
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
            refresh_token: value(&k, REFRESH_TOKEN),
            expires_at,
            scope: value(&k, SCOPE),
            resource_id: value(&k, RESOURCE_ID),
            resource_name: value(&k, RESOURCE_NAME),
            account: value(&k, ACCOUNT),
            pasted: value(&k, PASTED).is_some_and(|p| p == "true"),
        }))
    }

    pub fn save_token(&self, provider: &str, t: &Token) -> Result<(), String> {
        self.update(&title(provider), is_provider_field, |k| {
            k.retain(|l, _| !TOKEN_FIELDS.contains(&l.as_str()));
            put(k, ACCESS_TOKEN, true, Some(t.access_token.clone()));
            put(k, REFRESH_TOKEN, true, t.refresh_token.clone());
            put(k, EXPIRES_AT, false, t.expires_at.map(|e| e.to_string()));
            put(k, SCOPE, false, t.scope.clone());
            put(k, RESOURCE_ID, false, t.resource_id.clone());
            put(k, RESOURCE_NAME, false, t.resource_name.clone());
            put(k, ACCOUNT, false, t.account.clone());
            put(k, PASTED, false, t.pasted.then(|| "true".into()));
        })
    }

    pub fn delete_token(&self, provider: &str) -> Result<(), String> {
        self.update(&title(provider), is_provider_field, |k| {
            k.retain(|l, _| !TOKEN_FIELDS.contains(&l.as_str()));
        })
    }

    pub fn provider_fields(&self) -> Result<BTreeMap<String, Fields>, String> {
        let k = self.kept(DEFINITIONS, |_| true)?;
        k.into_iter()
            .map(|(provider, (_, v))| {
                let fields = serde_json::from_str(&v).map_err(|e| {
                    format!(
                        "1Password vault `{}`: {DEFINITIONS}/{provider}: {e}",
                        self.name
                    )
                })?;
                Ok((provider, fields))
            })
            .collect()
    }

    /// Replaces the provider's stored fields; none removes its field.
    pub fn save_provider_fields(&self, provider: &str, fields: &Fields) -> Result<(), String> {
        let value = (!fields.is_empty()).then(|| Value::Object(fields.clone()).to_string());
        self.update(
            DEFINITIONS,
            |_| true,
            |k| {
                k.remove(provider);
                put(k, provider, false, value);
            },
        )
    }
}

/// The item holding a provider's client and token.
fn title(provider: &str) -> String {
    format!("sesame.{provider}")
}

fn is_provider_field(label: &str) -> bool {
    CLIENT_FIELDS.contains(&label) || TOKEN_FIELDS.contains(&label)
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
