//! Clients, tokens and the person's provider fields live in one plaintext SQLite
//! database, `<config_dir>/sesame.db`, guarded by file permissions as gcloud's
//! are: the directory 0700, the file 0600.
use crate::providers::Fields;
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::BTreeMap;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
    pub client_secret: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix seconds.
    pub expires_at: Option<u64>,
    pub scope: Option<String>,
    pub resource_id: Option<String>,
    pub resource_name: Option<String>,
    /// Pasted by the person (`sesame login --token`), not from an OAuth login.
    pub pasted: bool,
    /// Who signed in, from the provider's `identity_url`.
    pub account: Option<String>,
}

/// The schema, one step per `PRAGMA user_version`: append a step, never edit one.
const MIGRATIONS: &[&str] = &[
    "
    CREATE TABLE clients (
        provider TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        client_secret TEXT
    );
    CREATE TABLE tokens (
        provider TEXT PRIMARY KEY,
        access_token TEXT NOT NULL,
        refresh_token TEXT,
        expires_at INTEGER,
        scope TEXT,
        resource_id TEXT,
        resource_name TEXT
    );
",
    "
    -- A provider's fields the person set, each a JSON value; see providers::effective.
    CREATE TABLE provider_fields (
        provider TEXT NOT NULL,
        field TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY (provider, field)
    );
",
    "
    -- Who signed in, from the provider's identity_url.
    ALTER TABLE tokens ADD COLUMN account TEXT;
",
    "
    -- 1 for a token the person pasted (`sesame login --token`).
    ALTER TABLE tokens ADD COLUMN pasted INTEGER NOT NULL DEFAULT 0;
",
];

/// How long a process waits for another's write (a refresh holds the lock
/// across its HTTP request, which reqwest gives up on after 30s).
const BUSY_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Store {
    conn: Connection,
    path: PathBuf,
}

pub fn path() -> PathBuf {
    crate::providers::config_dir().join("sesame.db")
}

/// Makes the directory 0700 if missing and the file 0600, tightening a wider one.
fn prepare(path: &Path) -> Result<(), String> {
    let at = |e: std::io::Error, p: &Path| format!("{}: {e}", p.display());
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| at(e, dir))?;
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|e| at(e, path))?;
    let mode = file
        .metadata()
        .map_err(|e| at(e, path))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| at(e, path))?;
    }
    Ok(())
}

impl Store {
    pub fn open() -> Result<Store, String> {
        Store::open_at(path())
    }

    fn open_at(path: PathBuf) -> Result<Store, String> {
        prepare(&path)?;
        let conn = Connection::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let store = Store { conn, path };
        // No WAL: the rollback journal SQLite makes takes the database's 0600.
        store
            .conn
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(|e| store.err(e))?;
        store.locked(|s| {
            let version: i64 = s
                .conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .map_err(|e| s.err(e))?;
            for (i, step) in MIGRATIONS.iter().enumerate().skip(version as usize) {
                s.conn.execute_batch(step).map_err(|e| s.err(e))?;
                s.conn
                    .pragma_update(None, "user_version", i as i64 + 1)
                    .map_err(|e| s.err(e))?;
            }
            Ok(())
        })?;
        Ok(store)
    }

    fn err(&self, e: rusqlite::Error) -> String {
        format!("{}: {e}", self.path.display())
    }

    /// Runs `f` holding the database's write lock, so a read-then-write (a
    /// refresh) in another process waits for this one rather than racing it.
    pub fn locked<T>(&self, f: impl FnOnce(&Store) -> Result<T, String>) -> Result<T, String> {
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| self.err(e))?;
        match f(self) {
            Ok(v) => {
                self.conn.execute_batch("COMMIT").map_err(|e| self.err(e))?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    pub fn client(&self, provider: &str) -> Result<Option<Client>, String> {
        self.conn
            .query_row(
                "SELECT client_id, client_secret FROM clients WHERE provider = ?1",
                [provider],
                |r| {
                    Ok(Client {
                        client_id: r.get(0)?,
                        client_secret: r.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(|e| self.err(e))
    }

    pub fn save_client(&self, provider: &str, c: &Client) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO clients (provider, client_id, client_secret)
                 VALUES (?1, ?2, ?3)",
                params![provider, c.client_id, c.client_secret],
            )
            .map(drop)
            .map_err(|e| self.err(e))
    }

    pub fn token(&self, provider: &str) -> Result<Option<Token>, String> {
        self.conn
            .query_row(
                "SELECT access_token, refresh_token, expires_at, scope, resource_id, resource_name,
                        account, pasted
                 FROM tokens WHERE provider = ?1",
                [provider],
                |r| {
                    Ok(Token {
                        access_token: r.get(0)?,
                        refresh_token: r.get(1)?,
                        expires_at: r.get::<_, Option<i64>>(2)?.map(|t| t as u64),
                        scope: r.get(3)?,
                        resource_id: r.get(4)?,
                        resource_name: r.get(5)?,
                        account: r.get(6)?,
                        pasted: r.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(|e| self.err(e))
    }

    pub fn save_token(&self, provider: &str, t: &Token) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO tokens
                 (provider, access_token, refresh_token, expires_at, scope, resource_id, resource_name,
                  account, pasted)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    provider,
                    t.access_token,
                    t.refresh_token,
                    t.expires_at.map(|t| t as i64),
                    t.scope,
                    t.resource_id,
                    t.resource_name,
                    t.account,
                    t.pasted
                ],
            )
            .map(drop)
            .map_err(|e| self.err(e))
    }

    /// Every provider's stored fields, by provider name.
    pub fn provider_fields(&self) -> Result<BTreeMap<String, Fields>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT provider, field, value FROM provider_fields")
            .map_err(|e| self.err(e))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| self.err(e))?;
        let mut all: BTreeMap<String, Fields> = BTreeMap::new();
        for row in rows {
            let (provider, field, value) = row.map_err(|e| self.err(e))?;
            let value = serde_json::from_str(&value)
                .map_err(|e| format!("{}: {provider}.{field}: {e}", self.path.display()))?;
            all.entry(provider).or_default().insert(field, value);
        }
        Ok(all)
    }

    /// Replaces the provider's stored fields with `fields`.
    pub fn save_provider_fields(&self, provider: &str, fields: &Fields) -> Result<(), String> {
        self.delete_provider_fields(provider)?;
        for (field, value) in fields {
            self.conn
                .execute(
                    "INSERT INTO provider_fields (provider, field, value) VALUES (?1, ?2, ?3)",
                    params![provider, field, value.to_string()],
                )
                .map_err(|e| self.err(e))?;
        }
        Ok(())
    }

    pub fn delete_provider_fields(&self, provider: &str) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM provider_fields WHERE provider = ?1",
                [provider],
            )
            .map(drop)
            .map_err(|e| self.err(e))
    }

    pub fn delete_token(&self, provider: &str) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM tokens WHERE provider = ?1", [provider])
            .map(drop)
            .map_err(|e| self.err(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sesame-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn new_database_is_0600_in_a_0700_directory() {
        let dir = tmp("new").join("sesame");
        let db = dir.join("sesame.db");
        let s = Store::open_at(db.clone()).unwrap();
        s.save_client(
            "p",
            &Client {
                client_id: "id".into(),
                client_secret: None,
            },
        )
        .unwrap();
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&db), 0o600);
        assert_eq!(s.client("p").unwrap().unwrap().client_id, "id");
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn wider_existing_file_is_tightened() {
        let dir = tmp("wide");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("sesame.db");
        std::fs::write(&db, b"").unwrap();
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
        Store::open_at(db.clone()).unwrap();
        assert_eq!(mode(&db), 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_read_then_write_waits_instead_of_failing() {
        let dir = tmp("race");
        let db = dir.join("sesame.db");
        let t = |n: u64| Token {
            access_token: "a".into(),
            refresh_token: None,
            expires_at: Some(n),
            scope: None,
            resource_id: None,
            resource_name: None,
            account: None,
            pasted: false,
        };
        Store::open_at(db.clone())
            .unwrap()
            .save_token("p", &t(0))
            .unwrap();
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let db = db.clone();
                std::thread::spawn(move || {
                    let s = Store::open_at(db).unwrap();
                    s.locked(|s| {
                        let n = s.token("p")?.unwrap().expires_at.unwrap();
                        // A refresh's HTTP request, while the lock is held.
                        std::thread::sleep(Duration::from_millis(200));
                        s.save_token("p", &t(n + 1))
                    })
                })
            })
            .collect();
        for w in workers {
            w.join().unwrap().unwrap();
        }
        let s = Store::open_at(db).unwrap();
        assert_eq!(s.token("p").unwrap().unwrap().expires_at, Some(4));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reopening_keeps_rows_and_schema_version() {
        let dir = tmp("reopen");
        let db = dir.join("sesame.db");
        let t = Token {
            access_token: "a".into(),
            refresh_token: Some("r".into()),
            expires_at: Some(42),
            scope: None,
            resource_id: Some("site".into()),
            resource_name: None,
            account: None,
            pasted: true,
        };
        Store::open_at(db.clone())
            .unwrap()
            .save_token("p", &t)
            .unwrap();
        let s = Store::open_at(db).unwrap();
        let v: i64 = s
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v as usize, MIGRATIONS.len());
        let got = s.token("p").unwrap().unwrap();
        assert_eq!(
            (got.expires_at, got.resource_id, got.pasted),
            (Some(42), Some("site".into()), true)
        );
        s.delete_token("p").unwrap();
        assert!(s.token("p").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn provider_fields_are_replaced_whole() {
        let dir = tmp("fields");
        let s = Store::open_at(dir.join("sesame.db")).unwrap();
        let f = |v: serde_json::Value| v.as_object().unwrap().clone();
        s.save_provider_fields(
            "p",
            &f(serde_json::json!({"scopes": ["a"], "redirect_port": 1})),
        )
        .unwrap();
        s.save_provider_fields("p", &f(serde_json::json!({"scopes": ["b"]})))
            .unwrap();
        s.save_provider_fields("q", &f(serde_json::json!({"about": "q"})))
            .unwrap();
        let all = s.provider_fields().unwrap();
        assert_eq!(all["p"], f(serde_json::json!({"scopes": ["b"]})));
        s.delete_provider_fields("p").unwrap();
        assert_eq!(
            s.provider_fields().unwrap().keys().collect::<Vec<_>>(),
            ["q"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
