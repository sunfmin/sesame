//! The default store: one plaintext SQLite database, `<config_dir>/sesame.db`,
//! guarded by file permissions as gcloud's are: the directory 0700, the file 0600.
use super::{Client, Token};
use crate::providers::Fields;
use rusqlite::{Connection, MAIN_DB, OptionalExtension, params};
use std::collections::BTreeMap;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

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

pub struct Sqlite {
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

impl Sqlite {
    pub fn open() -> Result<Sqlite, String> {
        Sqlite::open_at(path())
    }

    fn open_at(path: PathBuf) -> Result<Sqlite, String> {
        prepare(&path)?;
        let conn = Connection::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let store = Sqlite { conn, path };
        // No WAL: the rollback journal SQLite makes takes the database's 0600.
        store
            .conn
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(|e| store.err(e))?;
        store.migrate()?;
        Ok(store)
    }

    /// A database in memory, named `name` in errors, with nothing on disk:
    /// `image` (what `image` gave) if any, else empty; migrated either way.
    pub fn in_memory(name: &str, image: Option<&[u8]>) -> Result<Sqlite, String> {
        let err = |e: rusqlite::Error| format!("{name}: {e}");
        let mut conn = Connection::open_in_memory().map_err(err)?;
        if let Some(image) = image {
            conn.deserialize_read_exact(MAIN_DB, image, image.len(), false)
                .map_err(err)?;
        }
        let store = Sqlite {
            conn,
            path: PathBuf::from(name),
        };
        store.migrate()?;
        Ok(store)
    }

    /// The whole database as bytes, for `in_memory` to take back.
    pub fn image(&mut self) -> Result<Vec<u8>, String> {
        let data = self
            .conn
            .serialize(MAIN_DB)
            .map_err(|e| format!("{}: {e}", self.path.display()))?;
        Ok(data.to_vec())
    }

    /// The connection, for a caller keeping tables of its own beside these.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    fn migrate(&self) -> Result<(), String> {
        self.transaction(|| {
            let version: i64 = self
                .conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .map_err(|e| self.err(e))?;
            for (i, step) in MIGRATIONS.iter().enumerate().skip(version as usize) {
                self.conn.execute_batch(step).map_err(|e| self.err(e))?;
                self.conn
                    .pragma_update(None, "user_version", i as i64 + 1)
                    .map_err(|e| self.err(e))?;
            }
            Ok(())
        })
    }

    fn err(&self, e: rusqlite::Error) -> String {
        format!("{}: {e}", self.path.display())
    }

    /// Runs `f` holding the database's write lock, so a read-then-write (a
    /// refresh) in another process waits for this one rather than racing it.
    /// It serializes only (`Store::locked`'s contract): what `f` wrote is
    /// committed even when `f` fails, as the vault's writes would stand.
    pub fn locked<T>(&self, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| self.err(e))?;
        let result = f();
        self.conn.execute_batch("COMMIT").map_err(|e| self.err(e))?;
        result
    }

    /// Runs `f` as one transaction: all of it, or, when it fails, none.
    /// Schema migrations only: the rest of sesame gets `locked`.
    fn transaction<T>(&self, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| self.err(e))?;
        match f() {
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

    /// The providers with a stored client or token.
    pub fn logins(&self) -> Result<Vec<String>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT provider FROM clients UNION SELECT provider FROM tokens ORDER BY 1")
            .map_err(|e| self.err(e))?;
        let rows = stmt.query_map([], |r| r.get(0)).map_err(|e| self.err(e))?;
        rows.collect::<Result<_, _>>().map_err(|e| self.err(e))
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

    /// Forgets the stored client; returns whether there was one.
    pub fn delete_client(&self, provider: &str) -> Result<bool, String> {
        self.conn
            .execute("DELETE FROM clients WHERE provider = ?1", [provider])
            .map(|n| n > 0)
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

    /// `locked` serializes only, as the vault does: a write made before `f`
    /// fails stands, and the database is usable after.
    #[test]
    fn locked_keeps_writes_made_before_an_error() {
        let s = Sqlite::in_memory("test", None).unwrap();
        let c = |id: &str| Client {
            client_id: id.into(),
            client_secret: None,
        };
        let r: Result<(), String> = s.locked(|| {
            s.save_client("p", &c("id"))?;
            Err("midway".into())
        });
        assert_eq!(r, Err("midway".into()));
        assert_eq!(s.client("p").unwrap(), Some(c("id")));
        s.locked(|| s.save_client("q", &c("q"))).unwrap();
        assert_eq!(s.client("q").unwrap(), Some(c("q")));
    }

    /// A migration step that fails leaves none of itself: the next run
    /// starts that step again from where the schema was.
    #[test]
    fn failed_migration_leaves_the_schema_as_it_was() {
        let dir = tmp("failed-migration");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("sesame.db");
        // The first step creates `clients`, then fails on this `tokens`.
        Connection::open(&db)
            .unwrap()
            .execute_batch("CREATE TABLE tokens (x)")
            .unwrap();
        assert!(Sqlite::open_at(db.clone()).is_err());
        let conn = Connection::open(&db).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        let clients: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name = 'clients'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!((version, clients), (0, 0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new_database_is_0600_in_a_0700_directory() {
        let dir = tmp("new").join("sesame");
        let db = dir.join("sesame.db");
        let s = Sqlite::open_at(db.clone()).unwrap();
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
        Sqlite::open_at(db.clone()).unwrap();
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
        Sqlite::open_at(db.clone())
            .unwrap()
            .save_token("p", &t(0))
            .unwrap();
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let db = db.clone();
                std::thread::spawn(move || {
                    let s = Sqlite::open_at(db).unwrap();
                    s.locked(|| {
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
        let s = Sqlite::open_at(db).unwrap();
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
        Sqlite::open_at(db.clone())
            .unwrap()
            .save_token("p", &t)
            .unwrap();
        let s = Sqlite::open_at(db).unwrap();
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
    fn an_image_comes_back_whole_and_migrated() {
        let mut s = Sqlite::in_memory("copy", None).unwrap();
        s.save_client(
            "p",
            &Client {
                client_id: "id".into(),
                client_secret: Some("s".into()),
            },
        )
        .unwrap();
        let image = s.image().unwrap();
        let back = Sqlite::in_memory("copy", Some(&image)).unwrap();
        assert_eq!(
            back.client("p").unwrap().unwrap().client_secret,
            Some("s".into())
        );
        let v: i64 = back
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v as usize, MIGRATIONS.len());
        assert!(Sqlite::in_memory("copy", Some(b"not a database")).is_err());
    }

    #[test]
    fn provider_fields_are_replaced_whole() {
        let dir = tmp("fields");
        let s = Sqlite::open_at(dir.join("sesame.db")).unwrap();
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
