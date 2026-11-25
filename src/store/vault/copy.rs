//! The local copy (docs/adr/0002): `sesame.db`'s tables in memory, plus each
//! item's id and `version` at the last sync, when it synced, and the
//! providers whose token the vault does not hold yet. On disk only sealed,
//! under a key derived from the service account token, at
//! `<config_dir>/1password-copy`, beside the lock that keeps two processes
//! here from overwriting each other's copy.
use super::item::{self, is_provider_field, kept};
use super::op::Item;
use super::{DEFINITIONS, Token};
use crate::store::sealed::Sealer;
use crate::store::sqlite::Sqlite;
use rusqlite::{OptionalExtension, params};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// The copy's own tables, beside `sesame.db`'s: which item each provider's
/// rows came from and its version then, when the copy last synced, and the
/// providers whose token row the vault does not hold yet.
const COPY_TABLES: &str = "
    CREATE TABLE IF NOT EXISTS vault_items (
        title TEXT PRIMARY KEY,
        id TEXT NOT NULL,
        version INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS copy_synced (at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS unwritten_tokens (provider TEXT PRIMARY KEY);
";

pub struct LocalCopy {
    /// `sesame.db`'s rows and the copy's own tables.
    rows: Sqlite,
    sealer: Sealer,
    /// Where the copy and the lock live: the config dir.
    dir: PathBuf,
    /// The vault's name, for errors.
    vault: String,
}

impl LocalCopy {
    /// Vault `vault`'s copy in `dir` if it opens under `token` (and whether
    /// it did), else an empty one: one sealed under another token, or
    /// damaged, is dropped, and the next sync fills its successor.
    pub fn load(vault: &str, token: &str, dir: PathBuf) -> Result<(LocalCopy, bool), String> {
        let sealer = Sealer::new(token, &format!("sesame's copy of 1Password vault {vault}"));
        let (rows, opened) = read(&sealer, &dir)?;
        let copy = LocalCopy {
            rows,
            sealer,
            dir,
            vault: vault.into(),
        };
        Ok((copy, opened))
    }

    /// Takes this machine's lock (a file in the config dir that holds
    /// nothing), then rereads the copy as another process may have left it.
    /// The lock is held until the file answered drops.
    pub fn lock(&mut self) -> Result<std::fs::File, String> {
        let file = lock_file(&self.dir)?;
        file.lock().map_err(|e| format!("locking: {e}"))?;
        self.rows = read(&self.sealer, &self.dir)?.0;
        Ok(file)
    }

    /// Writes the copy to disk, sealed: to a file beside it, then renamed
    /// over it, so a reader sees the old copy or the new, never half.
    pub fn save(&mut self) -> Result<(), String> {
        let image = self.rows.image()?;
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

    /// `sesame.db`'s rows, as the vault's items last read hold them.
    pub fn rows(&self) -> &Sqlite {
        &self.rows
    }

    fn err(&self, e: rusqlite::Error) -> String {
        format!("sesame's copy of 1Password vault `{}`: {e}", self.vault)
    }

    /// When the copy last synced, if it ever did.
    pub fn synced_at(&self) -> Result<Option<u64>, String> {
        self.rows
            .conn()
            .query_row("SELECT at FROM copy_synced", [], |r| r.get::<_, i64>(0))
            .optional()
            .map(|t| t.map(|t| t as u64))
            .map_err(|e| self.err(e))
    }

    pub fn mark_synced(&self, at: u64) -> Result<(), String> {
        let conn = self.rows.conn();
        conn.execute_batch("DELETE FROM copy_synced")
            .and_then(|_| conn.execute("INSERT INTO copy_synced (at) VALUES (?1)", [at as i64]))
            .map(drop)
            .map_err(|e| self.err(e))
    }

    /// Each item the copy holds rows of: title → (id, version).
    pub fn items(&self) -> Result<BTreeMap<String, (String, u64)>, String> {
        let mut stmt = self
            .rows
            .conn()
            .prepare("SELECT title, id, version FROM vault_items")
            .map_err(|e| self.err(e))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, (r.get(1)?, r.get::<_, i64>(2)? as u64)))
            })
            .map_err(|e| self.err(e))?;
        rows.collect::<Result<_, _>>().map_err(|e| self.err(e))
    }

    /// Makes the rows of item `title` what `item` holds (none: the item is
    /// gone), and records its id and version. An unwritten token stays as
    /// it is; an item that is not sesame's changes nothing.
    pub fn apply(&self, title: &str, item: Option<&Item>) -> Result<(), String> {
        let copy = &self.rows;
        let bad = |e: String| format!("1Password vault `{}`: {title}/{e}", self.vault);
        if title == DEFINITIONS {
            for provider in copy.provider_fields()?.into_keys() {
                copy.delete_provider_fields(&provider)?;
            }
            if let Some(item) = item {
                for (provider, fields) in
                    item::definitions(&kept(&item.json, |_| true)).map_err(bad)?
                {
                    copy.save_provider_fields(&provider, &fields)?;
                }
            }
        } else if let Some(provider) = title.strip_prefix("sesame.") {
            let unwritten = self.unwritten()?.iter().any(|p| p == provider);
            copy.delete_client(provider)?;
            if !unwritten {
                copy.delete_token(provider)?;
            }
            if let Some(item) = item {
                let k = kept(&item.json, is_provider_field);
                if let Some(c) = item::client_of(&k) {
                    copy.save_client(provider, &c)?;
                }
                if let Some(t) = item::token_of(&k).map_err(bad)?
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
        .map_err(|e| self.err(e))
    }

    /// The providers whose token in the copy the vault does not hold yet.
    pub fn unwritten(&self) -> Result<Vec<String>, String> {
        let mut stmt = self
            .rows
            .conn()
            .prepare("SELECT provider FROM unwritten_tokens")
            .map_err(|e| self.err(e))?;
        let rows = stmt.query_map([], |r| r.get(0)).map_err(|e| self.err(e))?;
        rows.collect::<Result<_, _>>().map_err(|e| self.err(e))
    }

    /// `provider`'s token in the copy, if the vault does not hold it yet.
    pub fn unwritten_token(&self, provider: &str) -> Result<Option<Token>, String> {
        match self.unwritten()?.iter().any(|p| p == provider) {
            true => self.rows.token(provider),
            false => Ok(None),
        }
    }

    /// Keeps `t` as `provider`'s token, marked unwritten, and saves the copy.
    pub fn keep_unwritten(&mut self, provider: &str, t: &Token) -> Result<(), String> {
        self.rows.save_token(provider, t)?;
        self.set_unwritten(provider, true)?;
        self.save()
    }

    pub fn set_unwritten(&self, provider: &str, unwritten: bool) -> Result<(), String> {
        let sql = match unwritten {
            true => "INSERT OR IGNORE INTO unwritten_tokens (provider) VALUES (?1)",
            false => "DELETE FROM unwritten_tokens WHERE provider = ?1",
        };
        self.rows
            .conn()
            .execute(sql, [provider])
            .map(drop)
            .map_err(|e| self.err(e))
    }
}

/// The copy on disk if it opens under this sealer (and whether it did),
/// else an empty one.
fn read(sealer: &Sealer, dir: &Path) -> Result<(Sqlite, bool), String> {
    let image = std::fs::read(copy_path(dir))
        .ok()
        .and_then(|b| sealer.open(&b));
    if let Some(copy) = image.and_then(|i| open_rows(Some(&i)).ok()) {
        return Ok((copy, true));
    }
    Ok((open_rows(None)?, false))
}

fn open_rows(image: Option<&[u8]>) -> Result<Sqlite, String> {
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
