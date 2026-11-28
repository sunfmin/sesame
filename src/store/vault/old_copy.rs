//! The Copy sesame kept itself before it used opcore's (docs/adr/0006):
//! `sesame.db`'s tables, sealed at `<config_dir>/1password-copy`. It is
//! never opened as a Copy again; it is read once, for the tokens it marked
//! `unwritten_tokens` (refreshed here, refused by the vault then), which
//! exist nowhere else and are written to the vault before it goes.
use super::Token;
use crate::store::sqlite::Sqlite;
use opcore::Sealer;
use std::path::{Path, PathBuf};

/// `<config_dir>/1password-copy`.
pub fn path(dir: &Path) -> PathBuf {
    dir.join("1password-copy")
}

/// The tokens the old Copy at `path` (vault `vault`, sealed under `token`)
/// marked unwritten, by provider. None from a file that does not open
/// (another token, another vault, damage): it would have been dropped and
/// rebuilt then too.
pub fn unwritten_tokens(path: &Path, vault: &str, token: &str) -> Vec<(String, Token)> {
    let sealer = Sealer::new(token, &format!("sesame's copy of 1Password vault {vault}"));
    let Some(image) = std::fs::read(path).ok().and_then(|b| sealer.open(&b)) else {
        return Vec::new();
    };
    let Ok(rows) = Sqlite::in_memory("sesame's old copy", Some(&image)) else {
        return Vec::new();
    };
    let marked: Vec<String> = rows
        .conn()
        .prepare("SELECT provider FROM unwritten_tokens")
        .and_then(|mut s| s.query_map([], |r| r.get(0))?.collect())
        .unwrap_or_default();
    marked
        .into_iter()
        .filter_map(|p| Some((p.clone(), rows.token(&p).ok()??)))
        .collect()
}
