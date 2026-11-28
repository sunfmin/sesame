//! Where clients, tokens and the person's provider fields are kept: by
//! default one plaintext SQLite database (`sqlite`), or, when the environment
//! names one with `SESAME_1PASSWORD_VAULT`, a 1Password vault written through
//! a service account (`vault`, docs/adr/0001). The rest of sesame sees one
//! `Store` and does not know which.
mod migrate;
mod sqlite;
mod vault;

use crate::providers::Fields;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

pub use migrate::migrate;
pub use vault::{VAULT_VAR, take_token};

#[derive(Debug, Clone, PartialEq)]
pub struct Client {
    pub client_id: String,
    pub client_secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
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

/// Where the store keeps its files: `$SESAME_CONFIG_DIR`, else `~/.config/sesame`.
fn config_dir() -> PathBuf {
    config_dir_in(
        std::env::var_os("SESAME_CONFIG_DIR"),
        std::env::var_os("HOME"),
    )
}

/// `config_dir`, given `$SESAME_CONFIG_DIR` (`named`) and `$HOME`.
fn config_dir_in(named: Option<OsString>, home: Option<OsString>) -> PathBuf {
    match named {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(home.unwrap_or_default())
            .join(".config")
            .join("sesame"),
    }
}

pub enum Store {
    Sqlite(sqlite::Sqlite),
    Vault(Box<vault::Vault>),
}

impl Store {
    /// The store this machine's environment selects: the vault named by
    /// `SESAME_1PASSWORD_VAULT`, else `sesame.db`. A vault that is named but
    /// cannot be used is an error, never a silent fall back to `sesame.db`.
    pub fn open() -> Result<Store, String> {
        Store::open_with(false)
    }

    /// `open`, with a view current enough to list every provider's state
    /// (`sesame providers`): the vault's Copy is synced first, pushing what
    /// waits (docs/adr/0005). `sesame.db` is current.
    pub fn open_current() -> Result<Store, String> {
        Store::open_with(true)
    }

    fn open_with(current: bool) -> Result<Store, String> {
        match vault::Vault::from_env(current)? {
            Some(v) => Ok(Store::Vault(Box::new(v))),
            None => sqlite::Sqlite::open().map(Store::Sqlite),
        }
    }

    /// An empty `sesame.db` in memory, for tests.
    #[cfg(test)]
    pub fn in_memory() -> Result<Store, String> {
        sqlite::Sqlite::in_memory("test store", None).map(Store::Sqlite)
    }

    /// Runs `f` holding this machine's lock on the store: another process's
    /// `locked` waits until `f` returns, so a read-then-write (a refresh) does
    /// not race one elsewhere, and what `f` reads is read afresh.
    ///
    /// It serializes, nothing more: each write in `f` stands once made, and an
    /// error from `f` undoes none of them (the vault writes through to
    /// 1Password, which has no transaction; `sesame.db` keeps the same rule).
    /// So `f` checks what it needs before its first write.
    pub fn locked<T>(&self, f: impl FnOnce(&Store) -> Result<T, String>) -> Result<T, String> {
        match self {
            Store::Sqlite(s) => s.locked(|| f(self)),
            Store::Vault(v) => v.locked(|| f(self)),
        }
    }

    /// `provider`'s token as it stands now, to decide on refreshing it (call
    /// it under `locked`): what another machine wrote included, so a token it
    /// refreshed is used rather than refreshed again. `token` answers from
    /// the vault's Copy as last synced; this syncs it first (docs/adr/0005).
    /// `sesame.db` is this machine's alone: the same as `token`.
    pub fn latest_token(&self, provider: &str) -> Result<Option<Token>, String> {
        match self {
            Store::Sqlite(s) => s.token(provider),
            Store::Vault(v) => v.latest_token(provider),
        }
    }

    pub fn client(&self, provider: &str) -> Result<Option<Client>, String> {
        match self {
            Store::Sqlite(s) => s.client(provider),
            Store::Vault(v) => v.client(provider),
        }
    }

    pub fn save_client(&self, provider: &str, c: &Client) -> Result<(), String> {
        match self {
            Store::Sqlite(s) => s.save_client(provider, c),
            Store::Vault(v) => v.save_client(provider, c),
        }
    }

    /// Forgets the stored client; returns whether there was one.
    pub fn delete_client(&self, provider: &str) -> Result<bool, String> {
        match self {
            Store::Sqlite(s) => s.delete_client(provider),
            Store::Vault(v) => v.delete_client(provider),
        }
    }

    pub fn token(&self, provider: &str) -> Result<Option<Token>, String> {
        match self {
            Store::Sqlite(s) => s.token(provider),
            Store::Vault(v) => v.token(provider),
        }
    }

    pub fn save_token(&self, provider: &str, t: &Token) -> Result<(), String> {
        match self {
            Store::Sqlite(s) => s.save_token(provider, t),
            Store::Vault(v) => v.save_token(provider, t),
        }
    }

    /// Stores `t`, a token the provider issued in place of the stored one
    /// (a refresh): the command goes on with it even where the vault cannot
    /// take the write now (`Vault::keep_token`). `sesame.db` saves it.
    pub fn keep_token(&self, provider: &str, t: &Token) -> Result<(), String> {
        match self {
            Store::Sqlite(s) => s.save_token(provider, t),
            Store::Vault(v) => v.keep_token(provider, t),
        }
    }

    pub fn delete_token(&self, provider: &str) -> Result<(), String> {
        match self {
            Store::Sqlite(s) => s.delete_token(provider),
            Store::Vault(v) => v.delete_token(provider),
        }
    }

    /// Every provider's stored fields, by provider name.
    pub fn provider_fields(&self) -> Result<BTreeMap<String, Fields>, String> {
        match self {
            Store::Sqlite(s) => s.provider_fields(),
            Store::Vault(v) => v.provider_fields(),
        }
    }

    /// Replaces the provider's stored fields with `fields`.
    pub fn save_provider_fields(&self, provider: &str, fields: &Fields) -> Result<(), String> {
        match self {
            Store::Sqlite(s) => s.save_provider_fields(provider, fields),
            Store::Vault(v) => v.save_provider_fields(provider, fields),
        }
    }

    pub fn delete_provider_fields(&self, provider: &str) -> Result<(), String> {
        match self {
            Store::Sqlite(s) => s.delete_provider_fields(provider),
            Store::Vault(v) => v.save_provider_fields(provider, &Fields::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::config_dir_in;
    use std::path::PathBuf;

    #[test]
    fn config_dir_is_the_named_dir_else_dot_config_sesame_under_home() {
        assert_eq!(
            config_dir_in(Some("/named".into()), Some("/home/p".into())),
            PathBuf::from("/named")
        );
        assert_eq!(
            config_dir_in(None, Some("/home/p".into())),
            PathBuf::from("/home/p/.config/sesame")
        );
        assert_eq!(config_dir_in(None, None), PathBuf::from(".config/sesame"));
    }
}
