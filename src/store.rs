//! Where clients, tokens and the person's provider fields are kept: by
//! default one plaintext SQLite database (`sqlite`), or, when the environment
//! names one with `SESAME_1PASSWORD_VAULT`, a 1Password vault written through
//! a service account (`vault`, docs/adr/0001). The rest of sesame sees one
//! `Store` and does not know which.
mod migrate;
mod sealed;
mod sqlite;
mod vault;

use crate::providers::Fields;
use std::collections::BTreeMap;

pub use migrate::migrate;
pub use vault::take_token;

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

pub enum Store {
    Sqlite(sqlite::Sqlite),
    Vault(vault::Vault),
}

impl Store {
    /// The store this machine's environment selects: the vault named by
    /// `SESAME_1PASSWORD_VAULT`, else `sesame.db`. A vault that is named but
    /// cannot be used is an error, never a silent fall back to `sesame.db`.
    pub fn open() -> Result<Store, String> {
        match vault::Vault::from_env()? {
            Some(v) => Ok(Store::Vault(v)),
            None => sqlite::Sqlite::open().map(Store::Sqlite),
        }
    }

    /// An empty `sesame.db` in memory, for tests.
    #[cfg(test)]
    pub fn in_memory() -> Result<Store, String> {
        sqlite::Sqlite::in_memory("test store", None).map(Store::Sqlite)
    }

    /// Runs `f` holding this machine's lock on the store, so a read-then-write
    /// (a refresh) in another process waits for this one rather than racing
    /// it; what `f` reads is read afresh.
    pub fn locked<T>(&self, f: impl FnOnce(&Store) -> Result<T, String>) -> Result<T, String> {
        match self {
            Store::Sqlite(s) => s.locked(|| f(self)),
            Store::Vault(v) => v.locked(|| f(self)),
        }
    }

    /// Before showing every provider's state (`sesame providers`): brings the
    /// vault's local copy up to date (one request when nothing moved).
    pub fn read_many(&self) -> Result<(), String> {
        match self {
            Store::Sqlite(_) => Ok(()),
            Store::Vault(v) => v.locked(|| v.sync(None)),
        }
    }

    /// Before deciding to refresh `provider`'s token (under `locked`): lets in
    /// what other machines wrote, `provider`'s item read whatever happened.
    /// `sesame.db` is this machine's alone: nothing to do.
    pub fn sync(&self, provider: &str) -> Result<(), String> {
        match self {
            Store::Sqlite(_) => Ok(()),
            Store::Vault(v) => v.sync(Some(provider)),
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
