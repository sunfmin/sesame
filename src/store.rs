//! Secrets live in the OS keychain (service `sesame`), or, when SESAME_STORE_DIR is
//! set, in 0600 files there (headless hosts and tests).
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub client_id: String,
    pub client_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix seconds.
    pub expires_at: Option<u64>,
    pub scope: Option<String>,
    pub resource_id: Option<String>,
    pub resource_name: Option<String>,
}

pub enum Kind {
    Client,
    Token,
}

fn key(provider: &str, kind: Kind) -> String {
    match kind {
        Kind::Client => format!("{provider}/client"),
        Kind::Token => format!("{provider}/token"),
    }
}

fn dir() -> Option<PathBuf> {
    std::env::var_os("SESAME_STORE_DIR").map(PathBuf::from)
}

pub fn load<T: DeserializeOwned>(provider: &str, kind: Kind) -> Result<Option<T>, String> {
    let key = key(provider, kind);
    let text = match dir() {
        Some(d) => match std::fs::read_to_string(d.join(key.replace('/', "__"))) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        },
        None => match keyring::Entry::new("sesame", &key).and_then(|e| e.get_password()) {
            Ok(t) => t,
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(e) => return Err(format!("keychain: {e}")),
        },
    };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| format!("stored {key}: {e}"))
}

pub fn save<T: Serialize>(provider: &str, kind: Kind, value: &T) -> Result<(), String> {
    let key = key(provider, kind);
    let text = serde_json::to_string(value).map_err(|e| e.to_string())?;
    match dir() {
        Some(d) => {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(d.join(key.replace('/', "__")))
                .map_err(|e| e.to_string())?;
            f.write_all(text.as_bytes()).map_err(|e| e.to_string())
        }
        None => keyring::Entry::new("sesame", &key)
            .and_then(|e| e.set_password(&text))
            .map_err(|e| {
                format!(
                    "keychain: {e}. Over SSH the login keychain is locked: run `security unlock-keychain`, or set SESAME_STORE_DIR to keep secrets in 0600 files instead"
                )
            }),
    }
}

pub fn delete(provider: &str, kind: Kind) -> Result<(), String> {
    let key = key(provider, kind);
    match dir() {
        Some(d) => match std::fs::remove_file(d.join(key.replace('/', "__"))) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
            _ => Ok(()),
        },
        None => match keyring::Entry::new("sesame", &key).and_then(|e| e.delete_credential()) {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(format!("keychain: {e}")),
        },
    }
}
