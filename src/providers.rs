use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

const BUILT_IN: &str = include_str!("providers.toml");

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    #[serde(default)]
    pub about: String,
    pub auth_url: String,
    pub token_url: String,
    /// Base for relative API paths; `{resource_id}` is the site picked at login.
    pub api_base: String,
    /// Hosts the token may be sent to; `*.example.com` matches subdomains.
    pub hosts: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub auth_params: BTreeMap<String, String>,
    #[serde(default)]
    pub token_body: TokenBody,
    /// Lists the sites a token can reach (Atlassian); the first, or `--site`, is kept.
    pub resources_url: Option<String>,
    /// Fixed loopback port, for providers that match the callback URL exactly.
    pub redirect_port: Option<u16>,
    /// How to register this provider's OAuth app, for `sesame setup`.
    #[serde(default)]
    pub setup: Vec<SetupStep>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupStep {
    pub title: String,
    /// The page to open for this step.
    pub page: Option<String>,
    /// What to click, fill in and pick; `{callback}` and `{scopes}` are filled in.
    #[serde(default)]
    pub details: String,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TokenBody {
    #[default]
    Form,
    Json,
}

pub fn config_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("SESAME_CONFIG_DIR") {
        return PathBuf::from(d);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join(".config").join("sesame")
}

pub fn all() -> Result<BTreeMap<String, Provider>, String> {
    let mut map: BTreeMap<String, Provider> =
        toml::from_str(BUILT_IN).map_err(|e| format!("built-in providers: {e}"))?;
    let user = config_dir().join("providers.toml");
    if let Ok(text) = std::fs::read_to_string(&user) {
        let extra: BTreeMap<String, Provider> =
            toml::from_str(&text).map_err(|e| format!("{}: {e}", user.display()))?;
        map.extend(extra);
    }
    Ok(map)
}

pub fn get(name: &str) -> Result<Provider, String> {
    let mut all = all()?;
    all.remove(name).ok_or_else(|| {
        let names: Vec<&str> = all.keys().map(String::as_str).collect();
        format!(
            "unknown provider `{name}`; choose one of: {}",
            names.join(", ")
        )
    })
}

/// The loopback redirect URL login listens on, for the port it bound.
pub fn redirect_uri(port: u16) -> String {
    format!("http://localhost:{port}/callback")
}

impl Provider {
    /// The redirect URL to register with the provider: fixed when `redirect_port` is.
    pub fn callback(&self) -> String {
        match self.redirect_port {
            Some(port) => redirect_uri(port),
            None => "http://localhost:<any port>/callback".into(),
        }
    }

    pub fn allows_host(&self, host: &str) -> bool {
        self.hosts.iter().any(|h| match h.strip_prefix("*.") {
            Some(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
            None => host == h,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_ins_parse() {
        let map: BTreeMap<String, Provider> = toml::from_str(BUILT_IN).unwrap();
        assert!(map.contains_key("google") && map.contains_key("jira"));
    }

    #[test]
    fn host_patterns() {
        let p = &toml::from_str::<BTreeMap<String, Provider>>(BUILT_IN).unwrap()["google"];
        assert!(p.allows_host("docs.googleapis.com"));
        assert!(!p.allows_host("googleapis.com.evil.com"));
        assert!(!p.allows_host("evil.com"));
    }
}
