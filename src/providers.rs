//! Providers: the built-in definitions in code (`built_in`), and the person's
//! own in `sesame.db`, kept as fields. The definition in force for a name is
//! the built-in one with the stored fields over it (`effective`), so a field
//! nobody changed follows each new version.
mod built_in;

use crate::store::Store;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// The authorization URL's parameter that carries the scopes (Slack: `user_scope`).
    #[serde(default = "default_scope_param")]
    pub scope_param: String,
    #[serde(default)]
    pub auth_params: BTreeMap<String, String>,
    /// Send PKCE (`code_challenge`, `code_verifier`) with the authorization code.
    #[serde(default = "yes")]
    pub pkce: bool,
    #[serde(default)]
    pub token_body: TokenBody,
    /// How the client authenticates to the token endpoint.
    #[serde(default)]
    pub client_auth: ClientAuth,
    /// Headers every `sesame api` request carries (Notion: `Notion-Version`);
    /// a `-H` of the same name replaces one.
    #[serde(default)]
    pub api_headers: BTreeMap<String, String>,
    /// JSON pointer to the object in the token response that holds
    /// `access_token` (Slack: `/authed_user`); empty for the top level. A
    /// response without `access_token` there (a refresh) is read at the top level.
    #[serde(default)]
    pub token_path: String,
    /// Lists the sites a token can reach (Atlassian); the first, or `--site`, is kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources_url: Option<String>,
    /// The token response's field naming the site the login reached (Notion:
    /// `workspace_name`); a JSON pointer when it starts with `/` (Slack: `/team/name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_name_field: Option<String>,
    /// How the authorization code comes back to sesame.
    #[serde(default)]
    pub redirect: Redirect,
    /// Fixed callback port, for providers that match the callback URL exactly;
    /// required for `https-paste`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_port: Option<u16>,
    /// A top-level field of a JSON response that is `false` when the call
    /// failed, even with HTTP 200 (Slack: `ok`); `api` then exits non-zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok_field: Option<String>,
    /// The loopback redirect's host: `localhost` or `127.0.0.1`.
    #[serde(default)]
    pub redirect_host: RedirectHost,
    /// Device authorization endpoint (RFC 8628): when set, login uses the
    /// device flow, and `--browser` the loopback redirect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_url: Option<String>,
    /// A JSON endpoint on one of `hosts` naming who signed in, read after login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_url: Option<String>,
    /// The field of `identity_url`'s answer that names the account (e.g. `login`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_field: Option<String>,
    /// How to register this provider's OAuth app, for `sesame setup`.
    #[serde(default)]
    pub setup: Vec<SetupStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupStep {
    pub title: String,
    /// The page to open for this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    /// What to click, fill in and pick; `{callback}` and `{scopes}` are filled in.
    #[serde(default)]
    pub details: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TokenBody {
    #[default]
    Form,
    Json,
}

/// How the authorization code gets back from the browser.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Redirect {
    /// `http://localhost:<port>/callback`, which login listens on.
    #[default]
    Loopback,
    /// `https://localhost:<redirect_port>/callback`, for providers that accept
    /// only https callbacks: nothing listens, the browser fails to open it, and
    /// the person pastes the address it ended on into the terminal.
    HttpsPaste,
}

fn default_scope_param() -> String {
    "scope".into()
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub enum RedirectHost {
    #[default]
    #[serde(rename = "localhost")]
    Localhost,
    #[serde(rename = "127.0.0.1")]
    Loopback,
}

impl RedirectHost {
    pub fn as_str(self) -> &'static str {
        match self {
            RedirectHost::Localhost => "localhost",
            RedirectHost::Loopback => "127.0.0.1",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ClientAuth {
    /// `client_id` and `client_secret` in the body.
    #[default]
    Body,
    /// HTTP Basic `client_id:client_secret`, nothing in the body.
    Basic,
}

/// Fields of a provider definition, by name, as `sesame.db` stores them.
pub type Fields = Map<String, Value>;

/// The definition's fields as flags, shared by `sesame provider add` and `set`.
#[derive(clap::Args, Debug, Default)]
pub struct FieldFlags {
    /// One line on what the provider is, for `sesame providers`.
    #[arg(long)]
    about: Option<String>,
    /// The OAuth authorization endpoint.
    #[arg(long)]
    auth_url: Option<String>,
    /// The OAuth token endpoint.
    #[arg(long)]
    token_url: Option<String>,
    /// Base for relative `sesame api` paths; `{resource_id}` is the site picked at login.
    #[arg(long)]
    api_base: Option<String>,
    /// A host the token may be sent to (`*.example.com` matches subdomains); repeatable.
    #[arg(long = "host")]
    hosts: Vec<String>,
    /// A scope login asks for; repeatable. With none, the authorization URL has no `scope`.
    #[arg(long = "scope")]
    scopes: Vec<String>,
    /// The authorization URL's parameter for the scopes (default `scope`; Slack `user_scope`).
    #[arg(long)]
    scope_param: Option<String>,
    /// `key=value` added to the authorization URL; repeatable.
    #[arg(long = "auth-param")]
    auth_params: Vec<String>,
    /// How the token endpoint takes its body: `form` or `json`.
    #[arg(long)]
    token_body: Option<String>,
    /// Whether login sends PKCE: `true` (default) or `false`.
    #[arg(long)]
    pkce: Option<bool>,
    /// JSON pointer to the object holding `access_token` in the token response
    /// (Slack `/authed_user`); empty for the top level.
    #[arg(long)]
    token_path: Option<String>,
    /// How the code comes back: `loopback` (default, sesame listens on
    /// http://localhost) or `https-paste` (https://localhost:<redirect-port>, pasted back).
    #[arg(long)]
    redirect: Option<String>,
    /// A top-level JSON response field that is `false` on failure even with HTTP 200 (Slack `ok`).
    #[arg(long)]
    ok_field: Option<String>,
    /// How the client authenticates to the token endpoint: `body` or `basic` (HTTP Basic).
    #[arg(long)]
    client_auth: Option<String>,
    /// Header `Name: value` every `sesame api` request carries; repeatable.
    /// A `-H` of the same name replaces it.
    #[arg(long = "api-header")]
    api_headers: Vec<String>,
    /// URL listing the sites a token reaches (Atlassian).
    #[arg(long)]
    resources_url: Option<String>,
    /// The token response's field naming the site the login reached (Notion: `workspace_name`);
    /// a JSON pointer when it starts with `/` (Slack: `/team/name`).
    #[arg(long)]
    site_name_field: Option<String>,
    /// Fixed loopback port for the callback, for providers that match it exactly.
    #[arg(long)]
    redirect_port: Option<u16>,
    /// The loopback redirect's host: `localhost` (the default) or `127.0.0.1`.
    #[arg(long)]
    redirect_host: Option<String>,
    /// Device authorization endpoint (RFC 8628); login then uses the device
    /// flow by default, and `--browser` the loopback redirect.
    #[arg(long)]
    device_url: Option<String>,
    /// JSON endpoint naming who signed in, read after login (on one of the hosts).
    #[arg(long)]
    identity_url: Option<String>,
    /// The field of the identity answer naming the account, e.g. `login`.
    #[arg(long)]
    identity_field: Option<String>,
    /// A step for `sesame setup`, as JSON: `{"title": …, "page": …, "details": …}`;
    /// repeatable, in order. `{callback}` and `{scopes}` in details are filled in.
    #[arg(long = "setup-step")]
    setup: Vec<String>,
}

impl FieldFlags {
    /// The fields given; a repeatable flag replaces its whole list. Only the
    /// shape of each flag is read here: `effective` validates the values.
    pub fn fields(self) -> Result<Fields, String> {
        let mut f = Fields::new();
        let mut put = |k: &str, v: Value| {
            f.insert(k.into(), v);
        };
        let opt = |v: Option<String>| v.map(Value::String);
        let list = |v: Vec<String>| (!v.is_empty()).then(|| Value::from(v));
        for (k, v) in [
            ("about", opt(self.about)),
            ("auth_url", opt(self.auth_url)),
            ("token_url", opt(self.token_url)),
            ("api_base", opt(self.api_base)),
            ("hosts", list(self.hosts)),
            ("scopes", list(self.scopes)),
            ("scope_param", opt(self.scope_param)),
            ("pkce", self.pkce.map(Value::from)),
            ("token_body", opt(self.token_body)),
            ("token_path", opt(self.token_path)),
            ("client_auth", opt(self.client_auth)),
            ("resources_url", opt(self.resources_url)),
            ("site_name_field", opt(self.site_name_field)),
            ("redirect", opt(self.redirect)),
            ("redirect_port", self.redirect_port.map(Value::from)),
            ("ok_field", opt(self.ok_field)),
            ("redirect_host", opt(self.redirect_host)),
            ("device_url", opt(self.device_url)),
            ("identity_url", opt(self.identity_url)),
            ("identity_field", opt(self.identity_field)),
        ] {
            if let Some(v) = v {
                put(k, v);
            }
        }
        if !self.auth_params.is_empty() {
            let mut m = Map::new();
            for kv in self.auth_params {
                let (k, v) = kv
                    .split_once('=')
                    .ok_or_else(|| format!("--auth-param `{kv}` is not key=value"))?;
                m.insert(k.into(), v.into());
            }
            put("auth_params", Value::Object(m));
        }
        if !self.api_headers.is_empty() {
            let mut m = Map::new();
            for h in self.api_headers {
                let (k, v) = h
                    .split_once(':')
                    .ok_or_else(|| format!("--api-header `{h}` is not `Name: value`"))?;
                m.insert(k.trim().into(), v.trim().into());
            }
            put("api_headers", Value::Object(m));
        }
        if !self.setup.is_empty() {
            let steps = self
                .setup
                .iter()
                .map(|s| {
                    serde_json::from_str(s)
                        .map_err(|e| format!("--setup-step `{s}` is not JSON: {e}"))
                })
                .collect::<Result<Vec<Value>, String>>()?;
            put("setup", Value::Array(steps));
        }
        Ok(f)
    }
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

/// The definition in force: `built_in` (if the name has one) with `user`'s
/// fields over it. The one place a definition is validated: every value
/// written to `sesame.db` passes through here first.
fn effective(name: &str, built_in: Option<&Provider>, user: &Fields) -> Result<Provider, String> {
    let mut fields = match built_in {
        Some(p) => as_fields(p),
        None => Fields::new(),
    };
    fields.extend(user.clone());
    let p: Provider = serde_json::from_value(Value::Object(fields))
        .map_err(|e| format!("provider `{name}`: {e}"))?;
    p.check().map_err(|e| format!("provider `{name}`: {e}"))?;
    Ok(p)
}

fn as_fields(p: &Provider) -> Fields {
    match serde_json::to_value(p) {
        Ok(Value::Object(m)) => m,
        _ => unreachable!("a Provider serializes to an object"),
    }
}

pub fn all() -> Result<BTreeMap<String, Provider>, String> {
    let mut user = Store::open()?.provider_fields()?;
    let mut map = BTreeMap::new();
    for (name, p) in built_in::all() {
        let f = user.remove(&name).unwrap_or_default();
        map.insert(name.clone(), effective(&name, Some(&p), &f)?);
    }
    for (name, f) in user {
        map.insert(name.clone(), effective(&name, None, &f)?);
    }
    Ok(map)
}

fn unknown(name: &str, names: impl Iterator<Item = String>) -> String {
    let names: Vec<String> = names.collect();
    format!(
        "unknown provider `{name}`; choose one of: {}",
        names.join(", ")
    )
}

pub fn get(name: &str) -> Result<Provider, String> {
    let mut all = all()?;
    all.remove(name)
        .ok_or_else(|| unknown(name, all.into_keys()))
}

/// `sesame provider add`: a new provider, all of whose fields are the person's.
pub fn add(name: &str, fields: Fields) -> Result<(), String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!(
            "provider name `{name}`: use letters, digits, `-` and `_`"
        ));
    }
    if built_in::all().contains_key(name) {
        return Err(format!(
            "`{name}` is a built-in provider; change its fields with `sesame provider set {name}`"
        ));
    }
    let store = Store::open()?;
    store.locked(|s| {
        if s.provider_fields()?.contains_key(name) {
            return Err(format!(
                "provider `{name}` exists; change it with `sesame provider set {name}`"
            ));
        }
        effective(name, None, &fields)?;
        s.save_provider_fields(name, &fields)
    })
}

/// `sesame provider set`: changes the given fields. For a built-in provider
/// only the fields that differ from the built-in definition are stored.
pub fn set(name: &str, fields: Fields) -> Result<(), String> {
    let built_in = built_in::all().remove(name);
    let store = Store::open()?;
    store.locked(|s| {
        let mut all = s.provider_fields()?;
        let mut user = match (all.remove(name), &built_in) {
            (Some(f), _) => f,
            (None, Some(_)) => Fields::new(),
            (None, None) => {
                return Err(format!(
                    "unknown provider `{name}`; add it with `sesame provider add {name}`"
                ));
            }
        };
        user.extend(fields);
        if let Some(p) = &built_in {
            let base = as_fields(p);
            user.retain(|k, v| base.get(k) != Some(v));
        }
        effective(name, built_in.as_ref(), &user)?;
        s.save_provider_fields(name, &user)
    })
}

/// `sesame provider show`: the definition in force, each field with where it
/// comes from: `built-in`, `user`, or `default` (unset, so the default holds).
pub fn show(name: &str) -> Result<Value, String> {
    let built_in = built_in::all().remove(name);
    let user = Store::open()?
        .provider_fields()?
        .remove(name)
        .unwrap_or_default();
    if built_in.is_none() && user.is_empty() {
        return Err(unknown(name, all()?.into_keys()));
    }
    let p = effective(name, built_in.as_ref(), &user)?;
    let fields = as_fields(&p)
        .into_iter()
        .map(|(k, value)| {
            let from = if user.contains_key(&k) {
                "user"
            } else if built_in.is_some() {
                "built-in"
            } else {
                "default"
            };
            (k, serde_json::json!({ "value": value, "from": from }))
        })
        .collect();
    Ok(Value::Object(fields))
}

/// `sesame provider rm`: forgets the person's fields. A provider they added is
/// gone; a built-in one is back to its built-in definition. Returns what
/// happened, for the person.
pub fn remove(name: &str) -> Result<String, String> {
    let is_built_in = built_in::all().contains_key(name);
    let store = Store::open()?;
    let had = store.locked(|s| {
        let had = s.provider_fields()?.contains_key(name);
        s.delete_provider_fields(name)?;
        Ok(had)
    })?;
    match (is_built_in, had) {
        (true, true) => Ok(format!("`{name}` is back to its built-in definition.")),
        (true, false) => Ok(format!("`{name}` already has its built-in definition.")),
        (false, true) => Ok(format!("Removed the provider `{name}`.")),
        (false, false) => Err(unknown(name, all()?.into_keys())),
    }
}

fn check_url(field: &str, u: &str) -> Result<(), String> {
    let parsed = url::Url::parse(u).map_err(|e| format!("{field} `{u}`: {e}"))?;
    match parsed.scheme() {
        "https" | "http" => Ok(()),
        s => Err(format!("{field} `{u}`: scheme {s} is not http or https")),
    }
}

impl Provider {
    /// What the types do not say: URLs that parse, at least one host, a usable port.
    fn check(&self) -> Result<(), String> {
        check_url("auth_url", &self.auth_url)?;
        check_url("token_url", &self.token_url)?;
        check_url("api_base", &self.api_base.replace("{resource_id}", "x"))?;
        if let Some(u) = &self.resources_url {
            check_url("resources_url", u)?;
        }
        if self.hosts.is_empty() {
            return Err("hosts is empty: give at least one --host the token may go to".into());
        }
        if let Some(h) = self.hosts.iter().find(|h| {
            let bare = h.strip_prefix("*.").unwrap_or(h);
            bare.is_empty() || bare.contains(['/', ':', '*', ' '])
        }) {
            return Err(format!("host `{h}`: a host name, or `*.` and a domain"));
        }
        if let Some(u) = &self.device_url {
            check_url("device_url", u)?;
        }
        match (&self.identity_url, &self.identity_field) {
            (None, None) => {}
            (Some(u), Some(f)) => {
                check_url("identity_url", u)?;
                let host = url::Url::parse(u)
                    .ok()
                    .and_then(|u| u.host_str().map(String::from))
                    .unwrap_or_default();
                if !self.allows_host(&host) {
                    return Err(format!(
                        "identity_url `{u}`: the token goes only to hosts, and {host} is not one"
                    ));
                }
                if f.trim().is_empty() {
                    return Err("identity_field is empty".into());
                }
            }
            _ => return Err("identity_url and identity_field go together: give both".into()),
        }
        for (k, v) in &self.api_headers {
            reqwest::header::HeaderName::from_bytes(k.as_bytes())
                .map_err(|_| format!("api header `{k}`: not a header name"))?;
            reqwest::header::HeaderValue::from_str(v)
                .map_err(|_| format!("api header `{k}`: value `{v}` is not a header value"))?;
            if k.eq_ignore_ascii_case("authorization") {
                return Err("api header `Authorization`: sesame sets it from the token".into());
            }
        }
        if self
            .site_name_field
            .as_deref()
            .is_some_and(|f| f.trim().is_empty())
        {
            return Err("site_name_field is empty: leave it out, or name a field".into());
        }
        if self.redirect_port == Some(0) {
            return Err("redirect_port 0: leave it out for any free port".into());
        }
        if self.redirect == Redirect::HttpsPaste && self.redirect_port.is_none() {
            return Err(
                "redirect https-paste needs a redirect_port: the callback URL registered with the provider"
                    .into(),
            );
        }
        if self.scope_param.is_empty() || self.scope_param.contains([' ', '&', '=']) {
            return Err(format!(
                "scope_param `{}`: a URL parameter name",
                self.scope_param
            ));
        }
        if !self.token_path.is_empty() && !self.token_path.starts_with('/') {
            return Err(format!(
                "token_path `{}`: a JSON pointer, e.g. `/authed_user`; empty for the top level",
                self.token_path
            ));
        }
        if self.ok_field.as_deref() == Some("") {
            return Err("ok_field is empty: leave it out, or name a field".into());
        }
        for s in &self.setup {
            if s.title.trim().is_empty() {
                return Err("a setup step has no title".into());
            }
            if let Some(page) = &s.page {
                check_url("setup page", page)?;
            }
        }
        Ok(())
    }

    /// The redirect URL login sends, for the port it uses.
    pub fn redirect_uri(&self, port: u16) -> String {
        let scheme = match self.redirect {
            Redirect::Loopback => "http",
            Redirect::HttpsPaste => "https",
        };
        format!("{scheme}://{}:{port}/callback", self.redirect_host.as_str())
    }

    /// The redirect URL to register with the provider: fixed when `redirect_port` is.
    pub fn callback(&self) -> String {
        match self.redirect_port {
            Some(port) => self.redirect_uri(port),
            None => self.redirect_uri(0).replace(":0/", ":<any port>/"),
        }
    }

    pub fn allows_host(&self, host: &str) -> bool {
        self.hosts.iter().any(|h| match h.strip_prefix("*.") {
            Some(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
            None => host == h,
        })
    }
}

/// The built-in definitions, for other modules' tests.
#[cfg(test)]
pub fn built_in(name: &str) -> Provider {
    built_in::all().remove(name).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fields(v: Value) -> Fields {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn built_ins_are_valid() {
        let all = built_in::all();
        for name in ["github", "google", "jira", "notion", "slack"] {
            assert!(all.contains_key(name), "{name}");
        }
        for (name, p) in &all {
            effective(name, Some(p), &Fields::new()).unwrap();
        }
    }

    #[test]
    fn host_patterns() {
        let p = built_in("google");
        assert!(p.allows_host("docs.googleapis.com"));
        assert!(!p.allows_host("googleapis.com.evil.com"));
        assert!(!p.allows_host("evil.com"));
    }

    #[test]
    fn user_fields_override_only_themselves() {
        let g = built_in("google");
        let p = effective("google", Some(&g), &fields(json!({"scopes": ["email"]}))).unwrap();
        assert_eq!(p.scopes, ["email"]);
        assert_eq!(p.auth_url, g.auth_url);
        assert_eq!(p.setup.len(), g.setup.len());
    }

    #[test]
    fn invalid_fields_are_refused() {
        let ok = json!({
            "auth_url": "https://a.example/auth",
            "token_url": "https://a.example/token",
            "api_base": "https://api.a.example/{resource_id}",
            "hosts": ["api.a.example"],
        });
        effective("a", None, &fields(ok.clone())).unwrap();
        for (k, v, want) in [
            ("auth_url", json!("not a url"), "auth_url"),
            ("token_url", json!("ftp://a.example"), "scheme ftp"),
            ("hosts", json!([]), "hosts is empty"),
            ("hosts", json!(["https://x"]), "host `https://x`"),
            ("token_body", json!("xml"), "unknown variant `xml`"),
            ("client_auth", json!("digest"), "unknown variant `digest`"),
            ("api_headers", json!({"bad name": "x"}), "not a header name"),
            ("api_headers", json!({"X-A": "a\nb"}), "not a header value"),
            (
                "api_headers",
                json!({"authorization": "x"}),
                "sets it from the token",
            ),
            ("site_name_field", json!(""), "site_name_field is empty"),
            ("redirect_port", json!(0), "redirect_port 0"),
            ("redirect", json!("https-paste"), "needs a redirect_port"),
            ("redirect", json!("carrier-pigeon"), "unknown variant"),
            ("scope_param", json!(""), "scope_param"),
            ("token_path", json!("authed_user"), "JSON pointer"),
            ("ok_field", json!(""), "ok_field is empty"),
            ("pkce", json!("maybe"), "expected a boolean"),
            (
                "redirect_host",
                json!("example.com"),
                "unknown variant `example.com`",
            ),
            ("device_url", json!("nope"), "device_url"),
            (
                "identity_url",
                json!("https://api.a.example/me"),
                "go together",
            ),
            ("identity_field", json!("login"), "go together"),
            ("setup", json!([{"title": ""}]), "no title"),
            ("nope", json!(1), "unknown field `nope`"),
        ] {
            let mut f = fields(ok.clone());
            f.insert(k.into(), v);
            let e = effective("a", None, &f).unwrap_err();
            assert!(e.contains(want), "{k}: {e}");
        }
        let mut f = fields(ok.clone());
        f.insert("identity_url".into(), json!("https://evil.example/me"));
        f.insert("identity_field".into(), json!("login"));
        let e = effective("a", None, &f).unwrap_err();
        assert!(e.contains("evil.example is not one"), "{e}");
        let mut f = fields(ok);
        f.remove("token_url");
        let e = effective("a", None, &f).unwrap_err();
        assert!(e.contains("missing field `token_url`"), "{e}");
    }

    #[test]
    fn flags_become_fields() {
        let flags = FieldFlags {
            scopes: vec!["a".into(), "b".into()],
            auth_params: vec!["prompt=consent".into()],
            api_headers: vec!["Notion-Version: 2026-03-11".into()],
            client_auth: Some("basic".into()),
            redirect_port: Some(9000),
            redirect: Some("https-paste".into()),
            pkce: Some(false),
            token_path: Some("/authed_user".into()),
            redirect_host: Some("127.0.0.1".into()),
            device_url: Some("https://x.example/device".into()),
            setup: vec![r#"{"title":"T","page":"https://x.example"}"#.into()],
            ..Default::default()
        };
        assert_eq!(
            Value::Object(flags.fields().unwrap()),
            json!({
                "scopes": ["a", "b"],
                "auth_params": {"prompt": "consent"},
                "api_headers": {"Notion-Version": "2026-03-11"},
                "client_auth": "basic",
                "redirect_port": 9000,
                "redirect": "https-paste",
                "pkce": false,
                "token_path": "/authed_user",
                "redirect_host": "127.0.0.1",
                "device_url": "https://x.example/device",
                "setup": [{"title": "T", "page": "https://x.example"}],
            })
        );
        let bad = FieldFlags {
            auth_params: vec!["novalue".into()],
            ..Default::default()
        };
        assert!(bad.fields().unwrap_err().contains("key=value"));
        let bad = FieldFlags {
            api_headers: vec!["novalue".into()],
            ..Default::default()
        };
        assert!(bad.fields().unwrap_err().contains("Name: value"));
    }
}
