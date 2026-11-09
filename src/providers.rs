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
    /// The endpoint a refresh goes to, when not `token_url` (Figma: `/v1/oauth/refresh`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_url: Option<String>,
    /// Base for relative API paths; `{resource_id}` is the site picked at login.
    pub api_base: String,
    /// Hosts the token may be sent to; `*.example.com` matches subdomains.
    pub hosts: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// What joins the scopes in the authorization URL: a space (OAuth's own), `,` for some.
    #[serde(default = "space")]
    pub scope_separator: String,
    #[serde(default)]
    pub auth_params: BTreeMap<String, String>,
    #[serde(default)]
    pub token_body: TokenBody,
    /// How the client authenticates to the token endpoint.
    #[serde(default)]
    pub client_auth: ClientAuth,
    /// Headers every `sesame api` request carries (Notion: `Notion-Version`);
    /// a `-H` of the same name replaces one.
    #[serde(default)]
    pub api_headers: BTreeMap<String, String>,
    /// Lists the sites a token can reach (Atlassian); the first, or `--site`, is kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources_url: Option<String>,
    /// The token response's field naming the site the login reached (Notion: `workspace_name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_name_field: Option<String>,
    /// Fixed loopback port, for providers that match the callback URL exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_port: Option<u16>,
    /// How many seconds the authorization code lasts, when it is short enough
    /// to tell the person (Figma: 30); login says so where it asks for a paste.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_seconds: Option<u64>,
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
    /// The field of `identity_url`'s answer that names the account (e.g. `login`),
    /// or a JSON pointer into it (`/data/viewer/name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_field: Option<String>,
    /// JSON body for `identity_url`: with one it is a POST (GraphQL), without it a GET.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_body: Option<Value>,
    /// Top-level fields of an API's JSON answer that, present and not empty,
    /// mean the call failed although the status is 2xx (GraphQL's `errors`).
    #[serde(default)]
    pub error_fields: Vec<String>,
    /// How to register this provider's OAuth app, for `sesame setup`.
    #[serde(default)]
    pub setup: Vec<SetupStep>,
}

fn space() -> String {
    " ".into()
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
    /// The endpoint a refresh goes to; without it, the token endpoint.
    #[arg(long)]
    refresh_url: Option<String>,
    /// Base for relative `sesame api` paths; `{resource_id}` is the site picked at login.
    #[arg(long)]
    api_base: Option<String>,
    /// A host the token may be sent to (`*.example.com` matches subdomains); repeatable.
    #[arg(long = "host")]
    hosts: Vec<String>,
    /// A scope login asks for; repeatable. With none, the authorization URL has no `scope`.
    #[arg(long = "scope")]
    scopes: Vec<String>,
    /// What joins the scopes in the authorization URL (default: a space).
    #[arg(long)]
    scope_separator: Option<String>,
    /// `key=value` added to the authorization URL; repeatable.
    #[arg(long = "auth-param")]
    auth_params: Vec<String>,
    /// How the token endpoint takes its body: `form` or `json`.
    #[arg(long)]
    token_body: Option<String>,
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
    /// The token response's field naming the site the login reached (Notion: `workspace_name`).
    #[arg(long)]
    site_name_field: Option<String>,
    /// Fixed loopback port for the callback, for providers that match it exactly.
    #[arg(long)]
    redirect_port: Option<u16>,
    /// How many seconds the authorization code lasts; login tells the person
    /// to paste the address back within them.
    #[arg(long)]
    code_seconds: Option<u64>,
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
    /// The field of the identity answer naming the account, e.g. `login`, or a
    /// JSON pointer into it, e.g. `/data/viewer/name`.
    #[arg(long)]
    identity_field: Option<String>,
    /// JSON body for the identity call, which makes it a POST (GraphQL).
    #[arg(long)]
    identity_body: Option<String>,
    /// A top-level field of the API's JSON answer that, not empty, fails the
    /// call despite a 2xx status (GraphQL: `errors`); repeatable.
    #[arg(long = "error-field")]
    error_fields: Vec<String>,
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
            ("refresh_url", opt(self.refresh_url)),
            ("api_base", opt(self.api_base)),
            ("hosts", list(self.hosts)),
            ("scopes", list(self.scopes)),
            ("scope_separator", opt(self.scope_separator)),
            ("error_fields", list(self.error_fields)),
            ("token_body", opt(self.token_body)),
            ("client_auth", opt(self.client_auth)),
            ("resources_url", opt(self.resources_url)),
            ("site_name_field", opt(self.site_name_field)),
            ("redirect_port", self.redirect_port.map(Value::from)),
            ("code_seconds", self.code_seconds.map(Value::from)),
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
        if let Some(b) = self.identity_body {
            let v = serde_json::from_str(&b)
                .map_err(|e| format!("--identity-body `{b}` is not JSON: {e}"))?;
            put("identity_body", v);
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

/// The loopback redirect URL login listens on, for the port it bound.
pub fn redirect_uri(host: RedirectHost, port: u16) -> String {
    format!("http://{}:{port}/callback", host.as_str())
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
        if let Some(u) = &self.refresh_url {
            check_url("refresh_url", u)?;
        }
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
        if self.identity_body.is_some() && self.identity_url.is_none() {
            return Err("identity_body without identity_url: give the URL it goes to".into());
        }
        if self.scope_separator.is_empty() {
            return Err("scope_separator is empty: give a space or a character such as `,`".into());
        }
        if self.error_fields.iter().any(|f| f.trim().is_empty()) {
            return Err("an error_fields entry is empty".into());
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
        if self.code_seconds == Some(0) {
            return Err("code_seconds 0: leave it out when the provider does not say".into());
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

    /// The redirect URL to register with the provider: fixed when `redirect_port` is.
    pub fn callback(&self) -> String {
        match self.redirect_port {
            Some(port) => redirect_uri(self.redirect_host, port),
            None => format!("http://{}:<any port>/callback", self.redirect_host.as_str()),
        }
    }

    /// Where a refresh goes: `refresh_url`, or else the token endpoint.
    pub fn refresh_endpoint(&self) -> &str {
        self.refresh_url.as_deref().unwrap_or(&self.token_url)
    }

    /// The first of `error_fields` a 2xx JSON answer carries with a value that
    /// is not empty (`null`, `false`, `""`, `[]` and `{}` are empty).
    pub fn error_in<'a>(&'a self, body: &[u8]) -> Option<&'a str> {
        let v: Value = serde_json::from_slice(body).ok()?;
        self.error_fields
            .iter()
            .find(|f| match v.get(f.as_str()) {
                None | Some(Value::Null) | Some(Value::Bool(false)) => false,
                Some(Value::String(s)) => !s.is_empty(),
                Some(Value::Array(a)) => !a.is_empty(),
                Some(Value::Object(o)) => !o.is_empty(),
                Some(_) => true,
            })
            .map(String::as_str)
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
        for name in ["figma", "github", "google", "jira", "linear", "notion"] {
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
            ("refresh_url", json!("nope"), "refresh_url"),
            ("code_seconds", json!(0), "code_seconds 0"),
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
            (
                "identity_body",
                json!({"query": "{ viewer { name } }"}),
                "without identity_url",
            ),
            ("scope_separator", json!(""), "scope_separator is empty"),
            ("error_fields", json!([""]), "error_fields entry is empty"),
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
    fn error_fields_fail_only_when_not_empty() {
        let p = built_in("linear");
        assert_eq!(
            p.error_in(br#"{"errors":[{"message":"x"}]}"#),
            Some("errors")
        );
        for ok in [
            &br#"{"data":{}}"#[..],
            br#"{"data":{},"errors":[]}"#,
            br#"{"errors":null}"#,
            br#"[1]"#,
            b"not json",
        ] {
            assert_eq!(p.error_in(ok), None, "{}", String::from_utf8_lossy(ok));
        }
        assert_eq!(built_in("google").error_in(br#"{"errors":[1]}"#), None);
    }

    #[test]
    fn flags_become_fields() {
        let flags = FieldFlags {
            scopes: vec!["a".into(), "b".into()],
            auth_params: vec!["prompt=consent".into()],
            api_headers: vec!["Notion-Version: 2026-03-11".into()],
            client_auth: Some("basic".into()),
            redirect_port: Some(9000),
            refresh_url: Some("https://x.example/refresh".into()),
            code_seconds: Some(30),
            redirect_host: Some("127.0.0.1".into()),
            device_url: Some("https://x.example/device".into()),
            scope_separator: Some(",".into()),
            error_fields: vec!["errors".into()],
            identity_body: Some(r#"{"query":"{ viewer { name } }"}"#.into()),
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
                "refresh_url": "https://x.example/refresh",
                "code_seconds": 30,
                "redirect_host": "127.0.0.1",
                "device_url": "https://x.example/device",
                "scope_separator": ",",
                "error_fields": ["errors"],
                "identity_body": {"query": "{ viewer { name } }"},
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
