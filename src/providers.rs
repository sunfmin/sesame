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
    /// The APIs reached with this provider's one token, by name (Google:
    /// `gmail`, `calendar`, ...). A service's name is used like a provider's.
    #[serde(default)]
    pub services: BTreeMap<String, Service>,
}

/// One API of a provider: its own base and scopes, the provider's client,
/// hosts and token. `sesame login <service>` adds its scopes to those granted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Service {
    #[serde(default)]
    pub about: String,
    /// Base for relative `sesame api <service>` paths; on one of the provider's hosts.
    pub api_base: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// What `sesame setup` adds for this service (Google: enable its API).
    #[serde(default)]
    pub setup: Vec<SetupStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    /// Base for relative `sesame api` paths; `{resource_id}` is the site picked at login.
    #[arg(long)]
    api_base: Option<String>,
    /// A host the token may be sent to (`*.example.com` matches subdomains); repeatable.
    #[arg(long = "host")]
    hosts: Vec<String>,
    /// A scope login asks for; repeatable. With none, the authorization URL has no `scope`.
    #[arg(long = "scope")]
    scopes: Vec<String>,
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
    /// A service: an API reached with this provider's token, named like a
    /// provider. `name=…,api-base=…,scope=…` (`scope` repeats; `about` too), or
    /// JSON `{"name": …, "api_base": …, "scopes": […], "about": …, "setup": […]}`.
    /// Repeatable; on `set`, the keys given replace only those of that service.
    #[arg(long = "service")]
    services: Vec<String>,
    /// Remove the named service; repeatable.
    #[arg(long = "drop-service")]
    drop_services: Vec<String>,
}

/// The `sesame.db` field holding one service of a provider.
const SERVICE_FIELD: &str = "services.";

/// A `--service` value as its name and the service's fields given.
fn service_flag(spec: &str) -> Result<(String, Fields), String> {
    let mut f = if spec.trim_start().starts_with('{') {
        match serde_json::from_str(spec) {
            Ok(Value::Object(m)) => m,
            Ok(_) => return Err(format!("--service `{spec}` is not a JSON object")),
            Err(e) => return Err(format!("--service `{spec}` is not JSON: {e}")),
        }
    } else {
        let mut m = Fields::new();
        let mut scopes = Vec::new();
        for kv in spec.split(',') {
            let (k, v) = kv
                .split_once('=')
                .ok_or_else(|| format!("--service `{spec}`: `{kv}` is not key=value"))?;
            match k.trim() {
                "scope" => scopes.push(Value::from(v.trim())),
                k @ ("name" | "about") => {
                    m.insert(k.into(), v.trim().into());
                }
                "api-base" => {
                    m.insert("api_base".into(), v.trim().into());
                }
                k => {
                    return Err(format!(
                        "--service `{spec}`: unknown key `{k}`; use name, api-base, scope, about"
                    ));
                }
            }
        }
        if !scopes.is_empty() {
            m.insert("scopes".into(), Value::Array(scopes));
        }
        m
    };
    match f.remove("name") {
        Some(Value::String(n)) => Ok((n, f)),
        _ => Err(format!("--service `{spec}` has no name")),
    }
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
            ("token_body", opt(self.token_body)),
            ("client_auth", opt(self.client_auth)),
            ("resources_url", opt(self.resources_url)),
            ("site_name_field", opt(self.site_name_field)),
            ("redirect_port", self.redirect_port.map(Value::from)),
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
        for spec in &self.services {
            let (name, service) = service_flag(spec)?;
            put(&format!("{SERVICE_FIELD}{name}"), Value::Object(service));
        }
        for name in self.drop_services {
            put(&format!("{SERVICE_FIELD}{name}"), Value::Null);
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
/// fields over it; a `services.<name>` field replaces that one service, or,
/// when null, drops it. The one place a definition is validated: every value
/// written to `sesame.db` passes through here first.
fn effective(name: &str, built_in: Option<&Provider>, user: &Fields) -> Result<Provider, String> {
    let mut fields = built_in.map(as_fields).unwrap_or_default();
    let mut services = match fields.remove("services") {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    };
    for (k, v) in user {
        match k.strip_prefix(SERVICE_FIELD) {
            Some(s) if v.is_null() => {
                services.remove(s);
            }
            Some(s) => {
                services.insert(s.into(), v.clone());
            }
            None => {
                fields.insert(k.clone(), v.clone());
            }
        }
    }
    fields.insert("services".into(), Value::Object(services));
    let p: Provider = serde_json::from_value(Value::Object(fields))
        .map_err(|e| format!("provider `{name}`: {e}"))?;
    p.check().map_err(|e| format!("provider `{name}`: {e}"))?;
    Ok(p)
}

fn as_fields<T: Serialize>(p: &T) -> Fields {
    match serde_json::to_value(p) {
        Ok(Value::Object(m)) => m,
        _ => unreachable!("a Provider or Service serializes to an object"),
    }
}

/// `base`'s value for a stored field name, reaching into `services` for a
/// `services.<name>` field.
fn base_value<'a>(base: &'a Fields, field: &str) -> Option<&'a Value> {
    match field.strip_prefix(SERVICE_FIELD) {
        Some(s) => base.get("services").and_then(|m| m.get(s)),
        None => base.get(field),
    }
}

/// Every provider in force, from the person's stored fields by provider. The
/// one place names are checked across providers: a service's name is used
/// like a provider's, so the two share one namespace.
fn resolve(mut user: BTreeMap<String, Fields>) -> Result<BTreeMap<String, Provider>, String> {
    let mut map = BTreeMap::new();
    for (name, p) in built_in::all() {
        let f = user.remove(&name).unwrap_or_default();
        map.insert(name.clone(), effective(&name, Some(&p), &f)?);
    }
    for (name, f) in user {
        map.insert(name.clone(), effective(&name, None, &f)?);
    }
    let mut owner: BTreeMap<&str, &str> = BTreeMap::new();
    for (provider, p) in &map {
        for service in p.services.keys() {
            if map.contains_key(service) {
                return Err(format!(
                    "service `{service}` of `{provider}`: `{service}` is already a provider, \
                     and a service and a provider cannot share a name"
                ));
            }
            if let Some(other) = owner.insert(service, provider) {
                return Err(format!(
                    "service `{service}`: both `{other}` and `{provider}` have one by that name"
                ));
            }
        }
    }
    Ok(map)
}

pub fn all() -> Result<BTreeMap<String, Provider>, String> {
    resolve(Store::open()?.provider_fields()?)
}

fn unknown(name: &str, all: &BTreeMap<String, Provider>) -> String {
    let names: Vec<&str> = all.keys().map(String::as_str).collect();
    let mut services: Vec<&str> = all
        .values()
        .flat_map(|p| p.services.keys().map(String::as_str))
        .collect();
    services.sort();
    let services = if services.is_empty() {
        String::new()
    } else {
        format!("; or a service: {}", services.join(", "))
    };
    format!(
        "unknown provider `{name}`; choose one of: {}{services}",
        names.join(", ")
    )
}

/// What a name on the command line means: a provider, or one of its services.
/// The token, client and hosts are always the provider's.
pub struct Target {
    pub provider: String,
    pub p: Provider,
    pub service: Option<String>,
}

impl Target {
    pub fn service(&self) -> Option<&Service> {
        self.service.as_ref().and_then(|s| self.p.services.get(s))
    }

    /// Base for relative API paths: the service's, else the provider's.
    pub fn api_base(&self) -> &str {
        self.service().map_or(&self.p.api_base, |s| &s.api_base)
    }
}

pub fn find(name: &str) -> Result<Target, String> {
    let mut all = all()?;
    if let Some(p) = all.remove(name) {
        return Ok(Target {
            provider: name.into(),
            p,
            service: None,
        });
    }
    let provider = all
        .iter()
        .find(|(_, p)| p.services.contains_key(name))
        .map(|(n, _)| n.clone());
    match provider {
        Some(provider) => Ok(Target {
            p: all.remove(&provider).unwrap_or_else(|| unreachable!()),
            provider,
            service: Some(name.into()),
        }),
        None => Err(unknown(name, &all)),
    }
}

fn check_name(what: &str, name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!(
            "{what} name `{name}`: use letters, digits, `-` and `_`"
        ));
    }
    Ok(())
}

/// `sesame provider add`: a new provider, all of whose fields are the person's.
pub fn add(name: &str, mut fields: Fields) -> Result<(), String> {
    check_name("provider", name)?;
    if built_in::all().contains_key(name) {
        return Err(format!(
            "`{name}` is a built-in provider; change its fields with `sesame provider set {name}`"
        ));
    }
    // A new provider has no service to drop.
    fields.retain(|_, v| !v.is_null());
    let store = Store::open()?;
    store.locked(|s| {
        let mut all = s.provider_fields()?;
        if all.contains_key(name) {
            return Err(format!(
                "provider `{name}` exists; change it with `sesame provider set {name}`"
            ));
        }
        all.insert(name.into(), fields.clone());
        resolve(all)?;
        s.save_provider_fields(name, &fields)
    })
}

/// `sesame provider set`: changes the given fields; a service's given keys
/// replace only those of that service. For a built-in provider only the
/// fields that differ from the built-in definition are stored.
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
        let services = effective(name, built_in.as_ref(), &user)
            .map(|p| p.services)
            .unwrap_or_default();
        for (k, v) in fields {
            let v = match (k.strip_prefix(SERVICE_FIELD), v) {
                (Some(svc), Value::Null) if !services.contains_key(svc) => {
                    return Err(format!("provider `{name}` has no service `{svc}`"));
                }
                (Some(svc), Value::Object(given)) => {
                    let mut m = services.get(svc).map(as_fields).unwrap_or_default();
                    m.extend(given);
                    Value::Object(m)
                }
                (_, v) => v,
            };
            user.insert(k, v);
        }
        let base = built_in.as_ref().map(as_fields).unwrap_or_default();
        user.retain(|k, v| match base_value(&base, k) {
            // Dropping a service only means something for one the built-in has.
            b if v.is_null() => b.is_some(),
            b => b != Some(v),
        });
        all.insert(name.into(), user.clone());
        resolve(all)?;
        s.save_provider_fields(name, &user)
    })
}

/// `sesame provider show`: the definition in force, each field with where it
/// comes from: `built-in`, `user`, or `default` (unset, so the default holds).
/// Each service is its own field, `services.<name>`, as `sesame.db` keeps it.
pub fn show(name: &str) -> Result<Value, String> {
    let built_in = built_in::all().remove(name);
    let user = Store::open()?
        .provider_fields()?
        .remove(name)
        .unwrap_or_default();
    if built_in.is_none() && user.is_empty() {
        return Err(unknown(name, &all()?));
    }
    let p = effective(name, built_in.as_ref(), &user)?;
    let from = |k: &str| {
        if user.contains_key(k) {
            "user"
        } else if built_in.is_some() {
            "built-in"
        } else {
            "default"
        }
    };
    let mut fields = Map::new();
    for (k, value) in as_fields(&p) {
        if k == "services" {
            continue;
        }
        let entry = serde_json::json!({ "value": value, "from": from(&k) });
        fields.insert(k, entry);
    }
    for (svc, s) in &p.services {
        let k = format!("{SERVICE_FIELD}{svc}");
        let entry = serde_json::json!({ "value": s, "from": from(&k) });
        fields.insert(k, entry);
    }
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
        (false, false) => Err(unknown(name, &all()?)),
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

fn check_steps(steps: &[SetupStep]) -> Result<(), String> {
    for s in steps {
        if s.title.trim().is_empty() {
            return Err("a setup step has no title".into());
        }
        if let Some(page) = &s.page {
            check_url("setup page", page)?;
        }
    }
    Ok(())
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
        check_steps(&self.setup)?;
        for (n, s) in &self.services {
            check_name("service", n)?;
            let base = s.api_base.replace("{resource_id}", "x");
            check_url(&format!("service `{n}` api_base"), &base)?;
            let host = url::Url::parse(&base)
                .ok()
                .and_then(|u| u.host_str().map(String::from))
                .unwrap_or_default();
            if !self.allows_host(&host) {
                return Err(format!(
                    "service `{n}` api_base `{}`: the token goes only to hosts, and {host} is not one",
                    s.api_base
                ));
            }
            check_steps(&s.setup).map_err(|e| format!("service `{n}`: {e}"))?;
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
        for name in ["github", "google", "jira", "notion"] {
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
