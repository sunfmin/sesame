//! Providers: the built-in definitions in code (`built_in`), and the person's
//! own in `sesame.db`, kept as fields. The definition in force for a name is
//! the built-in one with the stored fields over it (`effective`), so a field
//! nobody changed follows each new version.
mod built_in;
pub mod fields;

use crate::store::Store;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub use fields::FieldFlags;
use fields::{FIELDS, SERVICE_FIELD, check_url};

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
    /// The authorization URL's parameter that carries the scopes (Slack: `user_scope`).
    #[serde(default = "default_scope_param")]
    pub scope_param: String,
    /// What joins the scopes in the authorization URL: a space (OAuth's own), `,` for some.
    #[serde(default = "space")]
    pub scope_separator: String,
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
    /// The APIs reached with this provider's one token, by name (Google:
    /// `gmail`, `calendar`, ...). A service's name is used like a provider's.
    #[serde(default)]
    pub services: BTreeMap<String, Service>,
    /// The documentation pages the definition was read from.
    #[serde(default)]
    pub sources: Vec<String>,
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

fn space() -> String {
    " ".into()
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
/// written to `sesame.db` passes through here first, each field by its kind
/// in the field table, then what the fields say together.
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
    let err = |e: String| format!("provider `{name}`: {e}");
    fields::check(&fields).map_err(err)?;
    let p: Provider =
        serde_json::from_value(Value::Object(fields)).map_err(|e| err(e.to_string()))?;
    p.check().map_err(err)?;
    Ok(p)
}

fn as_fields<T: Serialize>(p: &T) -> Fields {
    match serde_json::to_value(p) {
        Ok(Value::Object(m)) => m,
        _ => unreachable!("a Provider or Service serializes to an object"),
    }
}

/// The value each field has when nobody gives it, from the serde defaults;
/// a field with none (an `Option` left out) is absent.
fn defaults() -> Fields {
    let mut required = Fields::new();
    for f in FIELDS.iter().filter(|f| f.required) {
        let v = match f.kind {
            fields::Kind::Hosts => serde_json::json!(["example.com"]),
            _ => Value::from("https://example.com"),
        };
        required.insert(f.name.into(), v);
    }
    let p: Provider = serde_json::from_value(Value::Object(required))
        .expect("the required fields alone make a definition");
    let mut d = as_fields(&p);
    d.retain(|k, _| !fields::field(k).is_some_and(|f| f.required));
    d
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
    resolve(stored(&Store::open()?)?)
}

/// Keeps of `user` only the fields that change `built_in`: a value equal to
/// the built-in one is no change of the person's. Dropping a service only
/// means something for one the built-in has.
fn own_changes(built_in: &Provider, user: &mut Fields) {
    let base = as_fields(built_in);
    user.retain(|k, v| match base_value(&base, k) {
        b if v.is_null() => b.is_some(),
        b => b != Some(v),
    });
}

/// The person's stored fields by provider, each built-in's reduced to its
/// own changes: a provider they added before it became built-in keeps only
/// the fields that differ from the built-in definition.
fn stored(s: &Store) -> Result<BTreeMap<String, Fields>, String> {
    let mut all = s.provider_fields()?;
    for (name, b) in built_in::all() {
        if let Some(user) = all.get_mut(&name) {
            own_changes(&b, user);
        }
    }
    Ok(all)
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

/// Refuses `name`'s fixed callback port when another provider has it: two
/// logins cannot listen on one port, and each registers it as its own.
fn port_is_free(all: &BTreeMap<String, Provider>, name: &str) -> Result<(), String> {
    let Some(port) = all.get(name).and_then(|p| p.redirect_port) else {
        return Ok(());
    };
    match all
        .iter()
        .find(|(o, p)| o.as_str() != name && p.redirect_port == Some(port))
    {
        Some((other, _)) => Err(format!(
            "provider `{name}`: redirect_port {port} is taken by `{other}`; pick another port"
        )),
        None => Ok(()),
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
        let mut all = stored(s)?;
        if all.contains_key(name) {
            return Err(format!(
                "provider `{name}` exists; change it with `sesame provider set {name}`"
            ));
        }
        all.insert(name.into(), fields.clone());
        port_is_free(&resolve(all)?, name)?;
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
        let mut all = stored(s)?;
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
        if let Some(b) = &built_in {
            own_changes(b, &mut user);
        }
        all.insert(name.into(), user.clone());
        port_is_free(&resolve(all)?, name)?;
        s.save_provider_fields(name, &user)
    })
}

/// The built-in definition of `name`, if any, its stored fields, and the
/// definition in force; an error for a name that is neither.
fn layers(name: &str) -> Result<(Option<Provider>, Fields, Provider), String> {
    let built_in = built_in::all().remove(name);
    let user = stored(&Store::open()?)?.remove(name).unwrap_or_default();
    if built_in.is_none() && user.is_empty() {
        return Err(unknown(name, &all()?));
    }
    let p = effective(name, built_in.as_ref(), &user)?;
    Ok((built_in, user, p))
}

/// `sesame provider show`: the definition in force, field by field of the
/// table, each with where it comes from: `built-in`, `user`, or `default`
/// (unset, so the default holds); a field without a value is left out.
/// Each service is its own field, `services.<name>`, as `sesame.db` keeps it.
pub fn show(name: &str) -> Result<Value, String> {
    let (built_in, user, p) = layers(name)?;
    let from = |k: &str| {
        if user.contains_key(k) {
            "user"
        } else if built_in.is_some() {
            "built-in"
        } else {
            "default"
        }
    };
    let mut values = as_fields(&p);
    let mut shown = Map::new();
    for f in FIELDS {
        if f.name == "services" {
            for (svc, s) in &p.services {
                let k = format!("{SERVICE_FIELD}{svc}");
                let entry = serde_json::json!({ "value": s, "from": from(&k) });
                shown.insert(k, entry);
            }
        } else if let Some(value) = values.remove(f.name) {
            let entry = serde_json::json!({ "value": value, "from": from(f.name) });
            shown.insert(f.name.into(), entry);
        }
    }
    Ok(Value::Object(shown))
}

/// `sesame provider export`: the `sesame provider add` command that makes
/// this definition again in another `sesame.db`: every field of the table
/// that is not its default, and every field the person gave.
pub fn export(name: &str) -> Result<String, String> {
    let (built_in, user, p) = layers(name)?;
    let values = as_fields(&p);
    let defaults = defaults();
    let mut out = String::new();
    if built_in.is_some() {
        out.push_str(&format!(
            "# `{name}` is built in, so `add` takes it only under another name.\n"
        ));
    }
    out.push_str(&format!("sesame provider add {}", fields::quote(name)));
    for f in FIELDS {
        let Some(v) = values.get(f.name) else {
            continue;
        };
        if defaults.get(f.name) == Some(v) && !user.contains_key(f.name) {
            continue;
        }
        // An empty list the person gave is the default: no flag says it.
        for g in f.kind.flag_values(v) {
            out.push_str(&format!(" \\\n  --{} {}", f.flag, fields::quote(&g)));
        }
    }
    out.push('\n');
    Ok(out)
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
    /// What one field's kind in the table does not say: the fields that go
    /// together, the steps and the services.
    fn check(&self) -> Result<(), String> {
        match (&self.identity_url, &self.identity_field) {
            (None, None) => {}
            (Some(u), Some(_)) => {
                let host = url::Url::parse(u)
                    .ok()
                    .and_then(|u| u.host_str().map(String::from))
                    .unwrap_or_default();
                if !self.allows_host(&host) {
                    return Err(format!(
                        "identity_url `{u}`: the token goes only to hosts, and {host} is not one"
                    ));
                }
            }
            _ => return Err("identity_url and identity_field go together: give both".into()),
        }
        if self.identity_body.is_some() && self.identity_url.is_none() {
            return Err("identity_body without identity_url: give the URL it goes to".into());
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

    /// The fields `sesame provider add` makes of these flags.
    fn flags(args: &[&str]) -> Result<Value, String> {
        use clap::{Args, FromArgMatches};
        let cmd = FieldFlags::augment_args(clap::Command::new("t").no_binary_name(true));
        let m = cmd.try_get_matches_from(args).map_err(|e| e.to_string())?;
        Ok(Value::Object(FieldFlags::from_arg_matches(&m).unwrap().0))
    }

    /// Every field of `Provider` has a row in the field table, and every row
    /// is a field: the struct literal stops compiling when a field is added,
    /// and this test then fails until the table has its row, question included.
    #[test]
    fn the_table_is_every_field() {
        let every = Provider {
            about: "a".into(),
            auth_url: "https://a.example/auth".into(),
            token_url: "https://a.example/token".into(),
            refresh_url: Some("https://a.example/refresh".into()),
            api_base: "https://a.example".into(),
            hosts: vec!["a.example".into()],
            scopes: vec!["s".into()],
            scope_param: "user_scope".into(),
            scope_separator: ",".into(),
            pkce: false,
            token_path: "/authed_user".into(),
            auth_params: BTreeMap::from([("k".into(), "v".into())]),
            token_body: TokenBody::Json,
            client_auth: ClientAuth::Basic,
            api_headers: BTreeMap::from([("X-A".into(), "1".into())]),
            resources_url: Some("https://a.example/sites".into()),
            site_name_field: Some("site".into()),
            redirect: Redirect::HttpsPaste,
            redirect_port: Some(9),
            code_seconds: Some(30),
            redirect_host: RedirectHost::Loopback,
            device_url: Some("https://a.example/device".into()),
            identity_url: Some("https://a.example/me".into()),
            identity_field: Some("login".into()),
            identity_body: Some(json!({"query": "q"})),
            error_fields: vec!["errors".into()],
            setup: vec![SetupStep {
                title: "T".into(),
                page: None,
                details: String::new(),
            }],
            services: BTreeMap::from([(
                "svc".into(),
                Service {
                    about: String::new(),
                    api_base: "https://a.example/svc".into(),
                    scopes: vec![],
                    setup: vec![],
                },
            )]),
            sources: vec!["https://a.example/docs".into()],
        };
        let mut have: Vec<String> = as_fields(&every).keys().cloned().collect();
        let mut table: Vec<String> = FIELDS.iter().map(|f| f.name.to_string()).collect();
        have.sort();
        table.sort();
        assert_eq!(have, table);
        effective("a", None, &as_fields(&every)).unwrap();
    }

    #[test]
    fn required_is_what_serde_requires() {
        let d = defaults();
        for f in FIELDS.iter().filter(|f| f.required) {
            assert!(!d.contains_key(f.name), "{}", f.name);
        }
        let mut required = Fields::new();
        for f in FIELDS.iter().filter(|f| f.required) {
            let v = match f.kind {
                fields::Kind::Hosts => json!(["a.example"]),
                _ => json!("https://a.example"),
            };
            required.insert(f.name.into(), v);
        }
        effective("a", None, &required).unwrap();
        for f in FIELDS.iter().filter(|f| f.required) {
            let mut missing = required.clone();
            missing.remove(f.name);
            let e = effective("a", None, &missing).unwrap_err();
            assert!(e.contains(&format!("missing field `{}`", f.name)), "{e}");
        }
    }

    #[test]
    fn choices_are_the_enum_variants() {
        for f in FIELDS {
            if let fields::Kind::Choice(words) = f.kind {
                for w in words {
                    let mut ok = fields(json!({
                        "auth_url": "https://a.example", "token_url": "https://a.example",
                        "api_base": "https://a.example", "hosts": ["a.example"],
                    }));
                    ok.insert(f.name.into(), json!(w));
                    // https-paste needs its fixed port.
                    ok.insert("redirect_port".into(), json!(9));
                    let p = effective("a", None, &ok).unwrap();
                    assert_eq!(as_fields(&p)[f.name], json!(w), "{}", f.name);
                }
            }
        }
    }

    #[test]
    fn built_in_ports_are_distinct() {
        let mut ports: Vec<u16> = built_in::all()
            .values()
            .filter_map(|p| p.redirect_port)
            .collect();
        let n = ports.len();
        ports.sort();
        ports.dedup();
        assert_eq!(ports.len(), n);
    }

    #[test]
    fn built_ins_are_valid() {
        let all = built_in::all();
        for name in [
            "figma", "github", "google", "jira", "linear", "notion", "slack",
        ] {
            assert!(all.contains_key(name), "{name}");
        }
        for (name, p) in &all {
            effective(name, Some(p), &Fields::new()).unwrap();
        }
    }

    #[test]
    fn google_services() {
        let g = built_in("google");
        assert_eq!(g.scopes, ["openid", "email"]);
        assert_eq!(g.auth_params["include_granted_scopes"], "true");
        let auth = |s: &str| format!("https://www.googleapis.com/auth/{s}");
        for (name, base, scopes) in [
            (
                "drive",
                "https://www.googleapis.com/drive/v3",
                vec!["drive.readonly"],
            ),
            (
                "docs",
                "https://docs.googleapis.com/v1",
                vec!["documents.readonly"],
            ),
            (
                "youtube",
                "https://www.googleapis.com/youtube/v3",
                vec!["youtube.readonly"],
            ),
            (
                "calendar",
                "https://www.googleapis.com/calendar/v3",
                vec!["calendar.readonly", "calendar.events"],
            ),
            (
                "gmail",
                "https://gmail.googleapis.com/gmail/v1",
                vec!["gmail.readonly", "gmail.send"],
            ),
        ] {
            let s = &g.services[name];
            assert_eq!(s.api_base, base, "{name}");
            let want: Vec<String> = scopes.iter().map(|s| auth(s)).collect();
            assert_eq!(s.scopes, want, "{name}");
            assert!(!s.setup.is_empty(), "{name}");
        }
        assert_eq!(g.services.len(), 5);
    }

    #[test]
    fn a_changed_service_is_stored_alone() {
        let g = built_in("google");
        let base = as_fields(&g);
        let mut gmail = as_fields(&g.services["gmail"]);
        assert_eq!(
            base_value(&base, "services.gmail"),
            Some(&Value::Object(gmail.clone()))
        );
        gmail.insert("scopes".into(), json!(["x"]));
        let user = fields(json!({"services.gmail": gmail, "services.youtube": null}));
        let p = effective("google", Some(&g), &user).unwrap();
        assert_eq!(p.services["gmail"].scopes, ["x"]);
        assert_eq!(p.services["drive"], g.services["drive"]);
        assert!(!p.services.contains_key("youtube"));
    }

    #[test]
    fn service_flags() {
        assert_eq!(
            flags(&[
                "--service",
                "name=a,api-base=https://a.example/v1,scope=r,scope=w,about=A",
                "--service",
                r#"{"name": "b", "api_base": "https://b.example"}"#,
                "--drop-service",
                "c",
            ])
            .unwrap(),
            json!({
                "services.a": {"api_base": "https://a.example/v1", "scopes": ["r", "w"], "about": "A"},
                "services.b": {"api_base": "https://b.example"},
                "services.c": null,
            })
        );
        for (bad, want) in [
            ("api-base=https://a.example", "has no name"),
            ("name=a,base=x", "unknown key `base`"),
            ("name=a,x", "not key=value"),
            ("[1]", "not key=value"),
        ] {
            let e = flags(&["--service", bad]).unwrap_err();
            assert!(e.contains(want), "{bad}: {e}");
        }
        let ok = json!({
            "auth_url": "https://a.example/auth",
            "token_url": "https://a.example/token",
            "api_base": "https://api.a.example",
            "hosts": ["*.a.example"],
        });
        for (svc, want) in [
            (
                json!({"api_base": "https://evil.example"}),
                "evil.example is not one",
            ),
            (json!({"api_base": "nope"}), "service `s` api_base"),
            (json!({"scopes": []}), "missing field `api_base`"),
        ] {
            let mut f = fields(ok.clone());
            f.insert("services.s".into(), svc);
            let e = effective("a", None, &f).unwrap_err();
            assert!(e.contains(want), "{e}");
        }
        let mut f = fields(ok);
        f.insert(
            "services.b d".into(),
            json!({"api_base": "https://x.a.example"}),
        );
        let e = effective("a", None, &f).unwrap_err();
        assert!(e.contains("service name `b d`"), "{e}");
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
            (
                "token_body",
                json!("xml"),
                "token_body `xml`: not one of form, json",
            ),
            ("client_auth", json!("digest"), "not one of body, basic"),
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
            (
                "redirect",
                json!("carrier-pigeon"),
                "not one of loopback, https-paste",
            ),
            ("scope_param", json!(""), "scope_param"),
            ("token_path", json!("authed_user"), "JSON pointer"),
            ("pkce", json!("maybe"), "expected a boolean"),
            ("refresh_url", json!("nope"), "refresh_url"),
            ("code_seconds", json!(0), "code_seconds 0"),
            (
                "redirect_host",
                json!("example.com"),
                "not one of localhost, 127.0.0.1",
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
}
