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

use fields::FIELDS;
pub use fields::FieldFlags;

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
    /// The documentation pages the definition was read from.
    #[serde(default)]
    pub sources: Vec<String>,
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
/// written to `sesame.db` passes through here first, each field by its kind
/// in the field table, then the fields that go together.
fn effective(name: &str, built_in: Option<&Provider>, user: &Fields) -> Result<Provider, String> {
    let mut fields = match built_in {
        Some(p) => as_fields(p),
        None => Fields::new(),
    };
    fields.extend(user.clone());
    let err = |e: String| format!("provider `{name}`: {e}");
    fields::check(&fields).map_err(err)?;
    let p: Provider =
        serde_json::from_value(Value::Object(fields)).map_err(|e| err(e.to_string()))?;
    p.check().map_err(err)?;
    Ok(p)
}

fn as_fields(p: &Provider) -> Fields {
    match serde_json::to_value(p) {
        Ok(Value::Object(m)) => m,
        _ => unreachable!("a Provider serializes to an object"),
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

/// Every provider in force, given the stored fields of all of them.
fn all_from(mut user: BTreeMap<String, Fields>) -> Result<BTreeMap<String, Provider>, String> {
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

pub fn all() -> Result<BTreeMap<String, Provider>, String> {
    all_from(Store::open()?.provider_fields()?)
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

/// Validates `name`'s new stored fields against everything else stored, and
/// writes them: a fixed callback port is one provider's only, since two
/// logins cannot listen on it, and each registers it as its own.
fn save(s: &Store, name: &str, built_in: Option<&Provider>, user: Fields) -> Result<(), String> {
    let p = effective(name, built_in, &user)?;
    if let Some(port) = p.redirect_port {
        let mut stored = s.provider_fields()?;
        stored.remove(name);
        let others = all_from(stored)?;
        if let Some((other, _)) = others
            .iter()
            .find(|(o, q)| o.as_str() != name && q.redirect_port == Some(port))
        {
            return Err(format!(
                "provider `{name}`: redirect_port {port} is taken by `{other}`; \
                 pick another port"
            ));
        }
    }
    s.save_provider_fields(name, &user)
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
        save(s, name, None, fields)
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
        save(s, name, built_in.as_ref(), user)
    })
}

/// The built-in definition of `name`, if any, its stored fields, and the
/// definition in force; an error for a name that is neither.
fn layers(name: &str) -> Result<(Option<Provider>, Fields, Provider), String> {
    let built_in = built_in::all().remove(name);
    let user = Store::open()?
        .provider_fields()?
        .remove(name)
        .unwrap_or_default();
    if built_in.is_none() && user.is_empty() {
        return Err(unknown(name, all()?.into_keys()));
    }
    let p = effective(name, built_in.as_ref(), &user)?;
    Ok((built_in, user, p))
}

/// `sesame provider show`: the definition in force, field by field of the
/// table, each with where it comes from: `built-in`, `user`, or `default`
/// (unset, so the default holds). A field without a value is left out.
pub fn show(name: &str) -> Result<Value, String> {
    let (built_in, user, p) = layers(name)?;
    let mut values = as_fields(&p);
    let mut shown = Fields::new();
    for f in FIELDS {
        let Some(value) = values.remove(f.name) else {
            continue;
        };
        let from = if user.contains_key(f.name) {
            "user"
        } else if built_in.is_some() {
            "built-in"
        } else {
            "default"
        };
        shown.insert(
            f.name.into(),
            serde_json::json!({ "value": value, "from": from }),
        );
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
        let given = f.kind.flag_values(v);
        if given.is_empty() {
            // An empty list the person gave is the default: no flag says it.
            continue;
        }
        for g in given {
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
        (false, false) => Err(unknown(name, all()?.into_keys())),
    }
}

/// The loopback redirect URL login listens on, for the port it bound.
pub fn redirect_uri(host: RedirectHost, port: u16) -> String {
    format!("http://{}:{port}/callback", host.as_str())
}

impl Provider {
    /// What one field's kind does not say: the fields that go together.
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
        Ok(())
    }

    /// The redirect URL to register with the provider: fixed when `redirect_port` is.
    pub fn callback(&self) -> String {
        match self.redirect_port {
            Some(port) => redirect_uri(self.redirect_host, port),
            None => format!("http://{}:<any port>/callback", self.redirect_host.as_str()),
        }
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

    /// Every field of `Provider` has a row in the field table, and every row
    /// is a field: the struct literal stops compiling when a field is added,
    /// and this test then fails until the table has its row, question included.
    #[test]
    fn the_table_is_every_field() {
        let every = Provider {
            about: "a".into(),
            auth_url: "https://a.example/auth".into(),
            token_url: "https://a.example/token".into(),
            api_base: "https://a.example".into(),
            hosts: vec!["a.example".into()],
            scopes: vec!["s".into()],
            scope_separator: ",".into(),
            auth_params: BTreeMap::from([("k".into(), "v".into())]),
            token_body: TokenBody::Json,
            client_auth: ClientAuth::Basic,
            api_headers: BTreeMap::from([("X-A".into(), "1".into())]),
            resources_url: Some("https://a.example/sites".into()),
            site_name_field: Some("site".into()),
            redirect_port: Some(9),
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
        for name in ["github", "google", "jira", "linear", "notion"] {
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
