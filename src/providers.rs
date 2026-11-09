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
    /// What joins the scopes in the authorization URL: a space (OAuth's own), `,` for some.
    #[serde(default = "space")]
    pub scope_separator: String,
    #[serde(default)]
    pub auth_params: BTreeMap<String, String>,
    #[serde(default)]
    pub token_body: TokenBody,
    /// Lists the sites a token can reach (Atlassian); the first, or `--site`, is kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources_url: Option<String>,
    /// Fixed loopback port, for providers that match the callback URL exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_port: Option<u16>,
    /// Top-level fields of an API's JSON answer that, present and not empty,
    /// mean the call failed although the status is 2xx (GraphQL's `errors`).
    #[serde(default)]
    pub error_fields: Vec<String>,
    /// The call login makes to learn who signed in, for `sesame providers`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub whoami: Option<Whoami>,
    /// How to register this provider's OAuth app, for `sesame setup`.
    #[serde(default)]
    pub setup: Vec<SetupStep>,
}

fn space() -> String {
    " ".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Whoami {
    /// Path under `api_base`, or a full URL on one of `hosts`.
    pub path: String,
    /// JSON body; with one the call is a POST, without it a GET.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    /// The account's name, with `{/json/pointer}` filled in from the answer.
    pub name: String,
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
    /// A scope login asks for; repeatable.
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
    /// URL listing the sites a token reaches (Atlassian).
    #[arg(long)]
    resources_url: Option<String>,
    /// Fixed loopback port for the callback, for providers that match it exactly.
    #[arg(long)]
    redirect_port: Option<u16>,
    /// A top-level field of the API's JSON answer that, not empty, fails the
    /// call despite a 2xx status (GraphQL: `errors`); repeatable.
    #[arg(long = "error-field")]
    error_fields: Vec<String>,
    /// The call login makes to learn who signed in, as JSON:
    /// `{"path": …, "body": …, "name": "{/json/pointer} …"}`; body makes it a POST.
    #[arg(long)]
    whoami: Option<String>,
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
            ("scope_separator", opt(self.scope_separator)),
            ("error_fields", list(self.error_fields)),
            ("token_body", opt(self.token_body)),
            ("resources_url", opt(self.resources_url)),
            ("redirect_port", self.redirect_port.map(Value::from)),
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
        if let Some(w) = self.whoami {
            let v =
                serde_json::from_str(&w).map_err(|e| format!("--whoami `{w}` is not JSON: {e}"))?;
            put("whoami", v);
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
pub fn redirect_uri(port: u16) -> String {
    format!("http://localhost:{port}/callback")
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
        if self.redirect_port == Some(0) {
            return Err("redirect_port 0: leave it out for any free port".into());
        }
        if self.scope_separator.is_empty() {
            return Err("scope_separator is empty: give a space or a character such as `,`".into());
        }
        if self.error_fields.iter().any(|f| f.trim().is_empty()) {
            return Err("an error_fields entry is empty".into());
        }
        if let Some(w) = &self.whoami {
            if w.path.trim().is_empty() {
                return Err("whoami has no path".into());
            }
            if !w.name.contains("{/") {
                return Err(format!(
                    "whoami name `{}` has no `{{/json/pointer}}` to fill in",
                    w.name
                ));
            }
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
            Some(port) => redirect_uri(port),
            None => "http://localhost:<any port>/callback".into(),
        }
    }

    /// The URL for `path` (relative to `api_base`, or full), refused unless on one of `hosts`.
    pub fn resolve(&self, resource_id: Option<&str>, path: &str) -> Result<url::Url, String> {
        let url = if path.starts_with("https://") || path.starts_with("http://") {
            url::Url::parse(path).map_err(|e| e.to_string())?
        } else {
            let mut base = self.api_base.clone();
            if base.contains("{resource_id}") {
                let id = resource_id.ok_or("no site stored; log in again")?;
                base = base.replace("{resource_id}", id);
            }
            let sep = if path.starts_with('/') { "" } else { "/" };
            url::Url::parse(&format!("{}{sep}{path}", base.trim_end_matches('/')))
                .map_err(|e| e.to_string())?
        };
        let host = url.host_str().unwrap_or("");
        if !self.allows_host(host) {
            return Err(format!(
                "refusing to send the token to {host}: not one of {:?}",
                self.hosts
            ));
        }
        Ok(url)
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

impl Whoami {
    /// `name` with each `{/pointer}` filled in from `answer`.
    pub fn name_in(&self, answer: &Value) -> Result<String, String> {
        let mut out = String::new();
        let mut rest = self.name.as_str();
        while let Some(i) = rest.find("{/") {
            out.push_str(&rest[..i]);
            let end = rest[i..]
                .find('}')
                .ok_or_else(|| format!("whoami name `{}`: unclosed `{{`", self.name))?;
            let pointer = &rest[i + 1..i + end];
            match answer.pointer(pointer) {
                Some(Value::String(s)) => out.push_str(s),
                Some(Value::Null) | None => {
                    return Err(format!("the answer has no {pointer}: {answer}"));
                }
                Some(v) => out.push_str(&v.to_string()),
            }
            rest = &rest[i + end + 1..];
        }
        out.push_str(rest);
        Ok(out)
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
        for name in ["google", "jira", "linear"] {
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
            ("redirect_port", json!(0), "redirect_port 0"),
            ("setup", json!([{"title": ""}]), "no title"),
            ("scope_separator", json!(""), "scope_separator is empty"),
            ("error_fields", json!([""]), "error_fields entry is empty"),
            (
                "whoami",
                json!({"path": "/me", "name": "me"}),
                "no `{/json/pointer}`",
            ),
            (
                "whoami",
                json!({"path": "", "name": "{/n}"}),
                "whoami has no path",
            ),
            ("whoami", json!({"name": "{/n}"}), "missing field `path`"),
            ("nope", json!(1), "unknown field `nope`"),
        ] {
            let mut f = fields(ok.clone());
            f.insert(k.into(), v);
            let e = effective("a", None, &f).unwrap_err();
            assert!(e.contains(want), "{k}: {e}");
        }
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
    fn whoami_name_fills_pointers() {
        let w = built_in("linear").whoami.unwrap();
        let answer =
            json!({"data": {"viewer": {"name": "Felix"}, "organization": {"name": "Acme"}}});
        assert_eq!(w.name_in(&answer).unwrap(), "Felix (Acme)");
        let e = w
            .name_in(&json!({"data": {"viewer": {"name": "F"}}}))
            .unwrap_err();
        assert!(e.contains("/data/organization/name"), "{e}");
    }

    #[test]
    fn flags_become_fields() {
        let flags = FieldFlags {
            scopes: vec!["a".into(), "b".into()],
            auth_params: vec!["prompt=consent".into()],
            redirect_port: Some(9000),
            scope_separator: Some(",".into()),
            error_fields: vec!["errors".into()],
            whoami: Some(r#"{"path":"/graphql","name":"{/data/viewer/name}"}"#.into()),
            setup: vec![r#"{"title":"T","page":"https://x.example"}"#.into()],
            ..Default::default()
        };
        assert_eq!(
            Value::Object(flags.fields().unwrap()),
            json!({
                "scopes": ["a", "b"],
                "auth_params": {"prompt": "consent"},
                "redirect_port": 9000,
                "scope_separator": ",",
                "error_fields": ["errors"],
                "whoami": {"path": "/graphql", "name": "{/data/viewer/name}"},
                "setup": [{"title": "T", "page": "https://x.example"}],
            })
        );
        let bad = FieldFlags {
            auth_params: vec!["novalue".into()],
            ..Default::default()
        };
        assert!(bad.fields().unwrap_err().contains("key=value"));
    }
}
