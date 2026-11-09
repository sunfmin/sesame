//! The field table: every field of a provider definition, once. The flags of
//! `sesame provider add` and `set` are made from it, `effective` validates each
//! value by its kind, `provider show` and `export` walk it, and `provider
//! guide` prints its research checklist from each field's question.
//!
//! A field added to `Provider` gets a row here, question included; the tests
//! fail until it has one.
use serde_json::{Map, Value};

/// A field's type, which decides its flag, how a flag value is read, how a
/// stored value is checked, and how `export` writes it back as flags.
#[derive(Clone, Copy, Debug)]
pub enum Kind {
    /// Free text.
    Text,
    /// Text that, when given, is not blank.
    Name,
    /// Text that, when given, is not empty; a space is one.
    Separator,
    /// An http(s) URL; `{resource_id}` may stand for the site picked at login.
    Url,
    /// One of these words.
    Choice(&'static [&'static str]),
    /// A TCP port, 1-65535.
    Port,
    /// Repeatable text, no entry blank.
    Names,
    /// Repeatable http(s) URL.
    Urls,
    /// Repeatable host name, or `*.` and a domain; at least one.
    Hosts,
    /// Repeatable `key=value`.
    Params,
    /// Repeatable `Name: value` HTTP header.
    Headers,
    /// One JSON value.
    Json,
    /// Repeatable JSON setup step `{"title": …, "page": …, "details": …}`.
    Steps,
}

pub struct Field {
    /// The name `sesame.db` and `provider show` use.
    pub name: &'static str,
    /// The long flag of `provider add` and `set`, without `--`.
    pub flag: &'static str,
    pub kind: Kind,
    /// `provider add` refuses a definition without it.
    pub required: bool,
    /// The flag's help.
    pub help: &'static str,
    /// What to find out about a platform to fill the field in, for `provider guide`.
    pub question: &'static str,
    /// Where a platform's docs usually answer it.
    pub look: &'static str,
}

pub const FIELDS: &[Field] = &[
    Field {
        name: "about",
        flag: "about",
        kind: Kind::Text,
        required: false,
        help: "One line on what the provider is, for `sesame providers`.",
        question: "What is the platform and its API, in one line (e.g. \"Acme REST API\")?",
        look: "the platform's developer home page",
    },
    Field {
        name: "auth_url",
        flag: "auth-url",
        kind: Kind::Url,
        required: true,
        help: "The OAuth authorization endpoint.",
        question: "Where is the authorization endpoint, the page the person approves access on?",
        look: "the OAuth guide's \"authorize\" step, or the metadata's authorization_endpoint",
    },
    Field {
        name: "token_url",
        flag: "token-url",
        kind: Kind::Url,
        required: true,
        help: "The OAuth token endpoint; refreshing goes there too.",
        question: "Where is the token endpoint that exchanges the code, and does refreshing \
                   (grant_type=refresh_token) go to the same one?",
        look: "the OAuth guide's \"exchange the code\" and \"refresh\" steps, or the metadata's token_endpoint",
    },
    Field {
        name: "api_base",
        flag: "api-base",
        kind: Kind::Url,
        required: true,
        help: "Base for relative `sesame api` paths; `{resource_id}` is the site picked at login.",
        question: "What is the API's base URL? Does it hold a site or workspace id (write it as `{resource_id}`)?",
        look: "the API reference's introduction or any endpoint's full URL",
    },
    Field {
        name: "hosts",
        flag: "host",
        kind: Kind::Hosts,
        required: true,
        help: "A host the token may be sent to (`*.example.com` matches subdomains); repeatable.",
        question: "Which hosts serve the API, so the token may be sent to them and to no other?",
        look: "the API reference's endpoint URLs (uploads and GraphQL can be on other hosts)",
    },
    Field {
        name: "scopes",
        flag: "scope",
        kind: Kind::Names,
        required: false,
        help: "A scope login asks for; repeatable. With none, the authorization URL has no `scope`.",
        question: "Which scopes exist, and which does the person's use of the API need? Is a scope \
                   needed to get a refresh token (e.g. `offline_access`)? No scopes at all?",
        look: "the OAuth guide's scopes table, or the metadata's scopes_supported",
    },
    Field {
        name: "scope_separator",
        flag: "scope-separator",
        kind: Kind::Separator,
        required: false,
        help: "What joins the scopes in the authorization URL (default: a space).",
        question: "What joins several scopes in the authorization URL: a space (OAuth's own) or a comma?",
        look: "the authorize step's example URL",
    },
    Field {
        name: "auth_params",
        flag: "auth-param",
        kind: Kind::Params,
        required: false,
        help: "`key=value` added to the authorization URL; repeatable.",
        question: "Does the authorization URL need parameters beyond the standard ones \
                   (e.g. `access_type=offline`, `prompt=consent`, `audience=…`, `owner=user`)?",
        look: "the authorize step's parameter table",
    },
    Field {
        name: "token_body",
        flag: "token-body",
        kind: Kind::Choice(&["form", "json"]),
        required: false,
        help: "How the token endpoint takes its body.",
        question: "Does the token endpoint take a form body (application/x-www-form-urlencoded) or JSON?",
        look: "the token step's request example and its Content-Type",
    },
    Field {
        name: "client_auth",
        flag: "client-auth",
        kind: Kind::Choice(&["body", "basic"]),
        required: false,
        help: "How the client authenticates to the token endpoint: in the body, or HTTP Basic.",
        question: "Do client_id and client_secret go in the token request's body, or as HTTP Basic \
                   (Authorization: Basic base64(id:secret))?",
        look: "the token step's request example, or the metadata's token_endpoint_auth_methods_supported",
    },
    Field {
        name: "api_headers",
        flag: "api-header",
        kind: Kind::Headers,
        required: false,
        help: "Header `Name: value` every `sesame api` request carries; repeatable. \
               A `-H` of the same name replaces it.",
        question: "Must every API request carry a header, e.g. a version (`Notion-Version`) or an Accept type?",
        look: "the API reference's introduction, versioning or \"making requests\" page",
    },
    Field {
        name: "resources_url",
        flag: "resources-url",
        kind: Kind::Url,
        required: false,
        help: "URL listing the sites a token reaches (Atlassian).",
        question: "After login, must the API first list the sites or workspaces the token reaches, \
                   to pick one for `{resource_id}`? At which URL?",
        look: "the OAuth guide's step after the token, e.g. \"accessible resources\"",
    },
    Field {
        name: "site_name_field",
        flag: "site-name-field",
        kind: Kind::Name,
        required: false,
        help: "The token response's field naming the site the login reached (Notion: `workspace_name`).",
        question: "Does the token response name the workspace the login reached, and in which field?",
        look: "the token step's response example",
    },
    Field {
        name: "redirect_port",
        flag: "redirect-port",
        kind: Kind::Port,
        required: false,
        help: "Fixed loopback port for the callback, for providers that match it exactly.",
        question: "Does the platform match the callback's port exactly against the registered one \
                   (then fix a port no other provider uses), or take any port on loopback?",
        look: "the app registration page's redirect URI rules",
    },
    Field {
        name: "redirect_host",
        flag: "redirect-host",
        kind: Kind::Choice(&["localhost", "127.0.0.1"]),
        required: false,
        help: "The loopback redirect's host.",
        question: "Which loopback host does the platform accept in the callback: `localhost` or `127.0.0.1`?",
        look: "the redirect URI rules, or native/desktop app guidance (RFC 8252)",
    },
    Field {
        name: "device_url",
        flag: "device-url",
        kind: Kind::Url,
        required: false,
        help: "Device authorization endpoint (RFC 8628); login then uses the device flow \
               by default, and `--browser` the loopback redirect.",
        question: "Does the platform offer the device flow (a code entered on its page), and at which endpoint? \
                   Must it be switched on for the app?",
        look: "the OAuth guide's \"device flow\" section, or the metadata's device_authorization_endpoint",
    },
    Field {
        name: "identity_url",
        flag: "identity-url",
        kind: Kind::Url,
        required: false,
        help: "JSON endpoint naming who signed in, read after login (on one of the hosts).",
        question: "Which API endpoint says who signed in (`/me`, `/user`, a GraphQL `viewer`)?",
        look: "the API reference's users or \"current user\" page",
    },
    Field {
        name: "identity_field",
        flag: "identity-field",
        kind: Kind::Name,
        required: false,
        help: "The field of the identity answer naming the account, e.g. `login`, or a \
               JSON pointer into it, e.g. `/data/viewer/name`.",
        question: "Which field of that endpoint's answer names the account (a field, or a JSON pointer)?",
        look: "that endpoint's response example",
    },
    Field {
        name: "identity_body",
        flag: "identity-body",
        kind: Kind::Json,
        required: false,
        help: "JSON body for the identity call, which makes it a POST (GraphQL).",
        question: "Is the identity call a POST with a body (GraphQL: `{\"query\": \"{ viewer { name } }\"}`)?",
        look: "that endpoint's request example",
    },
    Field {
        name: "error_fields",
        flag: "error-field",
        kind: Kind::Names,
        required: false,
        help: "A top-level field of the API's JSON answer that, not empty, fails the \
               call despite a 2xx status (GraphQL: `errors`); repeatable.",
        question: "Can an API answer be HTTP 200 and still a failure (GraphQL `errors`, Slack `\"ok\": false`)? \
                   Which top-level field says so?",
        look: "the API reference's errors page",
    },
    Field {
        name: "setup",
        flag: "setup-step",
        kind: Kind::Steps,
        required: false,
        help: "A step for `sesame setup`, as JSON: `{\"title\": …, \"page\": …, \"details\": …}`; \
               repeatable, in order. `{callback}` and `{scopes}` in details are filled in.",
        question: "How does the person register an OAuth app: which page, what to click and fill in, \
                   which app type, where to enter the callback, where the client id and secret show? \
                   Anything that expires they must know about (a refresh token that dies after 7 days)?",
        look: "the platform's \"create an app\" or \"register an integration\" guide",
    },
    Field {
        name: "sources",
        flag: "source",
        kind: Kind::Urls,
        required: false,
        help: "A documentation page this definition was read from; repeatable. \
               `provider show` and `export` keep them.",
        question: "Which official pages did each answer above come from?",
        look: "the links you followed for the other fields",
    },
];

/// What sesame does one way only, so no field configures it: a platform that
/// differs here cannot be signed in to with sesame yet.
pub const FIXED: &[(&str, &str)] = &[
    (
        "Does the platform support PKCE, and with which code_challenge_method?",
        "sesame always sends PKCE with S256. Most platforms without PKCE ignore it; one that \
         rejects the parameters cannot be signed in to yet.",
    ),
    (
        "What is the authorization URL's scope parameter called?",
        "sesame sends `scope` (Slack's user tokens use `user_scope`: not yet supported).",
    ),
    (
        "Where in the token response are access_token, refresh_token and expires_in?",
        "sesame reads them at the top level of the JSON answer.",
    ),
    (
        "How long do access and refresh tokens live, and does a refresh hand out a new refresh token?",
        "sesame refreshes at token_url a minute before expires_in runs out, and after a 401; it \
         keeps the old refresh token when a refresh brings none. Write a lifetime the person must \
         know about into a --setup-step.",
    ),
    (
        "Must every callback be https, or is http allowed for loopback?",
        "sesame's browser login listens on http://<redirect_host>:<port>/callback. A platform \
         that refuses http on loopback needs device_url, or cannot be signed in to yet.",
    ),
];

pub fn field(name: &str) -> Option<&'static Field> {
    FIELDS.iter().find(|f| f.name == name)
}

impl Kind {
    pub fn repeatable(self) -> bool {
        matches!(
            self,
            Kind::Names | Kind::Urls | Kind::Hosts | Kind::Params | Kind::Headers | Kind::Steps
        )
    }

    pub fn value_name(self) -> &'static str {
        match self {
            Kind::Text | Kind::Name | Kind::Separator | Kind::Names => "TEXT",
            Kind::Url | Kind::Urls => "URL",
            Kind::Choice(_) => "WORD",
            Kind::Port => "PORT",
            Kind::Hosts => "HOST",
            Kind::Params => "KEY=VALUE",
            Kind::Headers => "NAME: VALUE",
            Kind::Json | Kind::Steps => "JSON",
        }
    }

    /// The type, for help and the checklist.
    pub fn describe(self) -> String {
        let one = match self {
            Kind::Text => "text",
            Kind::Name | Kind::Names => "text, not blank",
            Kind::Separator => "text, not empty (a space counts)",
            Kind::Url | Kind::Urls => "http(s) URL",
            Kind::Choice(words) => return format!("one of: {}", words.join(", ")),
            Kind::Port => "port 1-65535",
            Kind::Hosts => "host, or `*.` and a domain",
            Kind::Params => "key=value",
            Kind::Headers => "`Name: value`",
            Kind::Json => "JSON",
            Kind::Steps => "JSON step",
        };
        if self.repeatable() {
            format!("{one}; repeatable")
        } else {
            one.into()
        }
    }

    /// One flag occurrence as the value it stands for. Choices are taken as
    /// given: `check` refuses an unknown word with the field's name.
    pub fn parse(self, s: &str) -> Result<Value, String> {
        match self {
            Kind::Port => s
                .parse::<u16>()
                .map(Value::from)
                .map_err(|_| format!("`{s}` is not a port")),
            Kind::Params => {
                let (k, v) = s
                    .split_once('=')
                    .ok_or_else(|| format!("`{s}` is not key=value"))?;
                Ok(Value::Object(Map::from_iter([(k.into(), v.into())])))
            }
            Kind::Headers => {
                let (k, v) = s
                    .split_once(':')
                    .ok_or_else(|| format!("`{s}` is not `Name: value`"))?;
                Ok(Value::Object(Map::from_iter([(
                    k.trim().into(),
                    v.trim().into(),
                )])))
            }
            Kind::Json | Kind::Steps => {
                serde_json::from_str(s).map_err(|e| format!("`{s}` is not JSON: {e}"))
            }
            _ => Ok(Value::String(s.into())),
        }
    }

    /// The value of all of a flag's occurrences, in order.
    pub fn collect(self, mut given: Vec<Value>) -> Value {
        match self {
            Kind::Params | Kind::Headers => {
                let mut m = Map::new();
                for v in given {
                    if let Value::Object(o) = v {
                        m.extend(o);
                    }
                }
                Value::Object(m)
            }
            k if k.repeatable() => Value::Array(given),
            _ => given.pop().unwrap_or(Value::Null),
        }
    }

    /// The flag values that give back `v`: `parse` and `collect` undone.
    pub fn flag_values(self, v: &Value) -> Vec<String> {
        let text = |v: &Value| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        match (self, v) {
            (Kind::Params, Value::Object(m)) => {
                m.iter().map(|(k, v)| format!("{k}={}", text(v))).collect()
            }
            (Kind::Headers, Value::Object(m)) => {
                m.iter().map(|(k, v)| format!("{k}: {}", text(v))).collect()
            }
            (Kind::Json, v) => vec![v.to_string()],
            (Kind::Steps, Value::Array(a)) => a.iter().map(Value::to_string).collect(),
            (_, Value::Array(a)) => a.iter().map(text).collect(),
            (_, v) => vec![text(v)],
        }
    }

    /// What the type alone does not say about a stored value. A value of the
    /// wrong JSON type is left to serde, which names the type it wants.
    pub fn check(self, name: &str, v: &Value) -> Result<(), String> {
        let strings = || v.as_array().into_iter().flatten().filter_map(Value::as_str);
        match self {
            Kind::Text | Kind::Json => {}
            Kind::Name => {
                if v.as_str().is_some_and(|s| s.trim().is_empty()) {
                    return Err(format!("{name} is empty: leave it out, or give a value"));
                }
            }
            Kind::Separator => {
                if v.as_str().is_some_and(str::is_empty) {
                    return Err(format!(
                        "{name} is empty: give a space or a character such as `,`"
                    ));
                }
            }
            Kind::Url => {
                if let Some(u) = v.as_str() {
                    check_url(name, u)?;
                }
            }
            Kind::Urls => {
                for u in strings() {
                    check_url(name, u)?;
                }
            }
            Kind::Choice(words) => {
                if let Some(s) = v.as_str().filter(|s| !words.contains(s)) {
                    return Err(format!("{name} `{s}`: not one of {}", words.join(", ")));
                }
            }
            Kind::Port => {
                if v.as_u64() == Some(0) {
                    return Err(format!("{name} 0: leave it out for any free port"));
                }
            }
            Kind::Names => {
                if strings().any(|s| s.trim().is_empty()) {
                    return Err(format!("a {name} entry is empty"));
                }
            }
            Kind::Hosts => {
                if v.as_array().is_some_and(Vec::is_empty) {
                    return Err(format!(
                        "{name} is empty: give at least one --host the token may go to"
                    ));
                }
                if let Some(h) = strings().find(|h| {
                    let bare = h.strip_prefix("*.").unwrap_or(h);
                    bare.is_empty() || bare.contains(['/', ':', '*', ' '])
                }) {
                    return Err(format!("host `{h}`: a host name, or `*.` and a domain"));
                }
            }
            Kind::Params => {}
            Kind::Headers => {
                for (k, v) in v.as_object().into_iter().flatten() {
                    reqwest::header::HeaderName::from_bytes(k.as_bytes())
                        .map_err(|_| format!("api header `{k}`: not a header name"))?;
                    let s = v.as_str().unwrap_or_default();
                    reqwest::header::HeaderValue::from_str(s).map_err(|_| {
                        format!("api header `{k}`: value `{s}` is not a header value")
                    })?;
                    if k.eq_ignore_ascii_case("authorization") {
                        return Err(
                            "api header `Authorization`: sesame sets it from the token".into()
                        );
                    }
                }
            }
            Kind::Steps => {
                for s in v.as_array().into_iter().flatten() {
                    let title = s.get("title").and_then(Value::as_str).unwrap_or_default();
                    if title.trim().is_empty() {
                        return Err("a setup step has no title".into());
                    }
                    if let Some(page) = s.get("page").and_then(Value::as_str) {
                        check_url("setup page", page)?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn check_url(field: &str, u: &str) -> Result<(), String> {
    let parsed = url::Url::parse(&u.replace("{resource_id}", "x"))
        .map_err(|e| format!("{field} `{u}`: {e}"))?;
    match parsed.scheme() {
        "https" | "http" => Ok(()),
        s => Err(format!("{field} `{u}`: scheme {s} is not http or https")),
    }
}

/// Checks each field `fields` holds by its kind; unknown names are left to serde.
pub fn check(fields: &Map<String, Value>) -> Result<(), String> {
    for f in FIELDS {
        if let Some(v) = fields.get(f.name) {
            f.kind.check(f.name, v)?;
        }
    }
    Ok(())
}

/// `s` as one word for sh: single-quoted unless it is plainly safe.
pub fn quote(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:@%+=,".contains(c));
    if plain {
        s.into()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// `sesame provider add` and `set`: one flag per field of the table.
#[derive(Debug, Default)]
pub struct FieldFlags(pub Map<String, Value>);

impl clap::FromArgMatches for FieldFlags {
    fn from_arg_matches(m: &clap::ArgMatches) -> Result<Self, clap::Error> {
        let mut flags = FieldFlags::default();
        flags.update_from_arg_matches(m)?;
        Ok(flags)
    }

    fn update_from_arg_matches(&mut self, m: &clap::ArgMatches) -> Result<(), clap::Error> {
        for f in FIELDS {
            if let Some(given) = m.get_many::<Value>(f.name) {
                let given: Vec<Value> = given.cloned().collect();
                self.0.insert(f.name.into(), f.kind.collect(given));
            }
        }
        Ok(())
    }
}

impl clap::Args for FieldFlags {
    fn augment_args(mut cmd: clap::Command) -> clap::Command {
        for f in FIELDS {
            let kind = f.kind;
            let help = format!(
                "{}{} [{}]",
                if f.required { "(required) " } else { "" },
                f.help,
                kind.describe()
            );
            cmd = cmd.arg(
                clap::Arg::new(f.name)
                    .long(f.flag)
                    .value_name(kind.value_name())
                    .help(help)
                    .value_parser(clap::builder::ValueParser::new(move |s: &str| {
                        kind.parse(s)
                    }))
                    .action(if kind.repeatable() {
                        clap::ArgAction::Append
                    } else {
                        clap::ArgAction::Set
                    }),
            );
        }
        cmd
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
        Self::augment_args(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Args, FromArgMatches};
    use serde_json::json;

    fn parse(args: &[&str]) -> Result<Value, String> {
        let cmd = FieldFlags::augment_args(clap::Command::new("t").no_binary_name(true));
        let m = cmd.try_get_matches_from(args).map_err(|e| e.to_string())?;
        Ok(Value::Object(FieldFlags::from_arg_matches(&m).unwrap().0))
    }

    #[test]
    fn every_field_has_a_question_and_a_place_to_look() {
        for f in FIELDS {
            for (what, text) in [("help", f.help), ("question", f.question), ("look", f.look)] {
                assert!(!text.trim().is_empty(), "field `{}` has no {what}", f.name);
            }
            assert!(f.question.contains('?'), "`{}`: ask a question", f.name);
        }
        for (q, does) in FIXED {
            assert!(q.contains('?') && !does.is_empty(), "{q}");
        }
    }

    #[test]
    fn names_and_flags_are_unique() {
        let mut names: Vec<_> = FIELDS.iter().map(|f| f.name).collect();
        let mut flags: Vec<_> = FIELDS.iter().map(|f| f.flag).collect();
        names.sort();
        names.dedup();
        flags.sort();
        flags.dedup();
        assert_eq!(names.len(), FIELDS.len());
        assert_eq!(flags.len(), FIELDS.len());
    }

    #[test]
    fn flags_become_fields() {
        let got = parse(&[
            "--scope",
            "a",
            "--scope",
            "b",
            "--auth-param",
            "prompt=consent",
            "--api-header",
            "Notion-Version: 2026-03-11",
            "--client-auth",
            "basic",
            "--redirect-port",
            "9000",
            "--redirect-host",
            "127.0.0.1",
            "--device-url",
            "https://x.example/device",
            "--scope-separator",
            ",",
            "--error-field",
            "errors",
            "--identity-body",
            r#"{"query":"{ viewer { name } }"}"#,
            "--setup-step",
            r#"{"title":"T","page":"https://x.example"}"#,
            "--source",
            "https://x.example/docs",
        ])
        .unwrap();
        assert_eq!(
            got,
            json!({
                "scopes": ["a", "b"],
                "auth_params": {"prompt": "consent"},
                "api_headers": {"Notion-Version": "2026-03-11"},
                "client_auth": "basic",
                "redirect_port": 9000,
                "redirect_host": "127.0.0.1",
                "device_url": "https://x.example/device",
                "scope_separator": ",",
                "error_fields": ["errors"],
                "identity_body": {"query": "{ viewer { name } }"},
                "setup": [{"title": "T", "page": "https://x.example"}],
                "sources": ["https://x.example/docs"],
            })
        );
        assert!(
            parse(&["--auth-param", "novalue"])
                .unwrap_err()
                .contains("key=value")
        );
        assert!(
            parse(&["--api-header", "novalue"])
                .unwrap_err()
                .contains("Name: value")
        );
        assert!(parse(&["--redirect-port", "x"]).is_err());
        assert!(
            parse(&["--identity-body", "{"])
                .unwrap_err()
                .contains("JSON")
        );
    }

    #[test]
    fn flag_values_undo_parse() {
        for f in FIELDS {
            let samples: &[&str] = match f.kind {
                Kind::Port => &["8080"],
                Kind::Params => &["a=1", "b=x=y"],
                Kind::Headers => &["X-A: 1", "X-B: two words"],
                Kind::Json => &[r#"{"query":"{ x }"}"#],
                Kind::Steps => &[r#"{"title":"T"}"#, r#"{"title":"U","details":"d"}"#],
                Kind::Choice(w) => &w[..1],
                k if k.repeatable() => &["one", "two"],
                _ => &["it's one"],
            };
            let given: Vec<Value> = samples.iter().map(|s| f.kind.parse(s).unwrap()).collect();
            let v = f.kind.collect(given);
            let again: Vec<Value> = f
                .kind
                .flag_values(&v)
                .iter()
                .map(|s| f.kind.parse(s).unwrap())
                .collect();
            assert_eq!(f.kind.collect(again), v, "{}", f.name);
        }
    }

    #[test]
    fn quoting() {
        assert_eq!(quote("https://a.example/x"), "https://a.example/x");
        assert_eq!(quote(" "), "' '");
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote(""), "''");
    }
}
