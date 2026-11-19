//! A provider's wire rules: what the fields of a `Provider` mean in the
//! requests sesame sends and the answers it reads. The authorization URL; a
//! request to the token or device endpoint and the token in its answer (or
//! why it refused); who signed in and which site a login reached; and the
//! URL, headers and failure signs of an API call. Nothing here sends: oauth.rs
//! and api.rs send what this builds and hand back what came, so each
//! provider's quirks are rows of this module's tests.
use crate::providers::{ClientAuth, Provider, TokenBody};
use crate::store::{Client, Token};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The authorization URL a loopback or https-paste login opens: the scopes in
/// `scope_param` joined by `scope_separator`, PKCE's challenge for `verifier`
/// unless `pkce` is off, then `auth_params`.
pub fn authorize_url(
    p: &Provider,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
    state: &str,
    verifier: &str,
) -> Result<url::Url, String> {
    let mut url = url::Url::parse(&p.auth_url).map_err(|e| e.to_string())?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri);
        if !scopes.is_empty() {
            q.append_pair(&p.scope_param, &scopes.join(&p.scope_separator));
        }
        q.append_pair("state", state);
        if p.pkce {
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            q.append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256");
        }
        for (k, v) in &p.auth_params {
            q.append_pair(k, v);
        }
    }
    Ok(url)
}

/// What a request to one of the provider's OAuth endpoints asks for.
pub enum Grant<'a> {
    /// The authorization code that came back on `redirect_uri`; `verifier`
    /// is PKCE's, sent when the provider's `pkce` is on.
    Code {
        code: &'a str,
        redirect_uri: &'a str,
        verifier: &'a str,
    },
    /// A new token for this refresh token.
    Refresh(&'a str),
    /// A device code for these scopes (RFC 8628), from `device_url`.
    Device(&'a [String]),
    /// The token for this device code, once the person approved it.
    DeviceCode(&'a str),
}

/// A POST to send as it is: its URL, headers and body.
#[derive(Debug, PartialEq)]
pub struct Request {
    pub url: String,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

/// The POST for `grant`: to the token endpoint (a refresh to `refresh_url`
/// when there is one, a device code request to `device_url`), in the
/// `token_body` encoding, asking for JSON, the client authenticated as
/// `client_auth` says (a device code request names it, nothing more).
pub fn token_request(p: &Provider, grant: Grant, client: &Client) -> Result<Request, String> {
    let s = String::from;
    let (url, mut form, authenticated) = match grant {
        Grant::Code {
            code,
            redirect_uri,
            verifier,
        } => {
            let mut form = vec![
                ("grant_type", s("authorization_code")),
                ("code", s(code)),
                ("redirect_uri", s(redirect_uri)),
            ];
            if p.pkce {
                form.push(("code_verifier", s(verifier)));
            }
            (&p.token_url, form, true)
        }
        Grant::Refresh(r) => {
            let form = vec![("grant_type", s("refresh_token")), ("refresh_token", s(r))];
            (p.refresh_url.as_ref().unwrap_or(&p.token_url), form, true)
        }
        Grant::Device(scopes) => {
            let url = p
                .device_url
                .as_ref()
                .ok_or("the provider has no device_url")?;
            let mut form = vec![("client_id", client.client_id.clone())];
            if !scopes.is_empty() {
                form.push(("scope", scopes.join(&p.scope_separator)));
            }
            (url, form, false)
        }
        Grant::DeviceCode(code) => {
            let form = vec![
                (
                    "grant_type",
                    s("urn:ietf:params:oauth:grant-type:device_code"),
                ),
                ("device_code", s(code)),
            ];
            (&p.token_url, form, true)
        }
    };
    let mut headers = vec![("Accept", s("application/json"))];
    match (authenticated, p.client_auth) {
        (false, _) => {}
        (true, ClientAuth::Body) => {
            form.push(("client_id", client.client_id.clone()));
            if let Some(secret) = &client.client_secret {
                form.push(("client_secret", secret.clone()));
            }
        }
        (true, ClientAuth::Basic) => {
            let secret = client.client_secret.as_deref().unwrap_or_default();
            let pair = format!("{}:{secret}", client.client_id);
            headers.push(("Authorization", format!("Basic {}", STANDARD.encode(pair))));
        }
    }
    let (content_type, body) = match p.token_body {
        TokenBody::Form => {
            let body = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&form)
                .finish();
            ("application/x-www-form-urlencoded", body.into_bytes())
        }
        TokenBody::Json => {
            let map: BTreeMap<_, _> = form.into_iter().collect();
            let body = serde_json::to_vec(&map).map_err(|e| e.to_string())?;
            ("application/json", body)
        }
    };
    headers.push(("Content-Type", s(content_type)));
    Ok(Request {
        url: url.clone(),
        headers,
        body,
    })
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
}

/// The token in a token endpoint's 2xx answer, at Unix time `now`: at
/// `token_path`, or at the top level when nothing with an `access_token` is
/// there (a Slack refresh); the site named by `site_name_field`. What the
/// answer leaves out (a refresh token that does not rotate, the scope, the
/// site, the account) is kept from `previous`, the token a refresh replaces.
pub fn token_from(
    p: &Provider,
    text: &str,
    previous: Option<&Token>,
    now: u64,
) -> Result<Token, String> {
    if let Some(f) = error_in(p, text.as_bytes()) {
        return Err(format!("token endpoint answered with `{f}`: {text}"));
    }
    let v: Value =
        serde_json::from_str(text).map_err(|e| format!("token response: {e}: {text}"))?;
    let site_name = p
        .site_name_field
        .as_deref()
        .and_then(|f| field(&v, f))
        .and_then(|n| n.as_str())
        .map(String::from);
    let at = v
        .pointer(&p.token_path)
        .filter(|t| t.get("access_token").is_some())
        .unwrap_or(&v);
    let t = TokenResponse::deserialize(at).map_err(|e| format!("token response: {e}: {text}"))?;
    let kept = |f: fn(&Token) -> &Option<String>| previous.and_then(|p| f(p).clone());
    Ok(Token {
        access_token: t.access_token,
        refresh_token: t.refresh_token.or_else(|| kept(|p| &p.refresh_token)),
        expires_at: t.expires_in.map(|s| now + s),
        scope: t.scope.or_else(|| kept(|p| &p.scope)),
        resource_id: kept(|p| &p.resource_id),
        resource_name: site_name.or_else(|| kept(|p| &p.resource_name)),
        account: kept(|p| &p.account),
        pasted: false,
    })
}

/// `f` of `v`: a JSON pointer when it starts with `/`, else a top-level field.
fn field<'a>(v: &'a Value, f: &str) -> Option<&'a Value> {
    match f.starts_with('/') {
        true => v.pointer(f),
        false => v.get(f),
    }
}

/// The error for a refused code exchange. An `invalid_grant`, or any 4xx from a
/// provider whose code lasts only seconds, most likely means the code expired.
pub fn code_refused(name: &str, p: &Provider, status: StatusCode, text: &str) -> String {
    let mut e = format!("token endpoint answered {status}: {text}");
    if text.contains("invalid_grant") || (p.code_seconds.is_some() && status.is_client_error()) {
        let lasts = match p.code_seconds {
            Some(s) => format!(" (it lasts {s} seconds)"),
            None => String::new(),
        };
        e.push_str(&format!(
            "\nThe authorization code most likely expired{lasts}; run `sesame login {name}` again."
        ));
    }
    e
}

/// What a poll of the token endpoint with a device code says.
#[derive(Debug, PartialEq)]
pub enum Poll {
    /// Approved: the token.
    Token(Token),
    /// Not yet: poll again after these seconds.
    Again(u64),
}

/// Reads a device-code poll's answer (RFC 8628 §3.5), polled every `interval`
/// seconds so far. A pending or slowed answer may come as a 400 or, as
/// GitHub's does, as a 200.
pub fn device_poll(
    p: &Provider,
    status: StatusCode,
    text: &str,
    interval: u64,
    now: u64,
) -> Result<Poll, String> {
    let v: Value = serde_json::from_str(text).unwrap_or_default();
    match v.get("error").and_then(|e| e.as_str()) {
        None if status.is_success() => token_from(p, text, None, now).map(Poll::Token),
        None => Err(format!("token endpoint answered {status}: {text}")),
        Some("authorization_pending") => Ok(Poll::Again(interval)),
        // The provider may name the new interval (GitHub does); else 5s more.
        Some("slow_down") => Ok(Poll::Again(
            v.get("interval")
                .and_then(|i| i.as_u64())
                .unwrap_or(interval + 5),
        )),
        Some("expired_token" | "token_expired") => {
            Err("the code expired before access was approved; run login again".into())
        }
        Some("access_denied") => Err("access was denied on the provider's page".into()),
        Some(e) => {
            let detail = v
                .get("error_description")
                .and_then(|d| d.as_str())
                .unwrap_or_default();
            Err(format!("provider refused: {e} {detail}"))
        }
    }
}

/// The account in `identity_url`'s 2xx answer: its `identity_field`, a JSON
/// pointer when it starts with `/`; a number is read as its digits.
pub fn identity_from(p: &Provider, bytes: &[u8]) -> Result<String, String> {
    let url = p.identity_url.as_deref().unwrap_or_default();
    let name = p.identity_field.as_deref().unwrap_or_default();
    if let Some(f) = error_in(p, bytes) {
        let text = String::from_utf8_lossy(bytes);
        return Err(format!("{url} answered with `{f}`: {text}"));
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("{url}: {e}"))?;
    match field(&v, name) {
        Some(Value::String(s)) => Ok(s.clone()),
        None | Some(Value::Null) => Err(format!("{url} has no `{name}`")),
        Some(other) => Ok(other.to_string()),
    }
}

/// One site a token reaches, in `resources_url`'s answer.
#[derive(Debug, Deserialize, PartialEq)]
pub struct Site {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub url: String,
}

/// The site a login keeps from `resources_url`'s answer: the one `site` names
/// (by name, id or part of its URL), else the first. With it, whether there
/// were others to pick with `--site`.
pub fn pick_site(bytes: &[u8], site: Option<&str>) -> Result<(Site, bool), String> {
    let mut list: Vec<Site> =
        serde_json::from_slice(bytes).map_err(|e| format!("listing sites: {e}"))?;
    let others = site.is_none() && list.len() > 1;
    let at = match site {
        Some(s) => list
            .iter()
            .position(|r| r.name == s || r.url.contains(s) || r.id == s),
        None => (!list.is_empty()).then_some(0),
    };
    match at {
        Some(i) => Ok((list.swap_remove(i), others)),
        None => {
            let names: Vec<_> = list
                .iter()
                .map(|r| format!("{} ({})", r.name, r.url))
                .collect();
            Err(format!(
                "no matching site; this login reaches: {}",
                names.join(", ")
            ))
        }
    }
}

/// The URL an API call goes to: `path` under `api_base` (its `{resource_id}`
/// the site picked at login), or a full URL; refused unless its host is one
/// of the provider's `hosts`, the only ones the token goes to.
pub fn api_url(
    api_base: &str,
    p: &Provider,
    token: &Token,
    path: &str,
) -> Result<url::Url, String> {
    let url = if path.starts_with("https://") || path.starts_with("http://") {
        url::Url::parse(path).map_err(|e| e.to_string())?
    } else {
        let mut base = api_base.to_string();
        if base.contains("{resource_id}") {
            let id = token
                .resource_id
                .as_deref()
                .ok_or("no site stored: log in again, or give a full URL")?;
            base = base.replace("{resource_id}", id);
        }
        let sep = if path.starts_with('/') { "" } else { "/" };
        url::Url::parse(&format!("{}{sep}{path}", base.trim_end_matches('/')))
            .map_err(|e| e.to_string())?
    };
    let host = url.host_str().unwrap_or("");
    if !allows_host(p, host) {
        return Err(format!(
            "refusing to send the token to {host}: not one of {:?}",
            p.hosts
        ));
    }
    Ok(url)
}

/// Whether the token may go to `host`: one of `hosts`, where `*.example.com`
/// matches its subdomains and itself.
pub fn allows_host(p: &Provider, host: &str) -> bool {
    p.hosts.iter().any(|h| match h.strip_prefix("*.") {
        Some(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
        None => host == h,
    })
}

/// The headers of an API call, besides its token: the `-H Name: value`
/// given, then each of `api_headers` not given (any case), then, with a body
/// and no Content-Type given, JSON's.
pub fn api_headers(
    p: &Provider,
    given: &[String],
    has_body: bool,
) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for h in given {
        let (k, v) = h
            .split_once(':')
            .ok_or_else(|| format!("header `{h}` has no `:`"))?;
        out.push((k.trim().to_string(), v.trim().to_string()));
    }
    let is_given = |name: &str| given_name(&out[..], name);
    let fixed: Vec<_> = p
        .api_headers
        .iter()
        .filter(|(k, _)| !is_given(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let typed = is_given("content-type");
    out.extend(fixed);
    if has_body && !typed {
        out.push(("Content-Type".into(), "application/json".into()));
    }
    Ok(out)
}

fn given_name(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
}

/// A 403 for a token that lacks a scope: RFC 6750's `insufficient_scope`
/// challenge, or Google's `insufficientPermissions` / `ACCESS_TOKEN_SCOPE_INSUFFICIENT`.
pub fn lacks_scope(challenge: &str, body: &[u8]) -> bool {
    let body = String::from_utf8_lossy(body);
    challenge.contains("insufficient_scope")
        || ["insufficientPermissions", "ACCESS_TOKEN_SCOPE_INSUFFICIENT"]
            .iter()
            .any(|m| body.contains(m))
}

/// The first of `error_fields` a 2xx JSON answer carries with a value that
/// is not empty (`null`, `false`, `""`, `[]` and `{}` are empty).
pub fn error_in<'a>(p: &'a Provider, body: &[u8]) -> Option<&'a str> {
    let v: Value = serde_json::from_slice(body).ok()?;
    p.error_fields
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::built_in;
    use serde_json::json;

    const NOW: u64 = 1_000_000;

    fn client(secret: Option<&str>) -> Client {
        Client {
            client_id: "cid".into(),
            client_secret: secret.map(String::from),
        }
    }

    fn token(access: &str) -> Token {
        Token {
            access_token: access.into(),
            refresh_token: None,
            expires_at: None,
            scope: None,
            resource_id: None,
            resource_name: None,
            account: None,
            pasted: false,
        }
    }

    /// The token a refresh replaces: everything an answer may leave out.
    fn previous() -> Token {
        Token {
            refresh_token: Some("refresh-1".into()),
            scope: Some("read".into()),
            resource_id: Some("site-1".into()),
            resource_name: Some("Acme".into()),
            account: Some("felix".into()),
            ..token("access-1")
        }
    }

    fn header<'a>(r: &'a Request, name: &str) -> Option<&'a str> {
        r.headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }

    fn form(r: &Request) -> BTreeMap<String, String> {
        url::form_urlencoded::parse(&r.body).into_owned().collect()
    }

    fn query(u: &url::Url, k: &str) -> Option<String> {
        u.query_pairs()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.into_owned())
    }

    fn authorize(name: &str, scopes: &[&str]) -> url::Url {
        let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
        authorize_url(
            &built_in(name),
            "cid",
            "http://localhost:1/callback",
            &scopes,
            "st",
            "ver",
        )
        .unwrap()
    }

    #[test]
    fn authorize_url_carries_scopes_pkce_and_params() {
        let u = authorize("github", &["repo", "read:org"]);
        assert_eq!(query(&u, "scope").as_deref(), Some("repo read:org"));
        assert_eq!(query(&u, "state").as_deref(), Some("st"));
        assert_eq!(query(&u, "client_id").as_deref(), Some("cid"));
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(b"ver"));
        assert_eq!(query(&u, "code_challenge"), Some(challenge));
        assert_eq!(query(&u, "code_challenge_method").as_deref(), Some("S256"));
        // Slack: user scopes, comma-joined, and no PKCE.
        let u = authorize("slack", &["channels:read", "chat:write"]);
        assert_eq!(
            query(&u, "user_scope").as_deref(),
            Some("channels:read,chat:write")
        );
        assert_eq!(query(&u, "scope"), None);
        assert_eq!(query(&u, "code_challenge"), None);
        // Linear: comma-joined.
        let u = authorize("linear", &["read", "write"]);
        assert_eq!(query(&u, "scope").as_deref(), Some("read,write"));
        // Notion: no scopes at all, and `owner=user`.
        let u = authorize("notion", &[]);
        assert_eq!(query(&u, "scope"), None);
        assert_eq!(query(&u, "owner").as_deref(), Some("user"));
        // Jira: Atlassian's audience and consent prompt.
        let u = authorize("jira", &["read:jira-work"]);
        assert_eq!(query(&u, "audience").as_deref(), Some("api.atlassian.com"));
        assert_eq!(query(&u, "prompt").as_deref(), Some("consent"));
    }

    fn code() -> Grant<'static> {
        Grant::Code {
            code: "the-code",
            redirect_uri: "http://localhost:1/callback",
            verifier: "ver",
        }
    }

    #[test]
    fn code_exchange_by_client_auth_and_token_body() {
        // HubSpot (and the default): a form, the client in it, no Basic.
        let r = token_request(&built_in("hubspot"), code(), &client(Some("sec"))).unwrap();
        assert_eq!(r.url, "https://api.hubspot.com/oauth/v3/token");
        assert_eq!(header(&r, "Authorization"), None);
        assert_eq!(header(&r, "Accept"), Some("application/json"));
        assert_eq!(
            header(&r, "Content-Type"),
            Some("application/x-www-form-urlencoded")
        );
        let f = form(&r);
        for (k, v) in [
            ("grant_type", "authorization_code"),
            ("code", "the-code"),
            ("redirect_uri", "http://localhost:1/callback"),
            ("code_verifier", "ver"),
            ("client_id", "cid"),
            ("client_secret", "sec"),
        ] {
            assert_eq!(f.get(k).map(String::as_str), Some(v), "{k}: {f:?}");
        }
        // A public client: its id, no secret.
        let f = form(&token_request(&built_in("github"), code(), &client(None)).unwrap());
        assert_eq!(f.get("client_id").map(String::as_str), Some("cid"));
        assert!(!f.contains_key("client_secret"), "{f:?}");
        // Notion: HTTP Basic and a JSON body without the client.
        let r = token_request(&built_in("notion"), code(), &client(Some("the-secret"))).unwrap();
        assert_eq!(
            header(&r, "Authorization"),
            Some("Basic Y2lkOnRoZS1zZWNyZXQ=")
        );
        assert_eq!(header(&r, "Content-Type"), Some("application/json"));
        let b: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(
            b,
            json!({"grant_type": "authorization_code", "code": "the-code",
                   "redirect_uri": "http://localhost:1/callback", "code_verifier": "ver"})
        );
        // Figma: HTTP Basic, a form without the client.
        let r = token_request(&built_in("figma"), code(), &client(Some("the-secret"))).unwrap();
        assert_eq!(
            header(&r, "Authorization"),
            Some("Basic Y2lkOnRoZS1zZWNyZXQ=")
        );
        let f = form(&r);
        assert!(!f.contains_key("client_id") && !f.contains_key("client_secret"));
        // Slack: no PKCE, so no verifier.
        let f = form(&token_request(&built_in("slack"), code(), &client(Some("s"))).unwrap());
        assert!(!f.contains_key("code_verifier"), "{f:?}");
    }

    #[test]
    fn refresh_goes_to_the_refresh_endpoint() {
        let grant = || Grant::Refresh("refresh-1");
        // Figma: its own endpoint, HTTP Basic.
        let r = token_request(&built_in("figma"), grant(), &client(Some("the-secret"))).unwrap();
        assert_eq!(r.url, "https://api.figma.com/v1/oauth/refresh");
        assert_eq!(
            header(&r, "Authorization"),
            Some("Basic Y2lkOnRoZS1zZWNyZXQ=")
        );
        let f = form(&r);
        assert_eq!(
            f.get("grant_type").map(String::as_str),
            Some("refresh_token")
        );
        assert_eq!(
            f.get("refresh_token").map(String::as_str),
            Some("refresh-1")
        );
        assert!(!f.contains_key("client_secret"));
        // HubSpot: the token endpoint, the client in the body.
        let r = token_request(&built_in("hubspot"), grant(), &client(Some("sec"))).unwrap();
        assert_eq!(r.url, "https://api.hubspot.com/oauth/v3/token");
        let f = form(&r);
        assert_eq!(f.get("client_secret").map(String::as_str), Some("sec"));
        assert_eq!(header(&r, "Authorization"), None);
        // Notion: JSON.
        let r = token_request(&built_in("notion"), grant(), &client(Some("s"))).unwrap();
        let b: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(
            b,
            json!({"grant_type": "refresh_token", "refresh_token": "refresh-1"})
        );
    }

    #[test]
    fn device_requests() {
        let p = built_in("github");
        let scopes = vec!["repo".to_string(), "gist".to_string()];
        let r = token_request(&p, Grant::Device(&scopes), &client(Some("sec"))).unwrap();
        assert_eq!(r.url, "https://github.com/login/device/code");
        let f = form(&r);
        assert_eq!(f.get("client_id").map(String::as_str), Some("cid"));
        assert_eq!(f.get("scope").map(String::as_str), Some("repo gist"));
        assert!(!f.contains_key("client_secret"), "only the id: {f:?}");
        let r = token_request(&p, Grant::Device(&[]), &client(None)).unwrap();
        assert!(!form(&r).contains_key("scope"));
        let r = token_request(&p, Grant::DeviceCode("dev"), &client(None)).unwrap();
        assert_eq!(r.url, "https://github.com/login/oauth/access_token");
        let f = form(&r);
        assert_eq!(
            f.get("grant_type").map(String::as_str),
            Some("urn:ietf:params:oauth:grant-type:device_code")
        );
        assert_eq!(f.get("device_code").map(String::as_str), Some("dev"));
        let e = token_request(&built_in("google"), Grant::Device(&[]), &client(None));
        assert!(e.unwrap_err().contains("no device_url"));
    }

    #[test]
    fn token_from_a_code_exchange() {
        let t = token_from(
            &built_in("github"),
            r#"{"access_token":"a","refresh_token":"r","expires_in":3600,"scope":"repo"}"#,
            None,
            NOW,
        )
        .unwrap();
        assert_eq!(
            t,
            Token {
                refresh_token: Some("r".into()),
                expires_at: Some(NOW + 3600),
                scope: Some("repo".into()),
                ..token("a")
            }
        );
        // Slack: the user's token under `authed_user`, next to the bot's; the
        // team's name nested.
        let t = token_from(
            &built_in("slack"),
            r#"{"ok":true,"access_token":"xoxb-bot","team":{"id":"T1","name":"Acme"},
                "authed_user":{"id":"U1","access_token":"xoxp-1","scope":"chat:write"}}"#,
            None,
            NOW,
        )
        .unwrap();
        assert_eq!(t.access_token, "xoxp-1");
        assert_eq!(t.scope.as_deref(), Some("chat:write"));
        assert_eq!(t.resource_name.as_deref(), Some("Acme"));
        // Notion: the workspace's name at the top level.
        let t = token_from(
            &built_in("notion"),
            r#"{"access_token":"a","refresh_token":"r","workspace_name":"Acme Space"}"#,
            None,
            NOW,
        )
        .unwrap();
        assert_eq!(t.resource_name.as_deref(), Some("Acme Space"));
        assert_eq!(t.expires_at, None);
    }

    #[test]
    fn token_from_a_refresh_keeps_what_it_leaves_out() {
        // Figma: no refresh token in the answer; the old one is kept.
        let t = token_from(
            &built_in("figma"),
            r#"{"access_token":"access-2","token_type":"bearer","expires_in":7776000}"#,
            Some(&previous()),
            NOW,
        )
        .unwrap();
        assert_eq!(
            t,
            Token {
                expires_at: Some(NOW + 7776000),
                ..previous().with_access("access-2")
            }
        );
        // Notion, Linear, HubSpot: a rotated refresh token replaces the old one.
        for name in ["notion", "linear", "hubspot"] {
            let t = token_from(
                &built_in(name),
                r#"{"access_token":"access-2","refresh_token":"refresh-2","scope":"read,write"}"#,
                Some(&previous()),
                NOW,
            )
            .unwrap();
            assert_eq!(t.refresh_token.as_deref(), Some("refresh-2"), "{name}");
            assert_eq!(t.scope.as_deref(), Some("read,write"), "{name}");
            assert_eq!(t.account.as_deref(), Some("felix"), "{name}");
        }
        // Slack: a refresh answers at the top level, without `authed_user`.
        let t = token_from(
            &built_in("slack"),
            r#"{"ok":true,"access_token":"xoxe-2","refresh_token":"r2","expires_in":43200}"#,
            Some(&previous()),
            NOW,
        )
        .unwrap();
        assert_eq!(t.access_token, "xoxe-2");
        assert_eq!(t.resource_name.as_deref(), Some("Acme"));
    }

    #[test]
    fn token_from_refusals() {
        // Slack fails with a 200 and `ok: false`.
        let e = token_from(
            &built_in("slack"),
            r#"{"ok":false,"error":"invalid_code"}"#,
            None,
            NOW,
        )
        .unwrap_err();
        assert!(e.contains("answered with `error`"), "{e}");
        let e = token_from(&built_in("github"), "<html>", None, NOW).unwrap_err();
        assert!(e.starts_with("token response:"), "{e}");
        let e = token_from(&built_in("github"), r#"{"token":"x"}"#, None, NOW).unwrap_err();
        assert!(e.contains("access_token"), "{e}");
    }

    #[test]
    fn a_refused_code_most_likely_expired() {
        let bad = StatusCode::BAD_REQUEST;
        // Figma: any 4xx, and its code lasts 30 seconds.
        let e = code_refused("figma", &built_in("figma"), bad, r#"{"error":true}"#);
        assert!(
            e.ends_with(
                "most likely expired (it lasts 30 seconds); run `sesame login figma` again."
            ),
            "{e}"
        );
        let e = code_refused(
            "github",
            &built_in("github"),
            bad,
            r#"{"error":"invalid_grant"}"#,
        );
        assert!(
            e.ends_with("most likely expired; run `sesame login github` again."),
            "{e}"
        );
        let e = code_refused("github", &built_in("github"), bad, r#"{"error":"nope"}"#);
        assert_eq!(
            e,
            r#"token endpoint answered 400 Bad Request: {"error":"nope"}"#
        );
        let e = code_refused("figma", &built_in("figma"), StatusCode::BAD_GATEWAY, "x");
        assert!(!e.contains("expired"), "{e}");
    }

    #[test]
    fn device_poll_answers() {
        let p = built_in("github");
        let poll = |status, text: &str| device_poll(&p, status, text, 5, NOW);
        let (ok, bad) = (StatusCode::OK, StatusCode::BAD_REQUEST);
        assert_eq!(
            poll(bad, r#"{"error":"authorization_pending"}"#),
            Ok(Poll::Again(5))
        );
        // GitHub answers 200 with the error, and names the new interval.
        assert_eq!(
            poll(ok, r#"{"error":"slow_down","interval":10}"#),
            Ok(Poll::Again(10))
        );
        assert_eq!(poll(bad, r#"{"error":"slow_down"}"#), Ok(Poll::Again(10)));
        assert_eq!(
            poll(ok, r#"{"access_token":"t","scope":"repo"}"#),
            Ok(Poll::Token(Token {
                scope: Some("repo".into()),
                ..token("t")
            }))
        );
        for (text, want) in [
            (r#"{"error":"expired_token"}"#, "the code expired"),
            (r#"{"error":"token_expired"}"#, "the code expired"),
            (r#"{"error":"access_denied"}"#, "access was denied"),
            (
                r#"{"error":"bad","error_description":"why"}"#,
                "provider refused: bad why",
            ),
            ("{}", "token endpoint answered 400 Bad Request"),
        ] {
            let e = poll(bad, text).unwrap_err();
            assert!(e.contains(want), "{text}: {e}");
        }
    }

    #[test]
    fn who_signed_in() {
        for (name, answer, account) in [
            ("github", json!({"login": "octo", "id": 1}), "octo"),
            (
                "figma",
                json!({"id": "1", "email": "f@example.com"}),
                "f@example.com",
            ),
            // A JSON pointer into a GraphQL answer.
            (
                "linear",
                json!({"data": {"viewer": {"name": "Felix"}}}),
                "Felix",
            ),
            // A number, read as its digits.
            ("hubspot", json!({"portalId": 247935561}), "247935561"),
            ("slack", json!({"ok": true, "user": "felix"}), "felix"),
        ] {
            let got = identity_from(&built_in(name), answer.to_string().as_bytes());
            assert_eq!(got.as_deref(), Ok(account), "{name}");
        }
        let e = identity_from(
            &built_in("slack"),
            br#"{"ok":false,"error":"invalid_auth"}"#,
        );
        assert!(e.unwrap_err().contains("answered with `error`"));
        let e = identity_from(&built_in("linear"), br#"{"data":null}"#);
        assert!(e.unwrap_err().ends_with("has no `/data/viewer/name`"));
        let e = identity_from(&built_in("github"), br#"{"login":null}"#);
        assert!(e.unwrap_err().ends_with("has no `login`"));
        assert!(identity_from(&built_in("github"), b"<html>").is_err());
        // Linear's is a POST of a GraphQL query.
        assert_eq!(
            built_in("linear").identity_body,
            Some(json!({"query": "{ viewer { name } }"}))
        );
    }

    #[test]
    fn jira_sites() {
        let list = br#"[{"id":"s1","name":"acme","url":"https://acme.atlassian.net"},
                        {"id":"s2","name":"beta","url":"https://beta.atlassian.net"}]"#;
        let (s, others) = pick_site(list, None).unwrap();
        assert_eq!((s.id.as_str(), others), ("s1", true));
        for by in ["beta", "s2", "beta.atlassian"] {
            let (s, others) = pick_site(list, Some(by)).unwrap();
            assert_eq!((s.id.as_str(), others), ("s2", false), "{by}");
        }
        let e = pick_site(list, Some("gamma")).unwrap_err();
        assert!(e.contains("acme (https://acme.atlassian.net), beta"), "{e}");
        let (_, others) = pick_site(br#"[{"id":"s1"}]"#, None).unwrap();
        assert!(!others);
        assert!(pick_site(b"[]", None).is_err());
        assert!(
            pick_site(b"{}", None)
                .unwrap_err()
                .starts_with("listing sites")
        );
        // The site picked goes into the API base.
        let p = built_in("jira");
        let t = Token {
            resource_id: Some("s2".into()),
            ..token("a")
        };
        let u = api_url(&p.api_base, &p, &t, "rest/api/3/myself").unwrap();
        assert_eq!(
            u.as_str(),
            "https://api.atlassian.com/ex/jira/s2/rest/api/3/myself"
        );
        let e = api_url(&p.api_base, &p, &token("a"), "/x").unwrap_err();
        assert!(e.contains("no site stored"), "{e}");
    }

    #[test]
    fn api_urls_go_only_to_the_hosts() {
        let p = built_in("github");
        let t = token("a");
        for (path, want) in [
            ("/user", "https://api.github.com/user"),
            ("user", "https://api.github.com/user"),
            (
                "https://uploads.github.com/x",
                "https://uploads.github.com/x",
            ),
        ] {
            assert_eq!(api_url(&p.api_base, &p, &t, path).unwrap().as_str(), want);
        }
        let e = api_url(&p.api_base, &p, &t, "https://evil.example/steal").unwrap_err();
        assert!(
            e.starts_with("refusing to send the token to evil.example"),
            "{e}"
        );
        let p = built_in("google");
        assert!(allows_host(&p, "docs.googleapis.com"));
        assert!(allows_host(&p, "googleapis.com"));
        assert!(!allows_host(&p, "googleapis.com.evil.com"));
        assert!(!allows_host(&p, "evil.com"));
    }

    #[test]
    fn api_headers_merge() {
        let headers = |name: &str, given: &[&str], body: bool| {
            let given: Vec<String> = given.iter().map(|s| s.to_string()).collect();
            api_headers(&built_in(name), &given, body)
        };
        let pairs = |xs: &[(&str, &str)]| -> Vec<(String, String)> {
            xs.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        // Notion's version header goes on every call, once.
        assert_eq!(
            headers("notion", &[], false),
            Ok(pairs(&[("Notion-Version", "2026-03-11")]))
        );
        // A -H of the same name, in any case, replaces it.
        assert_eq!(
            headers("notion", &["notion-version: 2022-06-28"], false),
            Ok(pairs(&[("notion-version", "2022-06-28")]))
        );
        // A body is JSON unless a -H says otherwise.
        assert_eq!(
            headers("linear", &[], true),
            Ok(pairs(&[("Content-Type", "application/json")]))
        );
        assert_eq!(
            headers("linear", &["content-type: text/plain", "X-A: 1"], true),
            Ok(pairs(&[("content-type", "text/plain"), ("X-A", "1")]))
        );
        assert_eq!(headers("linear", &[], false), Ok(vec![]));
        let e = headers("linear", &["no colon"], false).unwrap_err();
        assert_eq!(e, "header `no colon` has no `:`");
    }

    #[test]
    fn a_403_for_a_missing_scope() {
        assert!(lacks_scope(r#"Bearer error="insufficient_scope""#, b""));
        // Google's two ways of saying it.
        assert!(lacks_scope(
            "",
            br#"{"error":{"errors":[{"reason":"insufficientPermissions"}]}}"#
        ));
        assert!(lacks_scope(
            "",
            br#"{"details":[{"reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT"}]}"#
        ));
        assert!(!lacks_scope("Bearer", br#"{"error":"forbidden"}"#));
    }

    #[test]
    fn error_fields_fail_only_when_not_empty() {
        let p = built_in("linear");
        assert_eq!(
            error_in(&p, br#"{"errors":[{"message":"x"}]}"#),
            Some("errors")
        );
        for ok in [
            &br#"{"data":{}}"#[..],
            br#"{"data":{},"errors":[]}"#,
            br#"{"errors":null}"#,
            br#"{"errors":false}"#,
            br#"{"errors":""}"#,
            br#"{"errors":{}}"#,
            br#"[1]"#,
            b"not json",
        ] {
            assert_eq!(error_in(&p, ok), None, "{}", String::from_utf8_lossy(ok));
        }
        assert_eq!(error_in(&p, br#"{"errors":"x"}"#), Some("errors"));
        assert_eq!(error_in(&p, br#"{"errors":1}"#), Some("errors"));
        assert_eq!(error_in(&built_in("google"), br#"{"errors":[1]}"#), None);
        // Slack: `ok: false` with an `error` code.
        let slack = built_in("slack");
        assert_eq!(
            error_in(&slack, br#"{"ok":false,"error":"channel_not_found"}"#),
            Some("error")
        );
        assert_eq!(error_in(&slack, br#"{"ok":true}"#), None);
    }

    impl Token {
        fn with_access(self, access: &str) -> Token {
            Token {
                access_token: access.into(),
                ..self
            }
        }
    }
}
