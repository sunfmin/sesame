//! Login: the authorization-code flow (with PKCE unless the provider turns it
//! off), the code coming back on a loopback redirect or pasted from an https
//! one; or the device flow (RFC 8628). Plus refresh, and storing a token the
//! person pasted.
use crate::providers::{ClientAuth, Provider, Redirect, TokenBody};
use crate::store::{Client, Store, Token};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random() -> String {
    B64.encode(rand::random::<[u8; 32]>())
}

pub struct LoginOptions {
    pub scopes: Option<Vec<String>>,
    pub open_browser: bool,
    pub site: Option<String>,
    /// Use the loopback redirect even when the provider offers the device flow.
    pub loopback: bool,
}

/// The error for a provider with no stored client, naming the next command.
pub fn no_client(name: &str) -> String {
    format!(
        "no OAuth client for `{name}`; run `sesame setup {name}` for how to register one and store it"
    )
}

/// The HTTP client for every request sesame makes; some APIs (GitHub) refuse
/// a request without a User-Agent.
pub fn http() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .user_agent(concat!("sesame/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_default()
}

/// Signs in: the device flow when the provider has a `device_url` (unless
/// `opts.loopback`), otherwise the authorization-code flow with a loopback
/// redirect. Then picks the site and reads who signed in, and stores the token.
pub fn login(name: &str, p: &Provider, opts: &LoginOptions) -> Result<Token, String> {
    let store = Store::open()?;
    let client = store.client(name)?.ok_or_else(|| no_client(name))?;
    let scopes = opts.scopes.clone().unwrap_or_else(|| p.scopes.clone());
    let mut token = match &p.device_url {
        Some(device_url) if !opts.loopback => {
            device_flow(p, &client, device_url, &scopes, opts.open_browser)?
        }
        _ => loopback_flow(p, &client, &scopes, opts.open_browser)?,
    };
    if let Some(resources_url) = &p.resources_url {
        pick_resource(&mut token, resources_url, opts.site.as_deref())?;
    }
    if let (Some(url), Some(field)) = (&p.identity_url, &p.identity_field) {
        match identify(&token, url, field) {
            Ok(account) => token.account = Some(account),
            Err(e) => eprintln!("Signed in, but could not read who you are: {e}"),
        }
    }
    store.save_token(name, &token)?;
    Ok(token)
}

fn loopback_flow(
    p: &Provider,
    client: &Client,
    scopes: &[String],
    open_browser: bool,
) -> Result<Token, String> {
    let (listener, redirect_uri) = match p.redirect {
        Redirect::Loopback => {
            let listener = TcpListener::bind(("127.0.0.1", p.redirect_port.unwrap_or(0)))
                .map_err(|e| format!("cannot listen for the redirect: {e}"))?;
            let port = listener.local_addr().map_err(|e| e.to_string())?.port();
            (Some((listener, port)), p.redirect_uri(port))
        }
        // `Provider::check` makes https-paste carry a port.
        Redirect::HttpsPaste => (None, p.callback()),
    };
    let verifier = random();
    let state = random();

    let mut url = url::Url::parse(&p.auth_url).map_err(|e| e.to_string())?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", &client.client_id)
            .append_pair("redirect_uri", &redirect_uri);
        if !scopes.is_empty() {
            q.append_pair(&p.scope_param, &scopes.join(" "));
        }
        q.append_pair("state", &state);
        if p.pkce {
            let challenge = B64.encode(Sha256::digest(verifier.as_bytes()));
            q.append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256");
        }
        for (k, v) in &p.auth_params {
            q.append_pair(k, v);
        }
    }

    eprintln!("Open this URL to sign in:\n\n  {url}\n");
    match p.redirect {
        Redirect::Loopback => eprintln!(
            "Waiting for the redirect to {redirect_uri}.\n\
             On another machine than this one? Paste the address the browser ended on here."
        ),
        Redirect::HttpsPaste => eprintln!(
            "After you approve, the browser goes to {redirect_uri}?code=… and says it cannot\n\
             open the page: that is expected. Copy the whole address from its address bar and\n\
             paste it here."
        ),
    }
    if open_browser {
        let _ = open::that_detached(url.as_str());
    }

    let (tx, rx) = mpsc::channel::<String>();
    let tx2 = tx.clone();
    if let Some((listener, port)) = listener {
        let origin = format!("http://{}:{port}", p.redirect_host.as_str());
        std::thread::spawn(move || listen(listener, &origin, tx));
    }
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines().map_while(Result::ok) {
            if line.contains("code=") || line.contains("error=") {
                let _ = tx2.send(line.trim().to_string());
                return;
            }
        }
    });

    let back = rx.recv().map_err(|_| "no redirect arrived".to_string())?;
    let back = url::Url::parse(&back).map_err(|e| format!("not a URL: {e}"))?;
    let param = |k: &str| {
        back.query_pairs()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.into_owned())
    };
    if let Some(err) = param("error") {
        return Err(format!(
            "provider refused: {err} {}",
            param("error_description").unwrap_or_default()
        ));
    }
    if param("state").as_deref() != Some(state.as_str()) {
        return Err("state mismatch: the redirect is not from this login".into());
    }
    let code = param("code").ok_or("redirect carried no code")?;

    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code),
        ("redirect_uri", redirect_uri),
    ];
    if p.pkce {
        form.push(("code_verifier", verifier));
    }
    request_token(p, client, form, None)
}

/// Answers the browser's redirect to the loopback callback and sends its
/// address, as `origin` and the path, to `tx`.
fn listen(listener: TcpListener, origin: &str, tx: mpsc::Sender<String>) {
    for stream in listener.incoming().flatten() {
        let mut stream = stream;
        let mut line = String::new();
        if BufReader::new(&stream).read_line(&mut line).is_err() {
            continue;
        }
        let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
        if !target.starts_with("/callback") {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
            continue;
        }
        let body = "Signed in. You can close this tab and return to the terminal.";
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = tx.send(format!("{origin}{target}"));
        return;
    }
}

/// The device authorization grant (RFC 8628): the person enters a code on the
/// provider's page while sesame polls the token endpoint.
fn device_flow(
    p: &Provider,
    client: &Client,
    device_url: &str,
    scopes: &[String],
    open_browser: bool,
) -> Result<Token, String> {
    #[derive(serde::Deserialize)]
    struct DeviceCode {
        device_code: String,
        user_code: String,
        verification_uri: String,
        verification_uri_complete: Option<String>,
        expires_in: Option<u64>,
        interval: Option<u64>,
    }
    let mut form = vec![("client_id", client.client_id.clone())];
    if !scopes.is_empty() {
        form.push(("scope", scopes.join(" ")));
    }
    let (status, text) = post(p, device_url, form, None)?;
    if !status.is_success() {
        return Err(format!("device endpoint answered {status}: {text}"));
    }
    let d: DeviceCode =
        serde_json::from_str(&text).map_err(|e| format!("device response: {e}: {text}"))?;
    eprintln!(
        "To sign in, open {} and enter the code:\n\n  {}\n",
        d.verification_uri, d.user_code
    );
    eprintln!("Waiting for you to approve access there.");
    if open_browser {
        let page = d
            .verification_uri_complete
            .as_ref()
            .unwrap_or(&d.verification_uri);
        let _ = open::that_detached(page);
    }

    let deadline = now() + d.expires_in.unwrap_or(900);
    let mut interval = d.interval.unwrap_or(5);
    loop {
        std::thread::sleep(Duration::from_secs(interval));
        let form = vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ),
            ("device_code", d.device_code.clone()),
        ];
        let (status, text) = post(p, &p.token_url, form, Some(client))?;
        let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
        match v.get("error").and_then(|e| e.as_str()) {
            None if status.is_success() => return token_from(p, &text, None),
            None => return Err(format!("token endpoint answered {status}: {text}")),
            Some("authorization_pending") => {}
            // The provider may name the new interval (GitHub does); else 5s more.
            Some("slow_down") => {
                interval = v
                    .get("interval")
                    .and_then(|i| i.as_u64())
                    .unwrap_or(interval + 5)
            }
            Some("expired_token" | "token_expired") => {
                return Err("the code expired before access was approved; run login again".into());
            }
            Some("access_denied") => return Err("access was denied on the provider's page".into()),
            Some(e) => {
                let detail = v
                    .get("error_description")
                    .and_then(|d| d.as_str())
                    .unwrap_or_default();
                return Err(format!("provider refused: {e} {detail}"));
            }
        }
        if now() + interval > deadline {
            return Err("the code expired before access was approved; run login again".into());
        }
    }
}

/// Reads `field` of the provider's `identity_url` answer: the account signed in.
fn identify(token: &Token, url: &str, field: &str) -> Result<String, String> {
    let v: serde_json::Value = http()
        .get(url)
        .bearer_auth(&token.access_token)
        .header("Accept", "application/json")
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json())
        .map_err(|e| format!("{url}: {e}"))?;
    match &v[field] {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Null => Err(format!("{url} has no `{field}`")),
        other => Ok(other.to_string()),
    }
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
}

/// POSTs `form` to one of the provider's OAuth endpoints, in its `token_body`
/// encoding, asking for JSON; with `client`, authenticated as its `client_auth` says.
fn post(
    p: &Provider,
    url: &str,
    mut form: Vec<(&str, String)>,
    client: Option<&Client>,
) -> Result<(reqwest::StatusCode, String), String> {
    let mut req = http().post(url).header("Accept", "application/json");
    match (client, p.client_auth) {
        (None, _) => {}
        (Some(c), ClientAuth::Body) => {
            form.push(("client_id", c.client_id.clone()));
            if let Some(s) = &c.client_secret {
                form.push(("client_secret", s.clone()));
            }
        }
        (Some(c), ClientAuth::Basic) => {
            req = req.basic_auth(&c.client_id, c.client_secret.as_ref());
        }
    }
    let req = match p.token_body {
        TokenBody::Form => req.form(&form),
        TokenBody::Json => req.json(
            &form
                .iter()
                .cloned()
                .collect::<std::collections::BTreeMap<_, _>>(),
        ),
    };
    let resp = req.send().map_err(|e| format!("{url}: {e}"))?;
    let status = resp.status();
    let text = resp.text().map_err(|e| e.to_string())?;
    Ok((status, text))
}

fn request_token(
    p: &Provider,
    client: &Client,
    form: Vec<(&str, String)>,
    previous: Option<&Token>,
) -> Result<Token, String> {
    let (status, text) = post(p, &p.token_url, form, Some(client))?;
    if !status.is_success() {
        return Err(format!("token endpoint answered {status}: {text}"));
    }
    token_from(p, &text, previous)
}

/// The token in a token endpoint's answer: at `token_path`, or at the top
/// level when nothing with an `access_token` is there (a Slack refresh).
fn token_from(p: &Provider, text: &str, previous: Option<&Token>) -> Result<Token, String> {
    if !body_ok(p, text.as_bytes()) {
        return Err(format!("token endpoint refused: {text}"));
    }
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("token response: {e}: {text}"))?;
    let site_name = p
        .site_name_field
        .as_deref()
        .and_then(|f| match f.starts_with('/') {
            true => v.pointer(f),
            false => v.get(f),
        })
        .and_then(|n| n.as_str())
        .map(String::from);
    let at = v
        .pointer(&p.token_path)
        .filter(|t| t.get("access_token").is_some())
        .unwrap_or(&v);
    let t = TokenResponse::deserialize(at).map_err(|e| format!("token response: {e}: {text}"))?;
    Ok(Token {
        access_token: t.access_token,
        // Providers that do not rotate refresh tokens omit it on refresh.
        refresh_token: t
            .refresh_token
            .or_else(|| previous.and_then(|p| p.refresh_token.clone())),
        expires_at: t.expires_in.map(|s| now() + s),
        scope: t.scope.or_else(|| previous.and_then(|p| p.scope.clone())),
        resource_id: previous.and_then(|p| p.resource_id.clone()),
        resource_name: site_name.or_else(|| previous.and_then(|p| p.resource_name.clone())),
        account: previous.and_then(|p| p.account.clone()),
        pasted: false,
    })
}

/// `sesame login --token`: stores a token the person got another way. It has
/// no refresh token and no expiry: when it stops working, paste a new one.
/// Who it belongs to is read from `identity_url`, as after a login.
pub fn save_pasted(name: &str, p: &Provider, access_token: &str) -> Result<Token, String> {
    let access_token = access_token.trim();
    if access_token.is_empty() || access_token.contains(char::is_whitespace) {
        return Err("the pasted token is empty or contains spaces".into());
    }
    let mut token = Token {
        access_token: access_token.into(),
        refresh_token: None,
        expires_at: None,
        scope: None,
        resource_id: None,
        resource_name: None,
        account: None,
        pasted: true,
    };
    if let (Some(url), Some(field)) = (&p.identity_url, &p.identity_field) {
        match identify(&token, url, field) {
            Ok(account) => token.account = Some(account),
            Err(e) => eprintln!("Stored, but could not read who the token belongs to: {e}"),
        }
    }
    Store::open()?.save_token(name, &token)?;
    Ok(token)
}

/// `false` when the provider's `ok_field` in a JSON body says the call failed.
pub fn body_ok(p: &Provider, body: &[u8]) -> bool {
    let Some(field) = &p.ok_field else {
        return true;
    };
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get(field).cloned())
        != Some(serde_json::Value::Bool(false))
}

fn pick_resource(token: &mut Token, url: &str, site: Option<&str>) -> Result<(), String> {
    #[derive(serde::Deserialize)]
    struct Resource {
        id: String,
        #[serde(default)]
        name: String,
        #[serde(default)]
        url: String,
    }
    let list: Vec<Resource> = http()
        .get(url)
        .bearer_auth(&token.access_token)
        .header("Accept", "application/json")
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json())
        .map_err(|e| format!("listing sites: {e}"))?;
    let chosen = match site {
        Some(s) => list
            .iter()
            .find(|r| r.name == s || r.url.contains(s) || r.id == s),
        None => list.first(),
    }
    .ok_or_else(|| {
        let names: Vec<_> = list
            .iter()
            .map(|r| format!("{} ({})", r.name, r.url))
            .collect();
        format!("no matching site; this login reaches: {}", names.join(", "))
    })?;
    if site.is_none() && list.len() > 1 {
        eprintln!(
            "Using site {} ({}); pick another with --site.",
            chosen.name, chosen.url
        );
    }
    token.resource_id = Some(chosen.id.clone());
    token.resource_name = Some(chosen.name.clone());
    Ok(())
}

/// The stored token, refreshed first when it expires within a minute (or when forced).
/// The read, the refresh and the write hold the database's lock, so a second
/// process refreshing the same provider waits and then sees the new token.
pub fn valid_token(name: &str, p: &Provider, force_refresh: bool) -> Result<Token, String> {
    Store::open()?.locked(|store| {
        let Some(token) = store.token(name)? else {
            if store.client(name)?.is_none() {
                return Err(no_client(name));
            }
            return Err(format!(
                "not logged in to `{name}`; run `sesame login {name}`"
            ));
        };
        let fresh = token.expires_at.is_none_or(|t| t > now() + 60);
        if fresh && !force_refresh {
            return Ok(token);
        }
        let refresh = token.refresh_token.clone().ok_or_else(|| {
            format!("`{name}` token expired and has no refresh token; run `sesame login {name}`")
        })?;
        let client = store.client(name)?.ok_or_else(|| no_client(name))?;
        let form = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh),
        ];
        let new = request_token(p, &client, form, Some(&token))?;
        store.save_token(name, &new)?;
        Ok(new)
    })
}
