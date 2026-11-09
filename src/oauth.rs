//! Authorization-code flow (with PKCE unless the provider turns it off), the
//! code coming back on a loopback redirect or pasted from an https one; refresh;
//! and storing a token the person pasted.
use crate::providers::{Provider, Redirect, TokenBody};
use crate::store::{Client, Store, Token};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

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
}

/// The error for a provider with no stored client, naming the next command.
pub fn no_client(name: &str) -> String {
    format!(
        "no OAuth client for `{name}`; run `sesame setup {name}` for how to register one and store it"
    )
}

pub fn login(name: &str, p: &Provider, opts: &LoginOptions) -> Result<Token, String> {
    let store = Store::open()?;
    let client = store.client(name)?.ok_or_else(|| no_client(name))?;
    let (listener, redirect_uri) = match p.redirect {
        Redirect::Loopback => {
            let listener = TcpListener::bind(("127.0.0.1", p.redirect_port.unwrap_or(0)))
                .map_err(|e| format!("cannot listen for the redirect: {e}"))?;
            let port = listener.local_addr().map_err(|e| e.to_string())?.port();
            (Some(listener), p.redirect_uri(port))
        }
        // `Provider::check` makes https-paste carry a port.
        Redirect::HttpsPaste => (None, p.callback()),
    };
    let verifier = random();
    let state = random();
    let scopes = opts.scopes.clone().unwrap_or_else(|| p.scopes.clone());

    let mut url = url::Url::parse(&p.auth_url).map_err(|e| e.to_string())?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", &client.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair(&p.scope_param, &scopes.join(" "))
            .append_pair("state", &state);
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
    if opts.open_browser {
        let _ = open::that_detached(url.as_str());
    }

    let (tx, rx) = mpsc::channel::<String>();
    if let Some(listener) = listener {
        let tx = tx.clone();
        std::thread::spawn(move || listen(listener, tx));
    }
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines().map_while(Result::ok) {
            if line.contains("code=") || line.contains("error=") {
                let _ = tx.send(line.trim().to_string());
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
    let mut token = request_token(p, &client, &mut form, None)?;
    if let Some(resources_url) = &p.resources_url {
        pick_resource(&mut token, resources_url, opts.site.as_deref())?;
    }
    store.save_token(name, &token)?;
    Ok(token)
}

/// Answers the browser's redirect to the loopback callback and sends its address.
fn listen(listener: TcpListener, tx: mpsc::Sender<String>) {
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
        let _ = tx.send(format!("http://localhost{target}"));
        return;
    }
}

/// `sesame login --token`: stores a token the person got another way. It has
/// no refresh token and no expiry: when it stops working, paste a new one.
pub fn save_pasted(name: &str, access_token: &str) -> Result<Token, String> {
    let access_token = access_token.trim();
    if access_token.is_empty() || access_token.contains(char::is_whitespace) {
        return Err("the pasted token is empty or contains spaces".into());
    }
    let token = Token {
        access_token: access_token.into(),
        refresh_token: None,
        expires_at: None,
        scope: None,
        resource_id: None,
        resource_name: None,
        pasted: true,
    };
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

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
}

fn request_token(
    p: &Provider,
    client: &Client,
    form: &mut Vec<(&str, String)>,
    previous: Option<&Token>,
) -> Result<Token, String> {
    form.push(("client_id", client.client_id.clone()));
    if let Some(s) = &client.client_secret {
        form.push(("client_secret", s.clone()));
    }
    let http = reqwest::blocking::Client::new();
    let req = http.post(&p.token_url).header("Accept", "application/json");
    let req = match p.token_body {
        TokenBody::Form => req.form(form),
        TokenBody::Json => req.json(
            &form
                .iter()
                .cloned()
                .collect::<std::collections::BTreeMap<_, _>>(),
        ),
    };
    let resp = req.send().map_err(|e| format!("token endpoint: {e}"))?;
    let status = resp.status();
    let text = resp.text().map_err(|e| e.to_string())?;
    if !status.is_success() || !body_ok(p, text.as_bytes()) {
        return Err(format!("token endpoint answered {status}: {text}"));
    }
    let body: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("token response: {e}: {text}"))?;
    let at = body
        .pointer(&p.token_path)
        .filter(|v| v.get("access_token").is_some())
        .unwrap_or(&body);
    let t = TokenResponse::deserialize(at).map_err(|e| format!("token response: {e}: {text}"))?;
    let account = p
        .account_path
        .as_deref()
        .and_then(|ptr| body.pointer(ptr))
        .and_then(|v| v.as_str())
        .map(String::from);
    Ok(Token {
        access_token: t.access_token,
        // Providers that do not rotate refresh tokens omit it on refresh.
        refresh_token: t
            .refresh_token
            .or_else(|| previous.and_then(|p| p.refresh_token.clone())),
        expires_at: t.expires_in.map(|s| now() + s),
        scope: t.scope.or_else(|| previous.and_then(|p| p.scope.clone())),
        resource_id: previous.and_then(|p| p.resource_id.clone()),
        resource_name: account.or_else(|| previous.and_then(|p| p.resource_name.clone())),
        pasted: false,
    })
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
    let list: Vec<Resource> = reqwest::blocking::Client::new()
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
        let mut form = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh),
        ];
        let new = request_token(p, &client, &mut form, Some(&token))?;
        store.save_token(name, &new)?;
        Ok(new)
    })
}
