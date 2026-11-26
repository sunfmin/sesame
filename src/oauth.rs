//! Login: the authorization-code flow (with PKCE unless the provider turns it
//! off), the code coming back on a loopback redirect or pasted from an https
//! one; or the device flow (RFC 8628). Plus refresh, and storing a token the
//! person pasted.
use crate::providers::{Provider, Redirect, Target};
use crate::store::{Client, Store, Token};
use crate::wire::{self, Grant, Poll};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
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

/// Whose OAuth client signs in: the person's own, stored with `sesame client`,
/// or the provider's built-in public one (`public_client_id`, no secret).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClientSource {
    User,
    BuiltIn,
}

impl ClientSource {
    pub fn label(self) -> &'static str {
        match self {
            ClientSource::User => "your client",
            ClientSource::BuiltIn => "built-in client",
        }
    }
}

/// The client in force for a provider: the stored one if any, else the
/// built-in public client; `None` when there is neither. The one place that
/// choice is made.
pub fn client(
    store: &Store,
    name: &str,
    p: &Provider,
) -> Result<Option<(Client, ClientSource)>, String> {
    if let Some(c) = store.client(name)? {
        return Ok(Some((c, ClientSource::User)));
    }
    Ok(p.public_client_id.as_ref().map(|id| {
        let c = Client {
            client_id: id.clone(),
            client_secret: None,
        };
        (c, ClientSource::BuiltIn)
    }))
}

/// The HTTP client for every request sesame makes; some APIs (GitHub) refuse
/// a request without a User-Agent.
pub fn http() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .user_agent(concat!("sesame/", env!("SESAME_VERSION")))
        .build()
        .unwrap_or_default()
}

/// The scopes a token was granted: its response's `scope`, or, where the
/// provider left that out, the scopes login asked for (RFC 6749 §5.1).
/// Split on spaces or commas: providers join them either way (`scope_separator`).
pub fn granted(t: &Token) -> Vec<String> {
    t.scope
        .as_deref()
        .unwrap_or_default()
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// What login asks for by default: the provider's scopes, those the stored
/// token already has, and the service's, each once. Asking again for what was
/// granted keeps it in the new token, which replaces the old one.
fn wanted(t: &Target, granted: &[String]) -> Vec<String> {
    let service = t.service().map(|s| s.scopes.as_slice()).unwrap_or_default();
    let mut all: Vec<String> = Vec::new();
    for s in t.p.scopes.iter().chain(granted).chain(service) {
        if !all.contains(s) {
            all.push(s.clone());
        }
    }
    all
}

/// Signs in to the target's provider: the device flow when the provider has a
/// `device_url` (unless `opts.loopback`), otherwise the authorization-code flow
/// with a loopback redirect. Then picks the site and reads who signed in, and
/// stores the token, the provider's one, in place of the one before.
pub fn login(store: &Store, t: &Target, opts: &LoginOptions) -> Result<Token, String> {
    let (name, p) = (t.provider.as_str(), &t.p);
    let (client, source) = client(store, name, p)?.ok_or_else(|| no_client(name))?;
    if source == ClientSource::BuiltIn && opts.loopback && p.device_url.is_some() {
        return Err(format!(
            "the built-in client of `{name}` signs in only with the device flow; to sign in \
             through the browser, register your own client: `sesame setup {name}`"
        ));
    }
    let before = store.token(name)?.map(|t| granted(&t)).unwrap_or_default();
    let scopes = opts.scopes.clone().unwrap_or_else(|| wanted(t, &before));
    let mut token = match &p.device_url {
        Some(_) if !opts.loopback => device_flow(p, &client, &scopes, opts.open_browser)?,
        _ => loopback_flow(name, p, &client, &scopes, opts.open_browser)?,
    };
    if token.scope.is_none() && !scopes.is_empty() {
        token.scope = Some(scopes.join(" "));
    }
    if let Some(resources_url) = &p.resources_url {
        pick_resource(&mut token, resources_url, opts.site.as_deref())?;
    }
    if let (Some(url), Some(_)) = (&p.identity_url, &p.identity_field) {
        match identify(p, &token, url) {
            Ok(account) => token.account = Some(account),
            Err(e) => eprintln!("Signed in, but could not read who you are: {e}"),
        }
    }
    store.save_token(name, &token)?;
    Ok(token)
}

fn loopback_flow(
    name: &str,
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

    let url = wire::authorize_url(
        p,
        &client.client_id,
        &redirect_uri,
        scopes,
        &state,
        &verifier,
    )?;

    eprintln!("Open this URL to sign in:\n\n  {url}\n");
    let within = match p.code_seconds {
        Some(s) => format!(" within {s} seconds: the code in it expires then"),
        None => String::new(),
    };
    match p.redirect {
        Redirect::Loopback => eprintln!(
            "Waiting for the redirect to {redirect_uri}.\n\
             On another machine than this one? Paste the address the browser ended on here{within}."
        ),
        Redirect::HttpsPaste => eprintln!(
            "After you approve, the browser goes to {redirect_uri}?code=… and says it cannot\n\
             open the page: that is expected. Copy the whole address from its address bar and\n\
             paste it here{within}."
        ),
    }
    if open_browser {
        let _ = open::that_detached(url.as_str());
    }

    let (tx, rx) = mpsc::channel::<String>();
    let tx2 = tx.clone();
    if let Some((listener, port)) = listener {
        let origin = format!("http://{}:{port}", p.redirect_host.as_str());
        let state = state.clone();
        std::thread::spawn(move || listen(listener, &origin, &state, tx));
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

    let grant = Grant::Code {
        code: &code,
        redirect_uri: &redirect_uri,
        verifier: &verifier,
    };
    let (status, text) = post(wire::token_request(p, grant, client)?)?;
    if !status.is_success() {
        return Err(wire::code_refused(name, p, status, &text));
    }
    wire::token_from(p, &text, None, now())
}

/// Answers the browser's redirect to the loopback callback and sends its
/// address, as `origin` and the path, to `tx`. Only a redirect carrying this
/// login's `state` ends the wait; any other request is answered and the
/// listener goes on. A connection silent for `READ_TIMEOUT` is dropped.
fn listen(listener: TcpListener, origin: &str, state: &str, tx: mpsc::Sender<String>) {
    for stream in listener.incoming().flatten() {
        let mut stream = stream;
        let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
        let mut line = String::new();
        if BufReader::new(&stream).read_line(&mut line).is_err() {
            continue;
        }
        let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
        let (status, body, done) = callback_answer(&target, state);
        let _ = write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        if done {
            let _ = tx.send(format!("{origin}{target}"));
            return;
        }
    }
}

/// How long the loopback listener waits for a connection's request line.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

/// The loopback's answer to a request for `target`, while waiting for the
/// redirect carrying `state`: its status, its body, and whether it ends the
/// wait.
fn callback_answer(target: &str, state: &str) -> (&'static str, &'static str, bool) {
    let Ok(u) = url::Url::parse(&format!("http://loopback{target}")) else {
        return ("400 Bad Request", "", false);
    };
    if u.path() != "/callback" {
        return ("404 Not Found", "", false);
    }
    let has = |k: &str| u.query_pairs().any(|(n, _)| n == k);
    if !u.query_pairs().any(|(n, v)| n == "state" && v == state) {
        return (
            "400 Bad Request",
            "This redirect is not from the login sesame is waiting for (its state differs). \
             Finish signing in from the URL sesame printed.",
            false,
        );
    }
    if has("error") {
        return (
            "200 OK",
            "The provider refused the sign-in. See the terminal for its reason.",
            true,
        );
    }
    if !has("code") {
        return ("400 Bad Request", "This redirect carried no code.", false);
    }
    (
        "200 OK",
        "Signed in. You can close this tab and return to the terminal.",
        true,
    )
}

/// The device authorization grant (RFC 8628): the person enters a code on the
/// provider's page while sesame polls the token endpoint.
fn device_flow(
    p: &Provider,
    client: &Client,
    scopes: &[String],
    open_browser: bool,
) -> Result<Token, String> {
    let (status, text) = post(wire::token_request(p, Grant::Device(scopes), client)?)?;
    let (d, expires_at, mut interval) = wire::device_code(status, now(), &text)?;
    eprintln!(
        "To sign in, open {} and enter the code:\n\n  {}\n",
        d.verification_uri, d.user_code
    );
    eprintln!("Waiting for you to approve access there.");
    if open_browser {
        let _ = open::that_detached(d.page());
    }

    loop {
        std::thread::sleep(Duration::from_secs(interval));
        let poll = wire::token_request(p, Grant::DeviceCode(&d.device_code), client)?;
        let (status, text) = post(poll)?;
        match wire::device_poll(p, status, &text, interval, now(), expires_at)? {
            Poll::Token(t) => return Ok(t),
            Poll::Again(next) => interval = next,
        }
    }
}

/// Who signed in: the provider's `identity_url` answer, read as `wire::identity_from` says.
fn identify(p: &Provider, token: &Token, url: &str) -> Result<String, String> {
    let req = match &p.identity_body {
        Some(b) => http().post(url).json(b),
        None => http().get(url),
    };
    let bytes = req
        .bearer_auth(&token.access_token)
        .header("Accept", "application/json")
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.bytes())
        .map_err(|e| format!("{url}: {e}"))?;
    wire::identity_from(p, &bytes)
}

/// Sends a request `wire` built; the answer's status and text.
fn post(r: wire::Request) -> Result<(reqwest::StatusCode, String), String> {
    let mut req = http().post(&r.url).body(r.body);
    for (k, v) in r.headers {
        req = req.header(k, v);
    }
    let resp = req.send().map_err(|e| format!("{}: {e}", r.url))?;
    let status = resp.status();
    let text = resp.text().map_err(|e| e.to_string())?;
    Ok((status, text))
}

/// `sesame login --token`: stores a token the person got another way. It has
/// no refresh token and no expiry: when it stops working, paste a new one.
/// Who it belongs to is read from `identity_url`, as after a login.
pub fn save_pasted(
    store: &Store,
    name: &str,
    p: &Provider,
    access_token: &str,
) -> Result<Token, String> {
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
    if let (Some(url), Some(_)) = (&p.identity_url, &p.identity_field) {
        match identify(p, &token, url) {
            Ok(account) => token.account = Some(account),
            Err(e) => eprintln!("Stored, but could not read who the token belongs to: {e}"),
        }
    }
    store.save_token(name, &token)?;
    Ok(token)
}

fn pick_resource(token: &mut Token, url: &str, site: Option<&str>) -> Result<(), String> {
    let bytes = http()
        .get(url)
        .bearer_auth(&token.access_token)
        .header("Accept", "application/json")
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.bytes())
        .map_err(|e| format!("listing sites: {e}"))?;
    let (chosen, others) = wire::pick_site(&bytes, site)?;
    if others {
        eprintln!(
            "Using site {} ({}); pick another with --site.",
            chosen.name, chosen.url
        );
    }
    token.resource_id = Some(chosen.id);
    token.resource_name = Some(chosen.name);
    Ok(())
}

/// Trades `refresh_token`, `token`'s, at the provider's refresh endpoint for
/// a new token, which keeps what the answer leaves out from `token`.
pub fn refresh(
    store: &Store,
    name: &str,
    p: &Provider,
    token: &Token,
    refresh_token: String,
) -> Result<Token, String> {
    let (client, _) = client(store, name, p)?.ok_or_else(|| no_client(name))?;
    let grant = Grant::Refresh(&refresh_token);
    let (status, text) = post(wire::token_request(p, grant, &client)?)?;
    if !status.is_success() {
        return Err(format!(
            "refresh endpoint answered {status}: {text}\nRun `sesame login {name}` again."
        ));
    }
    wire::token_from(p, &text, Some(token), now())
}
