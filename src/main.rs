mod oauth;
mod providers;
mod setup;
mod store;

use clap::{Parser, Subcommand};
use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;
use store::{Client, Store, Token};

const FOR_AI: &str = "\
If you are an AI using sesame for someone:
  1. Run `sesame providers` to see where each provider stands.
  2. For one showing `no client`, run `sesame setup <provider>` and walk the person
     through its steps. Never ask for a client secret or a token in the chat: the
     person runs `sesame client` (or `sesame login --token`) in their own terminal,
     which prompts for it.
  3. Have the person run `sesame login <service>` (or `<provider>`) and approve access
     in the browser themselves. A service (gmail, calendar, ...) shares its provider's
     client and token; logging in to it adds its scopes.
  4. Then call the API: `sesame api <service> <path>`.";

/// Sign in to SaaS APIs from the terminal and call them with the stored token.
#[derive(Parser)]
#[command(name = "sesame", version, before_help = FOR_AI)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List the providers and their services, and whether you are signed in to each.
    Providers,
    /// Add, change, show or remove a provider definition (stored in sesame.db).
    Provider {
        #[command(subcommand)]
        cmd: Box<ProviderCmd>,
    },
    /// Print the steps to register a provider's OAuth app and get to a working login.
    Setup { provider: String },
    /// Store the OAuth client (app) used to sign in to a provider.
    Client {
        provider: String,
        #[arg(long)]
        client_id: String,
        /// Read the client secret from stdin instead of prompting.
        #[arg(long)]
        secret_stdin: bool,
        /// The client has no secret (public client with PKCE).
        #[arg(long, conflicts_with = "secret_stdin")]
        no_secret: bool,
    },
    /// Sign in through the provider's OAuth page and store the token. A provider
    /// with a device endpoint (github) prints a code to enter on its page instead.
    /// For a service (gmail), signs in to its provider asking for the scopes
    /// already granted and the service's: the one token then covers both.
    /// `--token` stores a token you paste instead.
    Login {
        /// A provider, or a service of one.
        provider: String,
        /// Store a token you got another way (e.g. from the provider's app page)
        /// instead of the OAuth login; asks for it with hidden input. It has no
        /// refresh: when it stops working, paste a new one.
        #[arg(long, conflicts_with_all = ["scopes", "no_browser", "browser", "site"])]
        token: bool,
        /// Like --token, reading the token from stdin.
        #[arg(long, conflicts_with_all = ["token", "scopes", "no_browser", "browser", "site"])]
        token_stdin: bool,
        /// Scope to ask for instead of the defaults; repeatable.
        #[arg(long = "scope")]
        scopes: Vec<String>,
        /// Print the URL only; do not try to open a browser.
        #[arg(long)]
        no_browser: bool,
        /// Sign in through the loopback redirect even when the provider offers
        /// the device flow (needs the client secret where the provider does).
        #[arg(long)]
        browser: bool,
        /// Which site to use when the login reaches several (Jira).
        #[arg(long)]
        site: Option<String>,
    },
    /// Forget the stored token.
    Logout { provider: String },
    /// Print a valid access token, refreshing it if needed (for curl and scripts).
    Token { provider: String },
    /// Call the API with the provider's stored token.
    Api {
        /// A provider, or a service of one (`gmail`), whose API base paths are under.
        provider: String,
        /// Path under the API base, or a full URL on one of the provider's hosts.
        path: String,
        #[arg(short = 'X', long)]
        method: Option<String>,
        /// Header `Name: value`; repeatable.
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Request body; `@file` reads a file, `@-` reads stdin. Implies POST.
        #[arg(short = 'd', long)]
        data: Option<String>,
        /// Print the status line and response headers to stderr.
        #[arg(short = 'i', long)]
        include: bool,
    },
}

#[derive(Subcommand)]
enum ProviderCmd {
    /// Add a provider; --auth-url, --token-url, --api-base and --host are required.
    Add {
        name: String,
        #[command(flatten)]
        fields: providers::FieldFlags,
    },
    /// Change a provider's fields; a repeatable flag replaces its whole list.
    /// For a built-in provider only the changed fields are stored: the rest
    /// follows each new sesame version.
    Set {
        name: String,
        #[command(flatten)]
        fields: providers::FieldFlags,
    },
    /// Print the definition in force as JSON, each field marked `built-in`, `user` or `default`.
    Show { name: String },
    /// Remove a provider you added, or your changes to a built-in one.
    Rm { name: String },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sesame: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.cmd {
        Cmd::Providers => {
            let store = Store::open()?;
            for (name, p) in providers::all()? {
                let token = store.token(&name)?;
                let client = store.client(&name)?;
                let (state, next) = match (&client, &token) {
                    (_, Some(t)) => (format!("logged in{}", who(t)), String::new()),
                    (None, None) => ("no client".to_string(), format!("sesame setup {name}")),
                    (Some(_), None) => {
                        ("not logged in".to_string(), format!("sesame login {name}"))
                    }
                };
                let next = if next.is_empty() {
                    next
                } else {
                    format!("next: {next}")
                };
                println!("{name:<12} {state:<24} {next:<28} {}", p.about);
                for (service, svc) in &p.services {
                    let has = token.as_ref().map(oauth::granted).unwrap_or_default();
                    let state = if token.is_some() && svc.scopes.iter().all(|s| has.contains(s)) {
                        "authorized"
                    } else {
                        "not authorized"
                    };
                    let next = match (&client, state) {
                        (Some(_), "not authorized") => format!("next: sesame login {service}"),
                        _ => String::new(),
                    };
                    println!("  {service:<10} {state:<24} {next:<28} {}", svc.about);
                }
            }
        }
        Cmd::Provider { cmd } => match *cmd {
            ProviderCmd::Add { name, fields } => {
                providers::add(&name, fields.fields()?)?;
                eprintln!("Added the provider `{name}`; next: sesame setup {name}");
            }
            ProviderCmd::Set { name, fields } => {
                providers::set(&name, fields.fields()?)?;
                eprintln!(
                    "Changed the provider `{name}`; see it with `sesame provider show {name}`."
                );
            }
            ProviderCmd::Show { name } => {
                let v = providers::show(&name)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
                );
            }
            ProviderCmd::Rm { name } => eprintln!("{}", providers::remove(&name)?),
        },
        Cmd::Setup { provider } => {
            let t = providers::find(&provider)?;
            print!("{}", setup::render(&t.provider, &t.p));
        }
        Cmd::Client {
            provider,
            client_id,
            secret_stdin,
            no_secret,
        } => {
            let provider = providers::find(&provider)?.provider;
            let client_secret = if no_secret {
                None
            } else if secret_stdin {
                let mut s = String::new();
                std::io::stdin()
                    .read_to_string(&mut s)
                    .map_err(|e| e.to_string())?;
                Some(s.trim().to_string())
            } else {
                Some(rpassword::prompt_password("Client secret: ").map_err(|e| e.to_string())?)
            };
            Store::open()?.save_client(
                &provider,
                &Client {
                    client_id,
                    client_secret,
                },
            )?;
            eprintln!("Stored the `{provider}` client.");
        }
        Cmd::Login {
            provider,
            token,
            token_stdin,
            ..
        } if token || token_stdin => {
            let t = providers::find(&provider)?;
            let (provider, p) = (t.provider, t.p);
            let pasted = if token_stdin {
                let mut s = String::new();
                std::io::stdin()
                    .read_to_string(&mut s)
                    .map_err(|e| e.to_string())?;
                s
            } else {
                rpassword::prompt_password("Token: ").map_err(|e| e.to_string())?
            };
            let t = oauth::save_pasted(&provider, &p, &pasted)?;
            eprintln!("Stored the pasted `{provider}` token{}.", who(&t));
        }
        Cmd::Login {
            provider,
            scopes,
            no_browser,
            browser,
            site,
            ..
        } => {
            let t = providers::find(&provider)?;
            let opts = oauth::LoginOptions {
                scopes: (!scopes.is_empty()).then_some(scopes),
                open_browser: !no_browser && std::env::var_os("SSH_CONNECTION").is_none(),
                site,
                loopback: browser,
            };
            let token = oauth::login(&t, &opts)?;
            let service = t
                .service
                .as_ref()
                .map(|s| format!(" for `{s}`"))
                .unwrap_or_default();
            eprintln!("Logged in to `{}`{service}{}.", t.provider, who(&token));
        }
        Cmd::Logout { provider } => {
            let provider = providers::find(&provider)?.provider;
            Store::open()?.delete_token(&provider)?;
            eprintln!("Logged out of `{provider}` (the token of all its services).");
        }
        Cmd::Token { provider } => {
            let t = providers::find(&provider)?;
            println!(
                "{}",
                oauth::valid_token(&t.provider, &t.p, false)?.access_token
            );
        }
        Cmd::Api {
            provider,
            path,
            method,
            headers,
            data,
            include,
        } => {
            return api(&provider, &path, method, &headers, data, include);
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// ` (site, account)` for a token, from what login learned, and whether it
/// was pasted; empty if nothing.
fn who(t: &Token) -> String {
    let parts: Vec<&str> = [&t.resource_name, &t.account]
        .into_iter()
        .flatten()
        .map(String::as_str)
        .chain(t.pasted.then_some("pasted token"))
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    }
}

fn api(
    name: &str,
    path: &str,
    method: Option<String>,
    headers: &[String],
    data: Option<String>,
    include: bool,
) -> Result<ExitCode, String> {
    let t = providers::find(name)?;
    let (name, p) = (t.provider.as_str(), &t.p);
    let mut token = oauth::valid_token(name, p, false)?;
    let url = resolve(t.api_base(), p, &token, path)?;
    let body = match data.as_deref() {
        None => None,
        Some("@-") => {
            let mut b = Vec::new();
            std::io::stdin()
                .read_to_end(&mut b)
                .map_err(|e| e.to_string())?;
            Some(b)
        }
        Some(d) => match d.strip_prefix('@') {
            Some(f) => Some(std::fs::read(f).map_err(|e| format!("{f}: {e}"))?),
            None => Some(d.as_bytes().to_vec()),
        },
    };
    let method = method.unwrap_or_else(|| if body.is_some() { "POST" } else { "GET" }.into());
    let method =
        reqwest::Method::from_bytes(method.to_uppercase().as_bytes()).map_err(|e| e.to_string())?;
    let http = oauth::http();
    let send = |token: &Token| {
        let mut req = http
            .request(method.clone(), url.clone())
            .bearer_auth(&token.access_token);
        let mut given = Vec::new();
        for h in headers {
            let (k, v) = h
                .split_once(':')
                .ok_or_else(|| format!("header `{h}` has no `:`"))?;
            given.push(k.trim().to_ascii_lowercase());
            req = req.header(k.trim(), v.trim());
        }
        for (k, v) in &p.api_headers {
            if !given.contains(&k.to_ascii_lowercase()) {
                req = req.header(k, v);
            }
        }
        let has_type = given.iter().any(|k| k == "content-type");
        if let Some(b) = &body {
            if !has_type {
                req = req.header("Content-Type", "application/json");
            }
            req = req.body(b.clone());
        }
        req.send().map_err(|e| format!("{url}: {e}"))
    };
    let mut resp = send(&token)?;
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED && token.refresh_token.is_some() {
        token = oauth::valid_token(name, p, true)?;
        resp = send(&token)?;
    }
    let status = resp.status();
    if include || !status.is_success() {
        eprintln!("{:?} {status}", resp.version());
        if include {
            for (k, v) in resp.headers() {
                eprintln!("{k}: {}", v.to_str().unwrap_or("<binary>"));
            }
        }
    }
    let challenge = resp
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = resp.bytes().map_err(|e| e.to_string())?;
    if status == reqwest::StatusCode::FORBIDDEN && lacks_scope(&challenge, &bytes) {
        eprintln!("{}", scope_hint(&t, &url));
    }
    let mut out = std::io::stdout().lock();
    let pretty = std::io::stdout()
        .is_terminal()
        .then(|| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .flatten()
        .and_then(|v| serde_json::to_string_pretty(&v).ok());
    match pretty {
        Some(s) => writeln!(out, "{s}"),
        None => out.write_all(&bytes),
    }
    .map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Ok(ExitCode::FAILURE);
    }
    if let Some(f) = p.error_in(&bytes) {
        eprintln!("sesame: the answer carries `{f}`: the call failed despite {status}");
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// A 403 for a token that lacks a scope: RFC 6750's `insufficient_scope`
/// challenge, or Google's `insufficientPermissions` / `ACCESS_TOKEN_SCOPE_INSUFFICIENT`.
fn lacks_scope(challenge: &str, body: &[u8]) -> bool {
    let body = String::from_utf8_lossy(body);
    challenge.contains("insufficient_scope")
        || ["insufficientPermissions", "ACCESS_TOKEN_SCOPE_INSUFFICIENT"]
            .iter()
            .any(|m| body.contains(m))
}

/// The next step for a call refused for want of a scope: log in to the service
/// it was made through, or to the one whose API base the URL is under.
fn scope_hint(t: &providers::Target, url: &url::Url) -> String {
    let service = t.service.clone().or_else(|| {
        t.p.services
            .iter()
            .find(|(_, s)| url.as_str().starts_with(s.api_base.trim_end_matches('/')))
            .map(|(n, _)| n.clone())
    });
    match service {
        Some(s) => format!(
            "sesame: the `{}` token lacks a scope this call needs; run `sesame login {s}` to add the scopes of `{s}`",
            t.provider
        ),
        None => format!(
            "sesame: the `{p}` token lacks a scope this call needs; run `sesame login {p} --scope <scope>` with every scope it needs",
            p = t.provider
        ),
    }
}

fn resolve(
    api_base: &str,
    p: &providers::Provider,
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
                .ok_or("no site stored; log in again")?;
            base = base.replace("{resource_id}", id);
        }
        let sep = if path.starts_with('/') { "" } else { "/" };
        url::Url::parse(&format!("{}{sep}{path}", base.trim_end_matches('/')))
            .map_err(|e| e.to_string())?
    };
    let host = url.host_str().unwrap_or("");
    if !p.allows_host(host) {
        return Err(format!(
            "refusing to send the token to {host}: not one of {:?}",
            p.hosts
        ));
    }
    Ok(url)
}
