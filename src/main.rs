mod oauth;
mod providers;
mod store;

use clap::{Parser, Subcommand};
use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;
use store::{Client, Store, Token};

/// Sign in to SaaS APIs from the terminal and call them with the stored token.
#[derive(Parser)]
#[command(name = "sesame", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List the providers and whether you are signed in to each.
    Providers,
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
    /// Sign in through the provider's OAuth page and store the token.
    Login {
        provider: String,
        /// Scope to ask for instead of the provider's defaults; repeatable.
        #[arg(long = "scope")]
        scopes: Vec<String>,
        /// Print the URL only; do not try to open a browser.
        #[arg(long)]
        no_browser: bool,
        /// Which site to use when the login reaches several (Jira).
        #[arg(long)]
        site: Option<String>,
    },
    /// Forget the stored token.
    Logout { provider: String },
    /// Print a valid access token, refreshing it if needed (for curl and scripts).
    Token { provider: String },
    /// Call the provider's API with the stored token.
    Api {
        provider: String,
        /// Path under the provider's API base, or a full URL on one of its hosts.
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
                let state = match (&client, &token) {
                    (None, _) => "no client".to_string(),
                    (Some(_), None) => "not logged in".to_string(),
                    (Some(_), Some(t)) => match &t.resource_name {
                        Some(site) => format!("logged in ({site})"),
                        None => "logged in".to_string(),
                    },
                };
                println!("{name:<12} {state:<24} {}", p.about);
            }
        }
        Cmd::Client {
            provider,
            client_id,
            secret_stdin,
            no_secret,
        } => {
            providers::get(&provider)?;
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
            scopes,
            no_browser,
            site,
        } => {
            let p = providers::get(&provider)?;
            let opts = oauth::LoginOptions {
                scopes: (!scopes.is_empty()).then_some(scopes),
                open_browser: !no_browser && std::env::var_os("SSH_CONNECTION").is_none(),
                site,
            };
            let t = oauth::login(&provider, &p, &opts)?;
            let site = t
                .resource_name
                .map(|s| format!(" ({s})"))
                .unwrap_or_default();
            eprintln!("Logged in to `{provider}`{site}.");
        }
        Cmd::Logout { provider } => {
            Store::open()?.delete_token(&provider)?;
            eprintln!("Logged out of `{provider}`.");
        }
        Cmd::Token { provider } => {
            let p = providers::get(&provider)?;
            println!("{}", oauth::valid_token(&provider, &p, false)?.access_token);
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

fn api(
    name: &str,
    path: &str,
    method: Option<String>,
    headers: &[String],
    data: Option<String>,
    include: bool,
) -> Result<ExitCode, String> {
    let p = providers::get(name)?;
    let mut token = oauth::valid_token(name, &p, false)?;
    let url = resolve(&p, &token, path)?;
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
    let http = reqwest::blocking::Client::new();
    let send = |token: &Token| {
        let mut req = http
            .request(method.clone(), url.clone())
            .bearer_auth(&token.access_token);
        let mut has_type = false;
        for h in headers {
            let (k, v) = h
                .split_once(':')
                .ok_or_else(|| format!("header `{h}` has no `:`"))?;
            has_type |= k.trim().eq_ignore_ascii_case("content-type");
            req = req.header(k.trim(), v.trim());
        }
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
        token = oauth::valid_token(name, &p, true)?;
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
    let bytes = resp.bytes().map_err(|e| e.to_string())?;
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
    Ok(if status.is_success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn resolve(p: &providers::Provider, token: &Token, path: &str) -> Result<url::Url, String> {
    let url = if path.starts_with("https://") || path.starts_with("http://") {
        url::Url::parse(path).map_err(|e| e.to_string())?
    } else {
        let mut base = p.api_base.clone();
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
