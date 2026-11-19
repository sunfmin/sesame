//! `sesame api`: one call to a provider's API with its token. It resolves the
//! path under the API base (refusing hosts the provider does not list), sends
//! the request, refreshes and retries once on a 401, says which login adds a
//! missing scope on a 403, and prints the answer.

use crate::handed::{self, Handed};
use crate::oauth;
use crate::providers::{self, Target};
use crate::refresh::{self, Refresh};
use crate::store::{Store, Token};
use crate::wire;
use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;

/// The arguments of `sesame api`.
#[derive(clap::Args)]
pub struct Call {
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
}

impl Call {
    /// Make the call and print the answer to stdout; failure when the API
    /// answered with an error status or an error field.
    pub fn run(self) -> Result<ExitCode, String> {
        let Call {
            provider,
            path,
            method,
            headers,
            data,
            include,
        } = self;
        let (name, path, headers) = (provider.as_str(), path.as_str(), headers.as_slice());
        let (t, holder) = match handed::find(name)? {
            Some((t, h)) => (t, Holder::Handed(h)),
            None => {
                let store = Store::open()?;
                (providers::find(&store, name)?, Holder::Store(store))
            }
        };
        let (name, p) = (t.provider.as_str(), &t.p);
        let mut token = match &holder {
            Holder::Handed(h) => h.token.clone(),
            Holder::Store(s) => {
                refresh::valid_token(s, name, p, Refresh::Within(refresh::MIN_LIFE))?
            }
        };
        let url = wire::api_url(t.api_base(), p, &token, path)?;
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
        let method = reqwest::Method::from_bytes(method.to_uppercase().as_bytes())
            .map_err(|e| e.to_string())?;
        let headers = wire::api_headers(p, headers, body.is_some())?;
        let http = oauth::http();
        let send = |token: &Token| {
            let mut req = http
                .request(method.clone(), url.clone())
                .bearer_auth(&token.access_token);
            for (k, v) in &headers {
                req = req.header(k, v);
            }
            if let Some(b) = &body {
                req = req.body(b.clone());
            }
            req.send().map_err(|e| format!("{url}: {e}"))
        };
        let mut resp = send(&token)?;
        if let Holder::Store(s) = &holder
            && resp.status() == reqwest::StatusCode::UNAUTHORIZED
            && token.refresh_token.is_some()
        {
            token = refresh::valid_token(s, name, p, Refresh::Now)?;
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
        if let (Holder::Handed(h), reqwest::StatusCode::UNAUTHORIZED) = (&holder, status) {
            eprintln!(
                "sesame: the token handed in `{}` was refused or has expired; its holder must hand a new one",
                h.var
            );
        }
        if status == reqwest::StatusCode::FORBIDDEN && wire::lacks_scope(&challenge, &bytes) {
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
        if let Some(f) = wire::error_in(p, &bytes) {
            eprintln!("sesame: the answer carries `{f}`: the call failed despite {status}");
            return Ok(ExitCode::FAILURE);
        }
        Ok(ExitCode::SUCCESS)
    }
}

/// Where the call's token comes from: the environment, or the store, opened
/// once for the call and its refresh.
enum Holder {
    Handed(Handed),
    Store(Store),
}

/// The next step for a call refused for want of a scope: log in to the service
/// it was made through, or to the one whose API base the URL is under.
fn scope_hint(t: &Target, url: &url::Url) -> String {
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
