//! `sesame api`: one call to a provider's API with its token. It resolves the
//! path under the API base (refusing hosts the provider does not list), sends
//! the request, refreshes and retries once on a 401, says which login adds a
//! missing scope on a 403, and prints the answer.

use crate::providers::{self, Provider, Target};
use crate::store::Token;
use crate::{handed, oauth};
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
        let (t, handed) = match handed::find(name)? {
            Some((t, h)) => (t, Some(h)),
            None => (providers::find(name)?, None),
        };
        let (name, p) = (t.provider.as_str(), &t.p);
        let mut token = match &handed {
            Some(h) => h.token.clone(),
            None => oauth::valid_token(name, p, oauth::Refresh::Within(oauth::MIN_LIFE))?,
        };
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
        let method = reqwest::Method::from_bytes(method.to_uppercase().as_bytes())
            .map_err(|e| e.to_string())?;
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
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED
            && handed.is_none()
            && token.refresh_token.is_some()
        {
            token = oauth::valid_token(name, p, oauth::Refresh::Now)?;
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
        if let (Some(h), reqwest::StatusCode::UNAUTHORIZED) = (&handed, status) {
            eprintln!(
                "sesame: the token handed in `{}` was refused or has expired; its holder must hand a new one",
                h.var
            );
        }
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

fn resolve(api_base: &str, p: &Provider, token: &Token, path: &str) -> Result<url::Url, String> {
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
    if !p.allows_host(host) {
        return Err(format!(
            "refusing to send the token to {host}: not one of {:?}",
            p.hosts
        ));
    }
    Ok(url)
}
