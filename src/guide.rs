//! Connecting a platform sesame does not know, written for the person's AI:
//! `sesame provider guide` (the steps, with the research checklist made from
//! the field table) and `sesame provider discover` (what a platform's OAuth
//! metadata answers). Neither writes anything.
use crate::providers::fields::{self, FIELDS, FIXED, quote};
use serde_json::Value;
use std::fmt::Write;

/// `sesame provider guide`.
pub fn render() -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "\
Connect a platform sesame does not know, for an AI doing it for a person.
Find out how the platform's OAuth and API differ, store the answers with
commands, and check that the person can sign in and call the API.

1. Look for standard metadata first:
     sesame provider discover <the platform's domain or OAuth issuer>
   It reads RFC 8414 or OpenID Connect metadata, if the platform publishes
   it, and prints a draft `sesame provider add` command. It fills in only
   what the metadata says: the rest is still to find out in step 2.

2. Answer each question below from the platform's official documentation.

3. Note the page each answer came from. Write \"not found\" for what the
   docs do not say: do not guess. A default holds for a field left out.

4. Store the answers:
     sesame provider add <name> --auth-url … --token-url … --api-base … --host … \\
       --source <doc URL> --source … --setup-step '{{\"title\": …, \"page\": …, \"details\": …}}'
   Give each page as a --source, and the person's steps to register the app
   as --setup-step, in order, written for the person (`{{callback}}` and
   `{{scopes}}` in details are filled in). Do not edit sesame.db yourself.
   Change a field later with `sesame provider set <name> --<flag> …`.

5. Walk the person through `sesame setup <name>`, then `sesame client <name>`
   and `sesame login <name>`. The person types the client secret into
   `sesame client` in their own terminal: never ask for it in the chat.

6. Check it works: call an endpoint that says who signed in, e.g.
     sesame api <name> /me      (or /user, or a GraphQL viewer query)
   When login or the call fails, read the error, find the field it points
   to in step 2, fix it with `sesame provider set <name> …`, and log in again.

When it works, `sesame provider export <name>` prints the command that makes
this definition again elsewhere, to share it or to make it a built-in.

## The questions, one per field

"
    );
    for f in FIELDS {
        let _ = writeln!(
            out,
            "--{}{}  [{}]",
            f.flag,
            if f.required { "  (required)" } else { "" },
            f.kind.describe()
        );
        let _ = writeln!(out, "    {}", f.question);
        let _ = writeln!(out, "    Look in: {}.\n", f.look);
    }
    let _ = writeln!(
        out,
        "## What sesame does one way only\n\n\
         Check these too. When the platform does otherwise, sesame cannot sign in to it\n\
         yet: tell the person, rather than storing a provider that cannot work.\n"
    );
    for (q, does) in FIXED {
        let _ = writeln!(out, "- {q}\n    {does}\n");
    }
    out.trim_end().to_string() + "\n"
}

/// The URLs to try for `input`, in order: a metadata URL as given, else the
/// RFC 8414 one (`/.well-known/oauth-authorization-server` before the
/// issuer's path), then the OpenID Connect one (`/.well-known/openid-configuration`
/// after it).
fn candidates(input: &str) -> Result<Vec<url::Url>, String> {
    let with_scheme = if input.contains("://") {
        input.to_string()
    } else {
        format!("https://{input}")
    };
    let u = url::Url::parse(&with_scheme).map_err(|e| format!("`{input}`: {e}"))?;
    if u.path().contains("/.well-known/") {
        return Ok(vec![u]);
    }
    let origin = u.origin().ascii_serialization();
    let path = u.path().trim_end_matches('/');
    let mut urls = Vec::new();
    for s in [
        format!("{origin}/.well-known/oauth-authorization-server{path}"),
        format!("{origin}{path}/.well-known/openid-configuration"),
    ] {
        let parsed = url::Url::parse(&s).map_err(|e| e.to_string())?;
        if !urls.contains(&parsed) {
            urls.push(parsed);
        }
    }
    Ok(urls)
}

/// The metadata at `url`, or why there is none.
fn fetch(url: &url::Url) -> Result<serde_json::Map<String, Value>, String> {
    let resp = crate::oauth::http()
        .get(url.clone())
        .header("Accept", "application/json")
        .send()
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    if !status.is_success() {
        return Err(status.to_string());
    }
    match resp.json::<Value>() {
        Ok(Value::Object(m))
            if m.contains_key("authorization_endpoint") || m.contains_key("token_endpoint") =>
        {
            Ok(m)
        }
        Ok(_) => Err("not OAuth metadata".into()),
        Err(_) => Err("not JSON".into()),
    }
}

/// `sesame provider discover`: what the first metadata found answers, as a
/// draft `sesame provider add`, and what is still to find out.
pub fn discover(input: &str) -> Result<String, String> {
    let mut tried = Vec::new();
    for url in candidates(input)? {
        match fetch(&url) {
            Ok(m) => return Ok(draft(&url, &m)),
            Err(why) => tried.push(format!("  {url}: {why}")),
        }
    }
    Err(format!(
        "no OAuth metadata found for `{input}`; tried:\n{}\n\
         Answer each question of `sesame provider guide` from the platform's docs instead.",
        tried.join("\n")
    ))
}

fn draft(url: &url::Url, m: &serde_json::Map<String, Value>) -> String {
    let text = |k: &str| m.get(k).and_then(Value::as_str);
    let words = |k: &str| -> Option<Vec<&str>> {
        m.get(k)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
    };
    let mut flags: Vec<(&str, String)> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut answered = vec!["sources"];

    for (key, field) in [
        ("authorization_endpoint", "auth_url"),
        ("token_endpoint", "token_url"),
        ("device_authorization_endpoint", "device_url"),
    ] {
        if let Some(v) = text(key) {
            flags.push((field, v.into()));
            answered.push(field);
        }
    }
    match words("token_endpoint_auth_methods_supported") {
        Some(ms) if ms.contains(&"client_secret_post") => {
            notes.push("client_auth: the token endpoint takes the client in the body (client_secret_post), the default.".into());
            answered.push("client_auth");
        }
        Some(ms) if ms.contains(&"client_secret_basic") => {
            flags.push(("client_auth", "basic".into()));
            answered.push("client_auth");
        }
        Some(ms) => notes.push(format!(
            "client_auth: the token endpoint takes {}, neither in the body nor HTTP Basic; \
             a public client (`none`) is stored with `sesame client --no-secret`.",
            ms.join(", ")
        )),
        None => {}
    }
    let mut pkce_answered = false;
    if let Some(ms) = words("code_challenge_methods_supported") {
        pkce_answered = true;
        if ms.contains(&"S256") {
            notes.push(
                "PKCE: S256 is supported, which sesame sends (pkce is on by default).".into(),
            );
            answered.push("pkce");
        } else {
            notes.push(format!(
                "PKCE: only {} listed, and sesame sends S256 only: try --pkce false if the \
                 platform allows the code flow without PKCE.",
                ms.join(", ")
            ));
        }
    }
    if let Some(scopes) = words("scopes_supported") {
        notes.push(format!(
            "scopes the metadata lists (give the ones the API use needs as --scope): {}",
            scopes.join(" ")
        ));
    }
    flags.push(("api_base", "<API base URL>".into()));
    flags.push(("hosts", "<API host>".into()));
    flags.push(("sources", url.to_string()));

    let mut out = format!("Found OAuth metadata at {url}");
    if let Some(issuer) = text("issuer") {
        let _ = write!(out, " (issuer {issuer})");
    }
    out.push_str(".\n\nDraft; fill in each <…> and the fields below, then run it:\n\n");
    out.push_str("sesame provider add '<name>'");
    for (name, v) in &flags {
        let flag = fields::field(name).map_or(*name, |f| f.flag);
        let _ = write!(out, " \\\n  --{flag} {}", quote(v));
    }
    out.push('\n');
    if !notes.is_empty() {
        out.push_str("\nFrom the metadata:\n");
        for n in &notes {
            let _ = writeln!(out, "- {n}");
        }
    }
    out.push_str("\nNot in the metadata; find these out in the docs (`sesame provider guide`):\n");
    for f in FIELDS.iter().filter(|f| !answered.contains(&f.name)) {
        let _ = writeln!(out, "--{}: {}", f.flag, f.question);
    }
    for (q, _) in FIXED
        .iter()
        .filter(|(q, _)| !(pkce_answered && q.contains("PKCE")))
    {
        let _ = writeln!(out, "- {q}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guide_asks_about_every_field() {
        let out = render();
        for f in FIELDS {
            assert!(out.contains(&format!("--{}", f.flag)), "no --{}", f.flag);
            assert!(out.contains(f.question), "no question for {}", f.name);
        }
        for (q, _) in FIXED {
            assert!(out.contains(q), "{q}");
        }
        for want in [
            "sesame provider discover",
            "--source",
            "--setup-step",
            "not found",
            "never ask for it in the chat",
            "sesame provider set",
            "/me",
        ] {
            assert!(out.contains(want), "missing {want:?}");
        }
    }

    #[test]
    fn candidate_urls() {
        let s = |i: &str| -> Vec<String> {
            candidates(i)
                .unwrap()
                .into_iter()
                .map(|u| u.to_string())
                .collect()
        };
        assert_eq!(
            s("acme.example"),
            [
                "https://acme.example/.well-known/oauth-authorization-server",
                "https://acme.example/.well-known/openid-configuration",
            ]
        );
        assert_eq!(
            s("https://login.acme.example/tenant/"),
            [
                "https://login.acme.example/.well-known/oauth-authorization-server/tenant",
                "https://login.acme.example/tenant/.well-known/openid-configuration",
            ]
        );
        assert_eq!(
            s("https://acme.example/.well-known/openid-configuration"),
            ["https://acme.example/.well-known/openid-configuration"]
        );
    }
}
