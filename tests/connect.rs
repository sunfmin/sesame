//! Connecting a platform sesame does not know: `provider discover` against
//! fake metadata servers, `provider export` rebuilding a definition in an
//! empty database, `provider guide`, and fixed ports kept one provider's own.
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Serves `pages` (path, JSON body) on 127.0.0.1; every other path is a 404.
fn serve(pages: Vec<(&'static str, String)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut line = String::new();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            reader.read_line(&mut line).unwrap();
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap() == 0 || h.trim().is_empty() {
                    break;
                }
            }
            let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
            let (status, body) = match pages.iter().find(|(p, _)| *p == target) {
                Some((_, b)) => ("200 OK", b.clone()),
                None => ("404 Not Found", String::new()),
            };
            let mut s = stream;
            let _ = write!(
                s,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn config(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sesame-connect-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn sesame(config: &Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sesame"))
        .args(args)
        .env("SESAME_CONFIG_DIR", config)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into(),
        String::from_utf8_lossy(&out.stderr).into(),
    )
}

#[test]
fn discover_reads_rfc_8414_metadata() {
    let meta = serde_json::json!({
        "issuer": "https://acme.example",
        "authorization_endpoint": "https://acme.example/oauth/authorize",
        "token_endpoint": "https://acme.example/oauth/token",
        "device_authorization_endpoint": "https://acme.example/oauth/device",
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "scopes_supported": ["read", "write", "admin"],
    });
    let base = serve(vec![(
        "/.well-known/oauth-authorization-server",
        meta.to_string(),
    )]);
    let (ok, out, err) = sesame(&config("rfc8414"), &["provider", "discover", &base]);
    assert!(ok, "{err}");
    for want in [
        "--auth-url https://acme.example/oauth/authorize",
        "--token-url https://acme.example/oauth/token",
        "--device-url https://acme.example/oauth/device",
        "--client-auth basic",
        &format!("--source {base}/.well-known/oauth-authorization-server"),
        "read write admin",
        "S256 is supported",
        "--api-base",
        "--host",
        // Still to find out: fields the metadata does not cover.
        "--token-body:",
        "--redirect-port:",
        "--error-field:",
    ] {
        assert!(out.contains(want), "missing {want:?} in:\n{out}");
    }
    assert!(!out.contains("--auth-url:"), "{out}");
    assert!(!out.contains("--pkce:"), "{out}");
    assert!(!out.contains("which code_challenge_method"), "{out}");
}

#[test]
fn discover_falls_back_to_openid_configuration() {
    let meta = serde_json::json!({
        "issuer": "https://id.example",
        "authorization_endpoint": "https://id.example/authorize",
        "token_endpoint": "https://id.example/token",
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
    });
    let base = serve(vec![(
        "/tenant/.well-known/openid-configuration",
        meta.to_string(),
    )]);
    let (ok, out, err) = sesame(
        &config("oidc"),
        &["provider", "discover", &format!("{base}/tenant")],
    );
    assert!(ok, "{err}");
    assert!(
        out.contains("--auth-url https://id.example/authorize"),
        "{out}"
    );
    assert!(
        out.contains("--token-url https://id.example/token"),
        "{out}"
    );
    assert!(!out.contains("--client-auth basic"), "{out}");
    assert!(!out.contains("--device-url https"), "{out}");
    assert!(out.contains("--device-url:"), "{out}");

    // A metadata URL is read as given.
    let (ok, out, err) = sesame(
        &config("oidc-url"),
        &[
            "provider",
            "discover",
            &format!("{base}/tenant/.well-known/openid-configuration"),
        ],
    );
    assert!(ok && out.contains("https://id.example/token"), "{err}{out}");
}

#[test]
fn discover_without_metadata_points_to_the_guide() {
    let base = serve(vec![("/", "{}".into())]);
    let (ok, out, err) = sesame(&config("none"), &["provider", "discover", &base]);
    assert!(!ok, "{out}");
    assert!(err.contains("no OAuth metadata found"), "{err}");
    assert!(err.contains("oauth-authorization-server: 404"), "{err}");
    assert!(err.contains("openid-configuration: 404"), "{err}");
    assert!(err.contains("sesame provider guide"), "{err}");
}

#[test]
fn guide_lists_every_flag_and_help_points_to_it() {
    let dir = config("guide");
    let (ok, guide, err) = sesame(&dir, &["provider", "guide"]);
    assert!(ok, "{err}");
    let (ok, help, _) = sesame(&dir, &["provider", "add", "--help"]);
    assert!(ok);
    let flags: Vec<&str> = help
        .split_whitespace()
        // `--drop-service` removes a service: it fills in no field.
        .filter(|w| w.starts_with("--") && !["--help", "--drop-service"].contains(w))
        .collect();
    assert!(flags.len() > 15, "{help}");
    for flag in flags {
        assert!(guide.contains(flag), "guide misses {flag}");
    }
    let (_, top, _) = sesame(&dir, &["--help"]);
    assert!(top.contains("sesame provider guide"), "{top}");
}

#[test]
fn export_rebuilds_the_definition_in_an_empty_database() {
    let from = config("export-from");
    let (ok, _, err) = sesame(
        &from,
        &[
            "provider",
            "add",
            "acme",
            "--about",
            "Acme's API",
            "--auth-url",
            "https://acme.example/authorize",
            "--token-url",
            "https://acme.example/token",
            "--refresh-url",
            "https://acme.example/refresh",
            "--scope-param",
            "user_scope",
            "--pkce",
            "false",
            "--token-path",
            "/authed_user",
            "--redirect",
            "https-paste",
            "--code-seconds",
            "30",
            "--service",
            "name=billing,api-base=https://api.acme.example/billing,scope=billing.read",
            "--api-base",
            "https://api.acme.example/{resource_id}",
            "--host",
            "api.acme.example",
            "--host",
            "*.acme-cdn.example",
            "--scope",
            "read",
            "--scope",
            "write",
            "--scope-separator",
            ",",
            "--auth-param",
            "prompt=consent",
            "--token-body",
            "json",
            "--client-auth",
            "basic",
            "--api-header",
            "Acme-Version: 2026-01-01",
            "--resources-url",
            "https://api.acme.example/sites",
            "--redirect-port",
            "9411",
            "--redirect-host",
            "127.0.0.1",
            "--identity-url",
            "https://api.acme.example/graphql",
            "--identity-field",
            "/data/viewer/name",
            "--identity-body",
            r#"{"query": "{ viewer { name } }"}"#,
            "--error-field",
            "errors",
            "--setup-step",
            r#"{"title": "Register the app", "page": "https://acme.example/apps", "details": "Callback: {callback}; it's exact"}"#,
            "--source",
            "https://acme.example/docs/oauth",
            "--source",
            "https://acme.example/docs/api",
        ],
    );
    assert!(ok, "{err}");
    let (ok, shown, err) = sesame(&from, &["provider", "show", "acme"]);
    assert!(ok, "{err}");
    let shown: serde_json::Value = serde_json::from_str(&shown).unwrap();
    assert_eq!(
        shown["sources"]["value"],
        serde_json::json!([
            "https://acme.example/docs/oauth",
            "https://acme.example/docs/api"
        ])
    );

    let (ok, exported, err) = sesame(&from, &["provider", "export", "acme"]);
    assert!(ok, "{err}");
    assert!(
        exported.starts_with("sesame provider add acme"),
        "{exported}"
    );

    // Run the command as printed, in a shell, against an empty database.
    let to = config("export-to");
    let bin = Path::new(env!("CARGO_BIN_EXE_sesame")).parent().unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let out = Command::new("sh")
        .arg("-c")
        .arg(&exported)
        .env("PATH", path)
        .env("SESAME_CONFIG_DIR", &to)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}\n{exported}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (ok, again, err) = sesame(&to, &["provider", "show", "acme"]);
    assert!(ok, "{err}");
    let again: serde_json::Value = serde_json::from_str(&again).unwrap();
    assert_eq!(again, shown);

    // A built-in exports its definition in force, the person's changes included.
    let (ok, _, err) = sesame(&to, &["provider", "set", "linear", "--scope", "read"]);
    assert!(ok, "{err}");
    let (ok, linear, _) = sesame(&to, &["provider", "export", "linear"]);
    assert!(ok);
    assert!(linear.contains("--scope read \\"), "{linear}");
    assert!(!linear.contains("--scope write"), "{linear}");
    assert!(linear.contains("--scope-separator ,"), "{linear}");
}

#[test]
fn a_fixed_port_is_one_providers_only() {
    let dir = config("ports");
    let add = |name: &str, port: &str| {
        sesame(
            &dir,
            &[
                "provider",
                "add",
                name,
                "--auth-url",
                "https://a.example/authorize",
                "--token-url",
                "https://a.example/token",
                "--api-base",
                "https://a.example",
                "--host",
                "a.example",
                "--redirect-port",
                port,
            ],
        )
    };
    // jira, built in, listens on 8749.
    let (ok, _, err) = add("acme", "8749");
    assert!(
        !ok && err.contains("redirect_port 8749 is taken by `jira`"),
        "{err}"
    );
    let (ok, _, err) = add("acme", "9555");
    assert!(ok, "{err}");
    let (ok, _, err) = add("other", "9555");
    assert!(!ok && err.contains("taken by `acme`"), "{err}");
    let (ok, _, err) = sesame(
        &dir,
        &["provider", "set", "notion", "--redirect-port", "9555"],
    );
    assert!(!ok && err.contains("taken by `acme`"), "{err}");
    // Its own port again is no conflict.
    let (ok, _, err) = sesame(
        &dir,
        &["provider", "set", "acme", "--redirect-port", "9555"],
    );
    assert!(ok, "{err}");
}
