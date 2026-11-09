//! The whole flow against a fake provider on 127.0.0.1: client, login (the
//! test plays the browser), api, refresh after a 401, token, logout.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

/// One request: its target, its headers (names lowercased) and its body.
fn read_request(stream: &std::net::TcpStream) -> (String, Vec<(String, String)>, String) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).unwrap();
        if h.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let len = header(&headers, "content-length").map_or(0, |v| v.parse().unwrap());
    let mut body = vec![0; len];
    reader.read_exact(&mut body).unwrap();
    (target, headers, String::from_utf8(body).unwrap())
}

fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

fn reply(s: &mut std::net::TcpStream, status: &str, extra: &str, b: &str) {
    write!(
        s,
        "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{b}",
        b.len()
    )
    .unwrap();
}

fn fake_provider() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        let mut access = "access-1".to_string();
        for stream in listener.incoming().flatten() {
            let (target, headers, body) = read_request(&stream);
            let auth = header(&headers, "authorization").unwrap_or_default();
            log2.lock().unwrap().push(format!("{target} {body}"));
            let mut s = stream;
            if target.starts_with("/authorize") {
                let u = url::Url::parse(&format!("http://x{target}")).unwrap();
                let q = |k: &str| {
                    u.query_pairs()
                        .find(|(n, _)| n == k)
                        .unwrap()
                        .1
                        .into_owned()
                };
                let loc = format!("{}?code=the-code&state={}", q("redirect_uri"), q("state"));
                reply(&mut s, "302 Found", &format!("Location: {loc}\r\n"), "");
            } else if target == "/token" {
                if body.contains("grant_type=authorization_code") {
                    assert!(body.contains("code=the-code") && body.contains("code_verifier="));
                    reply(
                        &mut s,
                        "200 OK",
                        "",
                        r#"{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}"#,
                    );
                } else {
                    assert!(body.contains("refresh_token=refresh-1"));
                    access = "access-2".into();
                    reply(
                        &mut s,
                        "200 OK",
                        "",
                        r#"{"access_token":"access-2","expires_in":3600}"#,
                    );
                }
            } else if target == "/sites" {
                reply(
                    &mut s,
                    "200 OK",
                    "",
                    r#"[{"id":"site-9","name":"acme","url":"https://acme.example"}]"#,
                );
            } else if target.starts_with("/ex/site-9/me") {
                if auth == format!("Bearer {access}") && access == "access-2" {
                    reply(&mut s, "200 OK", "", r#"{"me":"felix"}"#);
                } else {
                    // The first call is refused, to make the CLI refresh.
                    access = "access-1-revoked".into();
                    reply(&mut s, "401 Unauthorized", "", "{}");
                }
            } else {
                reply(&mut s, "404 Not Found", "", "");
            }
        }
    });
    (port, log)
}

#[test]
fn login_call_refresh_logout() {
    let (port, log) = fake_provider();
    let tmp = std::env::temp_dir().join(format!("sesame-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let config = tmp.join("config");
    std::fs::create_dir_all(&config).unwrap();
    let sesame = |args: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sesame"));
        c.args(args).env("SESAME_CONFIG_DIR", &config);
        c
    };

    let base = format!("http://127.0.0.1:{port}");
    let out = sesame(&[
        "provider",
        "add",
        "fake",
        "--auth-url",
        &format!("{base}/authorize"),
        "--token-url",
        &format!("{base}/token"),
        "--api-base",
        &format!("{base}/ex/{{resource_id}}"),
        "--host",
        "127.0.0.1",
        "--scope",
        "read",
        "--resources-url",
        &format!("{base}/sites"),
    ])
    .output()
    .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let st = sesame(&["client", "fake", "--client-id", "cid", "--no-secret"])
        .status()
        .unwrap();
    assert!(st.success());

    let mut login = sesame(&["login", "fake", "--no-browser"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut err = BufReader::new(login.stderr.take().unwrap());
    let auth_url = loop {
        let mut l = String::new();
        assert!(
            err.read_line(&mut l).unwrap() > 0,
            "login ended before printing a URL"
        );
        if let Some(u) = l.trim().strip_prefix("http") {
            break format!("http{u}");
        }
    };
    // Play the browser: follow the provider's redirect to the CLI's loopback.
    let page = reqwest::blocking::get(&auth_url).unwrap().text().unwrap();
    assert!(page.contains("Signed in"));
    let status = login.wait().unwrap();
    let mut rest = String::new();
    err.read_to_string(&mut rest).unwrap();
    assert!(status.success(), "login failed: {rest}");

    let out = sesame(&["api", "fake", "/me"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), r#"{"me":"felix"}"#);

    let out = sesame(&["token", "fake"]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "access-2");

    let out = sesame(&["api", "fake", "https://evil.example/steal"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("refusing to send the token"));

    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(config.join("sesame.db"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    assert!(sesame(&["logout", "fake"]).status().unwrap().success());
    assert!(!sesame(&["token", "fake"]).status().unwrap().success());

    let log = log.lock().unwrap();
    assert!(
        log.iter().any(|l| l.contains("grant_type=refresh_token")),
        "{log:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// First use: no client yet. Every command names the next one to run, and a
/// provider added with `sesame provider add` prints its own setup steps.
#[test]
fn first_use_points_to_setup() {
    let tmp = std::env::temp_dir().join(format!("sesame-setup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let config = tmp.join("config");
    std::fs::create_dir_all(&config).unwrap();
    let sesame = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_sesame"))
            .args(args)
            .env("SESAME_CONFIG_DIR", &config)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr);
        (out.status.success(), text)
    };

    let (ok, out) = sesame(&[
        "provider",
        "add",
        "acme",
        "--auth-url",
        "https://acme.example/authorize",
        "--token-url",
        "https://acme.example/token",
        "--api-base",
        "https://api.acme.example",
        "--host",
        "api.acme.example",
        "--scope",
        "read",
        "--scope",
        "write",
        "--redirect-port",
        "9321",
        "--setup-step",
        r#"{"title": "Register the app", "page": "https://acme.example/apps",
            "details": "Callback: {callback}; scopes: {scopes}"}"#,
    ]);
    assert!(ok, "{out}");

    let (ok, out) = sesame(&["setup", "acme"]);
    assert!(ok, "{out}");
    assert!(out.contains("1. Register the app"), "{out}");
    assert!(out.contains("Open: https://acme.example/apps"), "{out}");
    assert!(
        out.contains("Callback: http://localhost:9321/callback; scopes: read, write"),
        "{out}"
    );
    assert!(
        out.contains("sesame client acme --client-id <client id>"),
        "{out}"
    );

    let (ok, out) = sesame(&["setup", "jira"]);
    assert!(
        ok && out.contains("http://localhost:8749/callback"),
        "{out}"
    );

    let (ok, out) = sesame(&["setup", "nope"]);
    assert!(!ok);
    assert!(out.contains("unknown provider `nope`"), "{out}");
    assert!(out.contains("acme, google, jira"), "{out}");

    let (_, out) = sesame(&["providers"]);
    assert!(out.contains("next: sesame setup acme"), "{out}");

    for cmd in [
        &["login", "acme", "--no-browser"][..],
        &["api", "acme", "/x"],
    ] {
        let (ok, out) = sesame(cmd);
        assert!(!ok);
        assert!(out.contains("run `sesame setup acme`"), "{cmd:?}: {out}");
    }

    let (ok, _) = sesame(&["client", "acme", "--client-id", "cid", "--no-secret"]);
    assert!(ok);
    let (_, out) = sesame(&["providers"]);
    assert!(out.contains("next: sesame login acme"), "{out}");
    let (ok, out) = sesame(&["api", "acme", "/x"]);
    assert!(!ok && out.contains("run `sesame login acme`"), "{out}");

    let (_, out) = sesame(&["--help"]);
    assert!(out.starts_with("If you are an AI"), "{out}");
    assert!(out.contains("sesame setup <provider>"), "{out}");
    assert!(!out.contains("providers.toml"), "{out}");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// `provider set` on a built-in stores only the changed field, `rm` brings the
/// built-in back, and an invalid value writes nothing.
#[test]
fn provider_set_show_rm() {
    let tmp = std::env::temp_dir().join(format!("sesame-provider-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let config = tmp.join("config");
    let sesame = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_sesame"))
            .args(args)
            .env("SESAME_CONFIG_DIR", &config)
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            err,
        )
    };
    let show = |name: &str| -> serde_json::Value {
        let (ok, out, err) = sesame(&["provider", "show", name]);
        assert!(ok, "{err}");
        serde_json::from_str(&out).unwrap()
    };
    let field_db_rows = || {
        let db = rusqlite::Connection::open(config.join("sesame.db")).unwrap();
        db.query_row("SELECT count(*) FROM provider_fields", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap()
    };

    let before = show("google");
    assert!(
        before
            .as_object()
            .unwrap()
            .values()
            .all(|f| f["from"] == "built-in")
    );

    let (ok, _, err) = sesame(&[
        "provider", "set", "google", "--scope", "email", "--scope", "openid",
    ]);
    assert!(ok, "{err}");
    let after = show("google");
    assert_eq!(
        after["scopes"]["value"],
        serde_json::json!(["email", "openid"])
    );
    assert_eq!(after["scopes"]["from"], "user");
    for (k, v) in before.as_object().unwrap() {
        if k != "scopes" {
            assert_eq!(&after[k], v, "{k} changed");
        }
    }
    assert_eq!(field_db_rows(), 1);
    let (_, out, _) = sesame(&["setup", "google"]);
    assert!(
        out.contains("The scopes sesame asks for at login: email, openid"),
        "{out}"
    );

    // Invalid values are refused before anything is written.
    for bad in [
        &["provider", "set", "google", "--token-url", "not a url"][..],
        &["provider", "set", "google", "--token-body", "xml"],
        &[
            "provider",
            "add",
            "bad",
            "--auth-url",
            "https://b.example/a",
            "--token-url",
            "https://b.example/t",
            "--api-base",
            "https://b.example",
        ],
        &[
            "provider",
            "add",
            "bad",
            "--auth-url",
            "https://b.example/a",
            "--token-url",
            "https://b.example/t",
            "--api-base",
            "https://b.example",
            "--host",
            "b.example",
            "--token-body",
            "xml",
        ],
    ] {
        let (ok, _, err) = sesame(bad);
        assert!(!ok, "{bad:?} was accepted");
        assert!(err.starts_with("sesame: "), "{bad:?}: {err}");
    }
    assert_eq!(field_db_rows(), 1);
    assert_eq!(show("google"), after);
    let (ok, _, err) = sesame(&["provider", "show", "bad"]);
    assert!(!ok && err.contains("unknown provider `bad`"), "{err}");

    let (ok, _, err) = sesame(&["provider", "add", "jira", "--host", "x.example"]);
    assert!(!ok && err.contains("sesame provider set jira"), "{err}");

    let (ok, _, err) = sesame(&["provider", "rm", "google"]);
    assert!(ok && err.contains("built-in"), "{err}");
    assert_eq!(show("google"), before);
    assert_eq!(field_db_rows(), 0);

    let (ok, _, err) = sesame(&["provider", "set", "nope", "--scope", "x"]);
    assert!(!ok && err.contains("sesame provider add nope"), "{err}");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// A provider shaped like Notion's: no scopes, HTTP Basic and a JSON body at
/// the token endpoint, a site name in the token response, rotating refresh
/// tokens, and a fixed header on every API request that `-H` replaces.
fn fake_basic_provider() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        // base64("cid:the-secret")
        let basic = "Basic Y2lkOnRoZS1zZWNyZXQ=";
        let mut access = "access-1".to_string();
        for stream in listener.incoming().flatten() {
            let (target, headers, body) = read_request(&stream);
            let h = |k: &str| header(&headers, k).unwrap_or_default();
            log2.lock().unwrap().push(format!("{target} {body}"));
            let mut s = stream;
            if target.starts_with("/authorize") {
                let u = url::Url::parse(&format!("http://x{target}")).unwrap();
                let q = |k: &str| {
                    u.query_pairs()
                        .find(|(n, _)| n == k)
                        .map(|(_, v)| v.into_owned())
                };
                assert_eq!(q("scope"), None, "{target}");
                assert_eq!(q("owner").as_deref(), Some("user"), "{target}");
                let loc = format!(
                    "{}?code=the-code&state={}",
                    q("redirect_uri").unwrap(),
                    q("state").unwrap()
                );
                reply(&mut s, "302 Found", &format!("Location: {loc}\r\n"), "");
            } else if target == "/token" {
                assert_eq!(h("authorization"), basic);
                assert!(
                    h("content-type").starts_with("application/json"),
                    "{headers:?}"
                );
                let b: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert!(
                    b.get("client_id").is_none() && b.get("client_secret").is_none(),
                    "{body}"
                );
                match b["grant_type"].as_str().unwrap() {
                    "authorization_code" => {
                        assert_eq!(b["code"], "the-code");
                        reply(
                            &mut s,
                            "200 OK",
                            "",
                            r#"{"access_token":"access-1","refresh_token":"refresh-1","workspace_name":"Acme Space","workspace_id":"w1"}"#,
                        );
                    }
                    "refresh_token" => {
                        assert_eq!(b["refresh_token"], "refresh-1");
                        access = "access-2".into();
                        reply(
                            &mut s,
                            "200 OK",
                            "",
                            r#"{"access_token":"access-2","refresh_token":"refresh-2","workspace_name":"Acme Space"}"#,
                        );
                    }
                    g => panic!("grant_type {g}"),
                }
            } else if target.starts_with("/v1/") {
                if h("authorization") != format!("Bearer {access}") || access != "access-2" {
                    // The first call is refused, to make the CLI refresh.
                    access = "access-1-revoked".into();
                    reply(&mut s, "401 Unauthorized", "", "{}");
                } else {
                    let versions: Vec<_> = headers
                        .iter()
                        .filter(|(k, _)| k == "fake-version")
                        .map(|(_, v)| v.as_str())
                        .collect();
                    reply(&mut s, "200 OK", "", &format!("{versions:?}"));
                }
            } else {
                reply(&mut s, "404 Not Found", "", "");
            }
        }
    });
    (port, log)
}

#[test]
fn basic_auth_provider_without_scopes() {
    let (port, log) = fake_basic_provider();
    let tmp = std::env::temp_dir().join(format!("sesame-basic-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let config = tmp.join("config");
    let sesame = |args: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sesame"));
        c.args(args).env("SESAME_CONFIG_DIR", &config);
        c
    };
    let run = |args: &[&str]| {
        let out = sesame(args).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(out.status.success(), "{args:?}: {err}");
        String::from_utf8_lossy(&out.stdout).to_string()
    };

    let base = format!("http://127.0.0.1:{port}");
    run(&[
        "provider",
        "add",
        "fake",
        "--auth-url",
        &format!("{base}/authorize"),
        "--token-url",
        &format!("{base}/token"),
        "--api-base",
        &format!("{base}/v1"),
        "--host",
        "127.0.0.1",
        "--auth-param",
        "owner=user",
        "--token-body",
        "json",
        "--client-auth",
        "basic",
        "--api-header",
        "Fake-Version: 2026-03-11",
        "--site-name-field",
        "workspace_name",
    ]);
    let shown: serde_json::Value =
        serde_json::from_str(&run(&["provider", "show", "fake"])).unwrap();
    assert_eq!(shown["client_auth"]["value"], "basic");
    assert_eq!(
        shown["api_headers"]["value"],
        serde_json::json!({"Fake-Version": "2026-03-11"})
    );
    assert_eq!(shown["site_name_field"]["value"], "workspace_name");
    assert_eq!(shown["scopes"]["value"], serde_json::json!([]));

    let mut client = sesame(&["client", "fake", "--client-id", "cid", "--secret-stdin"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    client
        .stdin
        .take()
        .unwrap()
        .write_all(b"the-secret\n")
        .unwrap();
    assert!(client.wait().unwrap().success());

    let mut login = sesame(&["login", "fake", "--no-browser"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut err = BufReader::new(login.stderr.take().unwrap());
    let auth_url = loop {
        let mut l = String::new();
        assert!(
            err.read_line(&mut l).unwrap() > 0,
            "login ended before printing a URL"
        );
        if let Some(u) = l.trim().strip_prefix("http") {
            break format!("http{u}");
        }
    };
    assert!(!auth_url.contains("scope="), "{auth_url}");
    let page = reqwest::blocking::get(&auth_url).unwrap().text().unwrap();
    assert!(page.contains("Signed in"));
    let status = login.wait().unwrap();
    let mut rest = String::new();
    err.read_to_string(&mut rest).unwrap();
    assert!(status.success(), "login failed: {rest}");
    assert!(rest.contains("Logged in to `fake` (Acme Space)"), "{rest}");
    assert!(run(&["providers"]).contains("logged in (Acme Space)"));

    // The first call gets a 401 and refreshes; the fixed header goes once.
    assert_eq!(
        run(&["api", "fake", "/v1/search", "-d", "{}"]).trim(),
        r#"["2026-03-11"]"#
    );
    // A -H of the same name (any case) replaces the fixed header.
    assert_eq!(
        run(&["api", "fake", "/search", "-H", "fake-version: 2022-06-28"]).trim(),
        r#"["2022-06-28"]"#
    );
    assert_eq!(run(&["token", "fake"]).trim(), "access-2");
    assert!(run(&["providers"]).contains("logged in (Acme Space)"));

    let db = rusqlite::Connection::open(config.join("sesame.db")).unwrap();
    let refresh: String = db
        .query_row(
            "SELECT refresh_token FROM tokens WHERE provider = 'fake'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(refresh, "refresh-2", "the rotated refresh token is kept");

    let log = log.lock().unwrap();
    assert!(
        log.iter()
            .any(|l| l.contains(r#""grant_type":"refresh_token""#)),
        "{log:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
