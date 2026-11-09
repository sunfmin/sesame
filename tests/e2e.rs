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
    assert!(
        out.contains("acme, figma, github, google, hubspot, jira, linear, notion"),
        "{out}"
    );

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
        out.contains("`sesame login google` asks only for: email, openid"),
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

/// A fake OAuth server: `answer(target, body)` gives the status line and the
/// JSON body for each request; every `target body` is logged.
fn serve(
    mut answer: impl FnMut(&str, &str) -> (&'static str, String) + Send + 'static,
) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (target, _, body) = read_request(&stream);
            log2.lock().unwrap().push(format!("{target} {body}"));
            let mut s = stream;
            if target.starts_with("/authorize") {
                // Play the provider's consent page: straight back to the redirect.
                let u = url::Url::parse(&format!("http://x{target}")).unwrap();
                let q = |k: &str| {
                    u.query_pairs()
                        .find(|(n, _)| n == k)
                        .unwrap()
                        .1
                        .into_owned()
                };
                let loc = format!("{}?code=the-code&state={}", q("redirect_uri"), q("state"));
                write!(s, "HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                continue;
            }
            let (status, b) = answer(&target, &body);
            write!(s, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()).unwrap();
        }
    });
    (port, log)
}

/// The device flow end to end with a client that has no secret: pending, then
/// slow_down, then a token; the account read after login; an expired code; and
/// `--browser` taking the loopback redirect on 127.0.0.1.
#[test]
fn device_flow_and_browser_fallback() {
    let mut devices = 0;
    let mut polls = 0;
    let (port, log) = serve(move |target, body| match target {
        "/device" => {
            devices += 1;
            let code = if devices == 1 {
                "dev-ok"
            } else {
                "dev-expired"
            };
            let b = format!(
                r#"{{"device_code":"{code}","user_code":"WDJB-MJHT","verification_uri":"https://example.com/device","expires_in":60,"interval":0}}"#
            );
            ("200 OK", b)
        }
        "/token" if body.contains("device_code=dev-expired") => {
            ("400 Bad Request", r#"{"error":"expired_token"}"#.into())
        }
        "/token" if body.contains("grant_type=urn") => {
            polls += 1;
            match polls {
                // RFC 8628 answers 400; GitHub answers 200 with the error.
                1 => (
                    "400 Bad Request",
                    r#"{"error":"authorization_pending"}"#.into(),
                ),
                2 => ("200 OK", r#"{"error":"slow_down","interval":1}"#.into()),
                _ => (
                    "200 OK",
                    r#"{"access_token":"device-token","scope":"repo"}"#.into(),
                ),
            }
        }
        "/token" => ("200 OK", r#"{"access_token":"browser-token"}"#.into()),
        "/user" => ("200 OK", r#"{"login":"octo","id":1}"#.into()),
        _ => ("404 Not Found", "{}".into()),
    });
    let tmp = std::env::temp_dir().join(format!("sesame-device-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let config = tmp.join("config");
    let sesame = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_sesame"))
            .args(args)
            .env("SESAME_CONFIG_DIR", &config)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr);
        (out.status.success(), text)
    };

    let base = format!("http://127.0.0.1:{port}");
    let (ok, out) = sesame(&[
        "provider",
        "add",
        "hub",
        "--auth-url",
        &format!("{base}/authorize"),
        "--token-url",
        &format!("{base}/token"),
        "--api-base",
        &base,
        "--host",
        "127.0.0.1",
        "--scope",
        "repo",
        "--device-url",
        &format!("{base}/device"),
        "--redirect-host",
        "127.0.0.1",
        "--identity-url",
        &format!("{base}/user"),
        "--identity-field",
        "login",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = sesame(&["provider", "show", "hub"]);
    assert!(ok, "{out}");
    let shown: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(shown["redirect_host"]["value"], "127.0.0.1");
    assert_eq!(shown["device_url"]["from"], "user");
    assert_eq!(shown["identity_field"]["value"], "login");
    let (ok, out) = sesame(&["setup", "hub"]);
    assert!(
        ok && out.contains("--no-secret") && out.contains("enters the code"),
        "{out}"
    );

    let (ok, out) = sesame(&["client", "hub", "--client-id", "cid", "--no-secret"]);
    assert!(ok, "{out}");

    let started = std::time::Instant::now();
    let (ok, out) = sesame(&["login", "hub", "--no-browser"]);
    assert!(ok, "{out}");
    assert!(
        out.contains("https://example.com/device") && out.contains("WDJB-MJHT"),
        "{out}"
    );
    assert!(out.contains("Logged in to `hub` (octo)"), "{out}");
    // The slow_down's interval of 1s was kept to.
    assert!(started.elapsed() >= std::time::Duration::from_secs(1));
    let (_, out) = sesame(&["providers"]);
    assert!(out.contains("logged in (octo)"), "{out}");
    let (ok, out) = sesame(&["token", "hub"]);
    assert!(ok && out.trim() == "device-token", "{out}");

    let (ok, out) = sesame(&["login", "hub", "--no-browser"]);
    assert!(!ok && out.contains("expired"), "{out}");

    // --browser: the loopback redirect, on 127.0.0.1 rather than localhost.
    let mut login = Command::new(env!("CARGO_BIN_EXE_sesame"))
        .args(["login", "hub", "--browser", "--no-browser"])
        .env("SESAME_CONFIG_DIR", &config)
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
    let redirect = url::Url::parse(&auth_url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "redirect_uri")
        .unwrap()
        .1
        .into_owned();
    assert!(redirect.starts_with("http://127.0.0.1:"), "{redirect}");
    let page = reqwest::blocking::get(&auth_url).unwrap().text().unwrap();
    assert!(page.contains("Signed in"));
    let status = login.wait().unwrap();
    let mut rest = String::new();
    err.read_to_string(&mut rest).unwrap();
    assert!(status.success(), "login --browser failed: {rest}");
    let (_, out) = sesame(&["token", "hub"]);
    assert_eq!(out.trim(), "browser-token");

    let log = log.lock().unwrap();
    assert!(log.iter().all(|l| !l.contains("client_secret")), "{log:?}");
    let device = log.iter().find(|l| l.starts_with("/device ")).unwrap();
    assert!(
        device.contains("client_id=cid") && device.contains("scope=repo"),
        "{device}"
    );
    let polls = log
        .iter()
        .filter(|l| l.contains("device_code=dev-ok"))
        .count();
    assert_eq!(polls, 3, "{log:?}");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// A Linear-shaped fake: comma-separated scopes, 24-hour tokens whose every
/// refresh hands out a new refresh token, and GraphQL errors under a 200.
fn fake_linear() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        let mut n = 1;
        for stream in listener.incoming().flatten() {
            let (target, headers, body) = read_request(&stream);
            log2.lock().unwrap().push(format!("{target} {body}"));
            let auth = header(&headers, "authorization").unwrap_or_default();
            let mut s = stream;
            let token = |n: i32| {
                format!(
                    r#"{{"access_token":"access-{n}","refresh_token":"refresh-{n}","expires_in":86399,"scope":"read,write"}}"#
                )
            };
            if target.starts_with("/authorize") {
                let u = url::Url::parse(&format!("http://x{target}")).unwrap();
                let q = |k: &str| {
                    u.query_pairs()
                        .find(|(m, _)| m == k)
                        .unwrap()
                        .1
                        .into_owned()
                };
                let loc = format!("{}?code=the-code&state={}", q("redirect_uri"), q("state"));
                reply(&mut s, "302 Found", &format!("Location: {loc}\r\n"), "");
            } else if target == "/oauth/token" {
                if body.contains("grant_type=authorization_code") {
                    reply(&mut s, "200 OK", "", &token(n));
                } else if body.contains(&format!("refresh_token=refresh-{n}")) {
                    n += 1;
                    reply(&mut s, "200 OK", "", &token(n));
                } else {
                    reply(
                        &mut s,
                        "400 Bad Request",
                        "",
                        r#"{"error":"invalid_grant"}"#,
                    );
                }
            } else if target == "/graphql" && auth == format!("Bearer access-{n}") {
                let b = if body.contains("broken") {
                    r#"{"data":null,"errors":[{"message":"Cannot query field \"broken\""}]}"#
                } else if body.contains("viewer { name }") {
                    r#"{"data":{"viewer":{"name":"Felix"}}}"#
                } else {
                    r#"{"data":{"viewer":{"id":"u1"}}}"#
                };
                reply(&mut s, "200 OK", "", b);
            } else if target == "/graphql" {
                reply(
                    &mut s,
                    "401 Unauthorized",
                    "",
                    r#"{"errors":[{"message":"auth"}]}"#,
                );
            } else {
                reply(&mut s, "404 Not Found", "", "");
            }
        }
    });
    (port, log)
}

/// The built-in `linear`, pointed at the fake: the authorization URL asks for
/// `read,write`, login names who signed in, a day later the token refreshes and
/// the new refresh token is kept, and GraphQL `errors` under a 200 fail `api`.
#[test]
fn linear_scopes_daily_refresh_graphql_errors() {
    let (port, log) = fake_linear();
    let tmp = std::env::temp_dir().join(format!("sesame-linear-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let config = tmp.join("config");
    std::fs::create_dir_all(&config).unwrap();
    let sesame = |args: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sesame"));
        c.args(args).env("SESAME_CONFIG_DIR", &config);
        c
    };
    let run = |args: &[&str]| {
        let out = sesame(args).output().unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };
    let db = || rusqlite::Connection::open(config.join("sesame.db")).unwrap();
    let stored = || {
        db().query_row(
            "SELECT refresh_token, expires_at FROM tokens WHERE provider = 'linear'",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
        )
        .unwrap()
    };
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    };
    // A day has passed: the stored access token is past its expiry.
    let a_day_later = || {
        db().execute(
            "UPDATE tokens SET expires_at = ?1 WHERE provider = 'linear'",
            [now() - 1],
        )
        .unwrap();
    };

    // 8752 is linear's fixed port; the test takes a free one so runs in
    // parallel (and a real `sesame login linear`) do not collide.
    let free = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
        .to_string();
    let base = format!("http://127.0.0.1:{port}");
    let (ok, _, err) = run(&[
        "provider",
        "set",
        "linear",
        "--auth-url",
        &format!("{base}/authorize"),
        "--token-url",
        &format!("{base}/oauth/token"),
        "--api-base",
        &base,
        "--host",
        "127.0.0.1",
        "--redirect-port",
        &free,
        "--identity-url",
        &format!("{base}/graphql"),
    ]);
    assert!(ok, "{err}");
    let (ok, out, err) = run(&["provider", "show", "linear"]);
    assert!(ok, "{err}");
    let shown: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(shown["scope_separator"]["value"], ",");
    assert_eq!(shown["scope_separator"]["from"], "built-in");
    assert_eq!(
        shown["error_fields"]["value"],
        serde_json::json!(["errors"])
    );

    let (ok, _, _) = run(&["client", "linear", "--client-id", "cid", "--secret-stdin"]);
    assert!(ok);

    let mut login = sesame(&["login", "linear", "--no-browser"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut err = BufReader::new(login.stderr.take().unwrap());
    let auth_url = loop {
        let mut l = String::new();
        assert!(err.read_line(&mut l).unwrap() > 0, "no URL printed");
        if let Some(u) = l.trim().strip_prefix("http") {
            break format!("http{u}");
        }
    };
    let u = url::Url::parse(&auth_url).unwrap();
    let scope = u.query_pairs().find(|(k, _)| k == "scope").unwrap().1;
    assert_eq!(scope, "read,write");
    let page = reqwest::blocking::get(&auth_url).unwrap().text().unwrap();
    assert!(page.contains("Signed in"));
    let status = login.wait().unwrap();
    let mut rest = String::new();
    err.read_to_string(&mut rest).unwrap();
    assert!(status.success(), "login failed: {rest}");
    assert!(rest.contains("Logged in to `linear` (Felix)"), "{rest}");

    let (refresh, expires) = stored();
    assert_eq!(refresh, "refresh-1");
    assert!((expires - now() - 86399).abs() < 60, "{expires}");
    let (_, out, _) = run(&["providers"]);
    assert!(out.contains("logged in (Felix)"), "{out}");

    let query = r#"{"query":"{ viewer { id } }"}"#;
    let (ok, out, err) = run(&["api", "linear", "/graphql", "-d", query]);
    assert!(ok, "{err}");
    assert!(out.contains("u1"), "{out}");

    // Two days in a row: each refresh rotates the refresh token and keeps the new one.
    for day in 2..=3 {
        a_day_later();
        let (ok, out, err) = run(&["api", "linear", "/graphql", "-d", query]);
        assert!(ok, "day {day}: {err}");
        assert!(out.contains("u1"), "{out}");
        assert_eq!(stored().0, format!("refresh-{day}"));
        assert!(stored().1 > now() + 86000);
    }

    let (ok, out, err) = run(&[
        "api",
        "linear",
        "/graphql",
        "-d",
        r#"{"query":"{ broken }"}"#,
    ]);
    assert!(!ok, "a 200 with errors passed: {out}");
    assert!(out.contains("Cannot query field"), "{out}");
    assert!(err.contains("`errors`"), "{err}");

    let log = log.lock().unwrap();
    let refreshes = log
        .iter()
        .filter(|l| l.contains("grant_type=refresh_token"))
        .count();
    assert_eq!(refreshes, 2, "{log:?}");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// A provider shaped like Figma's: HTTP Basic at the token endpoint, refresh
/// at its own endpoint whose answer has no refresh token, an authorization
/// code that lasts 30 seconds, and the account read from `/v1/me`.
#[test]
fn separate_refresh_endpoint_and_expired_code() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        // base64("cid:the-secret")
        let basic = "Basic Y2lkOnRoZS1zZWNyZXQ=";
        let mut exchanges = 0;
        let mut access = "access-1".to_string();
        for stream in listener.incoming().flatten() {
            let (target, headers, body) = read_request(&stream);
            let h = |k: &str| header(&headers, k).unwrap_or_default();
            log2.lock().unwrap().push(format!("{target} {body}"));
            let mut s = stream;
            if target.starts_with("/oauth?") {
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
            } else if target == "/v1/oauth/token" {
                assert_eq!(h("authorization"), basic);
                assert!(!body.contains("client_id") && !body.contains("client_secret"));
                assert!(body.contains("grant_type=authorization_code"), "{body}");
                exchanges += 1;
                if exchanges == 1 {
                    // The code came back too late.
                    reply(
                        &mut s,
                        "400 Bad Request",
                        "",
                        r#"{"error":true,"status":400,"message":"Invalid code"}"#,
                    );
                } else {
                    reply(
                        &mut s,
                        "200 OK",
                        "",
                        r#"{"user_id_string":"1","access_token":"access-1","token_type":"bearer","expires_in":7776000,"refresh_token":"refresh-1"}"#,
                    );
                }
            } else if target == "/v1/oauth/refresh" {
                assert_eq!(h("authorization"), basic);
                assert!(body.contains("refresh_token=refresh-1"), "{body}");
                assert!(!body.contains("client_secret"));
                access = "access-2".into();
                reply(
                    &mut s,
                    "200 OK",
                    "",
                    r#"{"access_token":"access-2","token_type":"bearer","expires_in":7776000}"#,
                );
            } else if target == "/v1/me"
                && h("authorization") == "Bearer access-1"
                && access == "access-1"
            {
                reply(
                    &mut s,
                    "200 OK",
                    "",
                    r#"{"id":"1","email":"felix@example.com","handle":"Felix"}"#,
                );
            } else if target.starts_with("/v1/files/") {
                if h("authorization") != format!("Bearer {access}") || access != "access-2" {
                    // Refused, to make the CLI refresh.
                    reply(&mut s, "401 Unauthorized", "", "{}");
                } else {
                    reply(&mut s, "200 OK", "", r#"{"name":"Design"}"#);
                }
            } else {
                reply(&mut s, "404 Not Found", "", "");
            }
        }
    });

    let tmp = std::env::temp_dir().join(format!("sesame-figma-{}", std::process::id()));
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
    // Plays the browser; returns whether login succeeded and what it printed.
    let login = || {
        let mut login = sesame(&["login", "fig", "--no-browser"])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut err = BufReader::new(login.stderr.take().unwrap());
        let mut printed = String::new();
        let auth_url = loop {
            let mut l = String::new();
            assert!(err.read_line(&mut l).unwrap() > 0, "no URL: {printed}");
            printed.push_str(&l);
            if let Some(u) = l.trim().strip_prefix("http") {
                break format!("http{u}");
            }
        };
        let page = reqwest::blocking::get(&auth_url).unwrap().text().unwrap();
        assert!(page.contains("Signed in"));
        let ok = login.wait().unwrap().success();
        err.read_to_string(&mut printed).unwrap();
        (ok, printed)
    };

    let base = format!("http://127.0.0.1:{port}");
    run(&[
        "provider",
        "add",
        "fig",
        "--auth-url",
        &format!("{base}/oauth"),
        "--token-url",
        &format!("{base}/v1/oauth/token"),
        "--refresh-url",
        &format!("{base}/v1/oauth/refresh"),
        "--api-base",
        &format!("{base}/v1"),
        "--host",
        "127.0.0.1",
        "--scope",
        "current_user:read",
        "--client-auth",
        "basic",
        "--code-seconds",
        "30",
        "--identity-url",
        &format!("{base}/v1/me"),
        "--identity-field",
        "email",
    ]);
    let shown: serde_json::Value =
        serde_json::from_str(&run(&["provider", "show", "fig"])).unwrap();
    assert_eq!(
        shown["refresh_url"]["value"],
        format!("{base}/v1/oauth/refresh")
    );
    assert_eq!(shown["code_seconds"]["value"], 30);
    let shown: serde_json::Value =
        serde_json::from_str(&run(&["provider", "show", "figma"])).unwrap();
    assert_eq!(
        shown["refresh_url"]["value"],
        "https://api.figma.com/v1/oauth/refresh"
    );
    assert_eq!(shown["redirect_port"]["value"], 8753);

    let mut client = sesame(&["client", "fig", "--client-id", "cid", "--secret-stdin"])
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

    let (ok, out) = login();
    assert!(!ok, "{out}");
    assert!(out.contains("within 30 seconds"), "{out}");
    assert!(
        out.contains("most likely expired (it lasts 30 seconds); run `sesame login fig` again"),
        "{out}"
    );

    let (ok, out) = login();
    assert!(ok, "{out}");
    assert!(
        out.contains("Logged in to `fig` (felix@example.com)"),
        "{out}"
    );
    assert!(run(&["providers"]).contains("logged in (felix@example.com)"));

    // A 401, a refresh at the refresh endpoint, then the call again.
    assert_eq!(
        run(&["api", "fig", "/files/abc"]).trim(),
        r#"{"name":"Design"}"#
    );
    assert_eq!(run(&["token", "fig"]).trim(), "access-2");

    let db = rusqlite::Connection::open(config.join("sesame.db")).unwrap();
    let refresh: String = db
        .query_row(
            "SELECT refresh_token FROM tokens WHERE provider = 'fig'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        refresh, "refresh-1",
        "the refresh answer had none: the old one is kept"
    );

    let log = log.lock().unwrap();
    assert!(
        !log.iter()
            .any(|l| l.starts_with("/v1/oauth/token ") && l.contains("refresh_token")),
        "{log:?}"
    );
    assert_eq!(
        log.iter()
            .filter(|l| l.starts_with("/v1/oauth/refresh "))
            .count(),
        1,
        "{log:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
/// A provider shaped like Slack's: the user token under `authed_user` next
/// to a bot token, the team name nested, and failures as HTTP 200 with
/// `"ok": false` and an `error` code.
fn fake_slack_provider() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (target, headers, body) = read_request(&stream);
            let auth = header(&headers, "authorization").unwrap_or_default();
            log2.lock().unwrap().push(format!("{target} {body}"));
            let mut s = stream;
            let t = target.as_str();
            if t.starts_with("/authorize") {
                let loc = format!(
                    "{}?code=the-code&state={}",
                    query(t, "redirect_uri").unwrap(),
                    query(t, "state").unwrap()
                );
                reply(&mut s, "302 Found", &format!("Location: {loc}\r\n"), "");
            } else if t == "/token" {
                reply(
                    &mut s,
                    "200 OK",
                    "",
                    r#"{"ok":true,"access_token":"xoxb-bot","team":{"id":"T1","name":"Acme"},
                       "authed_user":{"id":"U1","access_token":"xoxp-1","token_type":"user"}}"#,
                );
            } else if t == "/api/auth.test" {
                let b = if ["Bearer xoxp-1", "Bearer xoxp-pasted"].contains(&auth.as_str()) {
                    r#"{"ok":true,"user":"felix"}"#
                } else {
                    r#"{"ok":false,"error":"invalid_auth"}"#
                };
                reply(&mut s, "200 OK", "", b);
            } else if t.starts_with("/api/chat.postMessage") {
                reply(
                    &mut s,
                    "200 OK",
                    "",
                    r#"{"ok":false,"error":"channel_not_found"}"#,
                );
            } else {
                reply(&mut s, "404 Not Found", "", "");
            }
        }
    });
    (port, log)
}

fn query(target: &str, k: &str) -> Option<String> {
    let u = url::Url::parse(&format!("http://x{target}")).unwrap();
    u.query_pairs()
        .find(|(n, _)| n == k)
        .map(|(_, v)| v.into_owned())
}

/// A provider shaped like Slack: scopes in `user_scope`, no PKCE, the user
/// token under `authed_user`, an https callback whose address the person
/// pastes, failures as HTTP 200 with `"ok": false` and an `error` code; then a pasted token.
#[test]
fn https_paste_user_token_error_field_pasted_token() {
    let (port, log) = fake_slack_provider();
    let tmp = std::env::temp_dir().join(format!("sesame-paste-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let config = tmp.join("config");
    let sesame = |args: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sesame"));
        c.args(args).env("SESAME_CONFIG_DIR", &config);
        c
    };
    let run = |args: &[&str]| {
        let out = sesame(args).output().unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };

    let base = format!("http://127.0.0.1:{port}");
    let (ok_, _, err) = run(&[
        "provider",
        "add",
        "chat",
        "--auth-url",
        &format!("{base}/authorize"),
        "--token-url",
        &format!("{base}/token"),
        "--api-base",
        &format!("{base}/api"),
        "--host",
        "127.0.0.1",
        "--scope",
        "channels:read",
        "--scope",
        "chat:write",
        "--scope-param",
        "user_scope",
        "--pkce",
        "false",
        "--token-path",
        "/authed_user",
        "--site-name-field",
        "/team/name",
        "--redirect",
        "https-paste",
        "--redirect-port",
        // Not slack's 8751: a fixed port is one provider's only.
        "8761",
        "--error-field",
        "error",
    ]);
    assert!(ok_, "{err}");
    let (_, out, _) = run(&["provider", "show", "chat"]);
    let shown: serde_json::Value = serde_json::from_str(&out).unwrap();
    for (k, v) in [
        ("scope_param", serde_json::json!("user_scope")),
        ("pkce", serde_json::json!(false)),
        ("token_path", serde_json::json!("/authed_user")),
        ("site_name_field", serde_json::json!("/team/name")),
        ("redirect", serde_json::json!("https-paste")),
        ("error_fields", serde_json::json!(["error"])),
    ] {
        assert_eq!(
            shown[k],
            serde_json::json!({"value": v, "from": "user"}),
            "{k}"
        );
    }
    let (_, out, _) = run(&["setup", "chat"]);
    assert!(out.contains("https://localhost:8761/callback"), "{out}");
    assert!(run(&["client", "chat", "--client-id", "cid", "--no-secret"]).0);

    // Login: play the browser up to the https redirect, which nothing answers,
    // and paste the address it would end on. `tamper` edits that address.
    let login = |tamper: &dyn Fn(String) -> String| {
        let mut login = sesame(&["login", "chat", "--no-browser"])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut err = BufReader::new(login.stderr.take().unwrap());
        let auth_url = loop {
            let mut l = String::new();
            assert!(err.read_line(&mut l).unwrap() > 0, "no URL printed");
            if let Some(u) = l.trim().strip_prefix("http") {
                break format!("http{u}");
            }
        };
        let no_follow = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let resp = no_follow.get(&auth_url).send().unwrap();
        let landed = resp.headers()["location"].to_str().unwrap().to_string();
        assert!(
            landed.starts_with("https://localhost:8761/callback?code="),
            "{landed}"
        );
        let mut stdin = login.stdin.take().unwrap();
        writeln!(stdin, "{}", tamper(landed)).unwrap();
        drop(stdin);
        let status = login.wait().unwrap();
        let mut rest = String::new();
        err.read_to_string(&mut rest).unwrap();
        (status.success(), rest, auth_url)
    };

    let (ok_, err, _) = login(&|u| {
        let (head, _) = u.split_once("state=").unwrap();
        format!("{head}state=forged")
    });
    assert!(!ok_ && err.contains("state mismatch"), "{err}");
    assert!(!run(&["token", "chat"]).0, "a forged state stored a token");

    let (ok_, err, auth_url) = login(&|u| u);
    assert!(ok_, "{err}");
    assert!(err.contains("Logged in to `chat` (Acme)"), "{err}");
    assert_eq!(
        query(&auth_url[base.len()..], "user_scope").as_deref(),
        Some("channels:read chat:write")
    );
    for absent in ["scope", "code_challenge"] {
        assert_eq!(query(&auth_url[base.len()..], absent), None, "{auth_url}");
    }
    assert!(
        !log.lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("code_verifier")),
        "PKCE sent"
    );
    assert_eq!(run(&["token", "chat"]).1.trim(), "xoxp-1");
    let (_, out, _) = run(&["providers"]);
    assert!(out.contains("logged in (Acme)"), "{out}");

    let (ok_, out, err) = run(&["api", "chat", "/auth.test"]);
    assert!(ok_ && out.contains(r#""user":"felix""#), "{out}{err}");
    let (ok_, out, err) = run(&[
        "api",
        "chat",
        "/chat.postMessage",
        "-d",
        r#"{"channel":"C1","text":"hi"}"#,
    ]);
    assert!(!ok_, "ok:false exited zero");
    assert!(out.contains("channel_not_found"), "{out}");
    assert!(err.contains("carries `error`"), "{err}");

    // The fallback: a token pasted on stdin, no OAuth login.
    assert!(run(&["logout", "chat"]).0);
    let mut paste = sesame(&["login", "chat", "--token-stdin"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(paste.stdin.take().unwrap(), "xoxp-pasted").unwrap();
    assert!(paste.wait().unwrap().success());
    let (ok_, out, err) = run(&["api", "chat", "/auth.test"]);
    assert!(ok_ && out.contains("felix"), "{out}{err}");
    let (_, out, _) = run(&["providers"]);
    assert!(out.contains("logged in (pasted token)"), "{out}");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Signs in with `args` while playing the browser; returns the authorization URL.
fn browser_login(sesame: &dyn Fn(&[&str]) -> Command, args: &[&str]) -> (url::Url, String) {
    let mut login = sesame(args)
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
    let page = reqwest::blocking::get(&auth_url).unwrap().text().unwrap();
    assert!(page.contains("Signed in"));
    let status = login.wait().unwrap();
    let mut rest = String::new();
    err.read_to_string(&mut rest).unwrap();
    assert!(status.success(), "login failed: {rest}");
    (url::Url::parse(&auth_url).unwrap(), rest)
}

/// Two services of one provider: each login adds the service's scopes to those
/// granted, on one shared token; `api <service>` uses the service's base; a 403
/// for a missing scope names the login that adds it; names are one namespace.
#[test]
fn services_share_one_token() {
    let mut logins = 0;
    let (port, log) = serve(move |target, body| {
        match target {
        "/token" if body.contains("grant_type=authorization_code") => {
            logins += 1;
            let b = format!(r#"{{"access_token":"tok-{logins}","expires_in":3600}}"#);
            ("200 OK", b)
        }
        "/alpha/v1/things" => ("200 OK", r#"{"alpha":true}"#.into()),
        "/beta/v2/mail" => (
            "403 Forbidden",
            r#"{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT"}]}}"#.into(),
        ),
        "/beta/v2/ok" => ("200 OK", r#"{"beta":true}"#.into()),
        _ => ("404 Not Found", "{}".into()),
    }
    });
    let tmp = std::env::temp_dir().join(format!("sesame-services-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let config = tmp.join("config");
    let sesame = |args: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sesame"));
        c.args(args).env("SESAME_CONFIG_DIR", &config);
        c
    };
    let run = |args: &[&str]| {
        let out = sesame(args).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr);
        (out.status.success(), text)
    };

    let base = format!("http://127.0.0.1:{port}");
    let (ok, out) = run(&[
        "provider",
        "add",
        "fake",
        "--auth-url",
        &format!("{base}/authorize"),
        "--token-url",
        &format!("{base}/token"),
        "--api-base",
        &base,
        "--host",
        "127.0.0.1",
        "--scope",
        "openid",
        "--auth-param",
        "include_granted_scopes=true",
        "--service",
        &format!("name=alpha,api-base={base}/alpha/v1,scope=a.read,about=Alpha"),
        "--service",
        &format!(r#"{{"name": "beta", "api_base": "{base}/beta/v2", "scopes": ["b.read"]}}"#),
    ]);
    assert!(ok, "{out}");
    // `set` changes only the keys given of a service.
    let (ok, out) = run(&[
        "provider",
        "set",
        "fake",
        "--service",
        "name=beta,scope=b.read,scope=b.send",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = run(&["provider", "show", "fake"]);
    assert!(ok, "{out}");
    let shown: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        shown["services.beta"]["value"]["api_base"],
        format!("{base}/beta/v2")
    );
    assert_eq!(
        shown["services.beta"]["value"]["scopes"],
        serde_json::json!(["b.read", "b.send"])
    );
    assert_eq!(shown["services.alpha"]["from"], "user");

    // A service's name is used like a provider's: no two may share one.
    for (args, want) in [
        (
            vec![
                "provider",
                "set",
                "fake",
                "--service",
                "name=github,api-base=http://127.0.0.1/x",
            ],
            "`github` is already a provider",
        ),
        (
            vec![
                "provider",
                "set",
                "fake",
                "--service",
                "name=gmail,api-base=http://127.0.0.1/x",
            ],
            "both `fake` and `google`",
        ),
        (
            vec![
                "provider",
                "add",
                "alpha",
                "--auth-url",
                "https://x.example/a",
                "--token-url",
                "https://x.example/t",
                "--api-base",
                "https://x.example",
                "--host",
                "x.example",
            ],
            "`alpha` is already a provider",
        ),
        (
            vec![
                "provider",
                "set",
                "fake",
                "--service",
                "name=fake,api-base=http://127.0.0.1/x",
            ],
            "`fake` is already a provider",
        ),
        (
            vec![
                "provider",
                "set",
                "fake",
                "--service",
                "name=evil,api-base=https://evil.example",
            ],
            "evil.example is not one",
        ),
    ] {
        let (ok, out) = run(&args);
        assert!(!ok && out.contains(want), "{args:?}: {out}");
    }

    let (ok, out) = run(&["client", "alpha", "--client-id", "cid", "--no-secret"]);
    assert!(ok, "{out}");
    let (_, out) = run(&["providers"]);
    assert!(out.contains("next: sesame login alpha"), "{out}");

    let scope_of = |u: &url::Url| {
        let q = |k: &str| {
            u.query_pairs()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.into_owned())
        };
        assert_eq!(q("include_granted_scopes").as_deref(), Some("true"), "{u}");
        q("scope").unwrap()
    };
    let (u, rest) = browser_login(&sesame, &["login", "alpha", "--no-browser"]);
    assert_eq!(scope_of(&u), "openid a.read");
    assert!(rest.contains("Logged in to `fake` for `alpha`"), "{rest}");
    let (_, out) = run(&["providers"]);
    let line = |name: &str| {
        out.lines()
            .find(|l| l.trim_start().starts_with(&format!("{name} ")))
            .unwrap_or_default()
            .to_string()
    };
    assert!(line("alpha").contains(" authorized"), "{out}");
    assert!(line("beta").contains("not authorized"), "{out}");
    assert!(line("beta").contains("next: sesame login beta"), "{out}");

    // `api <service>` uses the service's base; beta's scope is not granted yet.
    let (ok, out) = run(&["api", "alpha", "/things"]);
    assert!(ok && out.contains(r#"{"alpha":true}"#), "{out}");
    let (ok, out) = run(&["api", "beta", "/mail"]);
    assert!(!ok && out.contains("run `sesame login beta`"), "{out}");
    // Through the provider with a full URL, the hint finds the service by its base.
    let (ok, out) = run(&["api", "fake", &format!("{base}/beta/v2/mail")]);
    assert!(!ok && out.contains("run `sesame login beta`"), "{out}");

    let (u, _) = browser_login(&sesame, &["login", "beta", "--no-browser"]);
    assert_eq!(scope_of(&u), "openid a.read b.read b.send");
    let (_, out) = run(&["providers"]);
    assert!(
        out.lines()
            .filter(|l| l.contains(" authorized") && !l.contains("not authorized"))
            .count()
            == 2,
        "{out}"
    );
    // One token, the newest, for the provider and both its services.
    for name in ["fake", "alpha", "beta"] {
        let (ok, out) = run(&["token", name]);
        assert!(ok && out.trim() == "tok-2", "{name}: {out}");
    }
    let (ok, out) = run(&["api", "beta", "ok"]);
    assert!(ok && out.contains(r#"{"beta":true}"#), "{out}");
    let db = rusqlite::Connection::open(config.join("sesame.db")).unwrap();
    let rows: i64 = db
        .query_row("SELECT count(*) FROM tokens", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 1);

    let (ok, out) = run(&["provider", "set", "fake", "--drop-service", "beta"]);
    assert!(ok, "{out}");
    let (ok, out) = run(&["api", "beta", "ok"]);
    assert!(!ok && out.contains("unknown provider `beta`"), "{out}");
    assert!(out.contains("or a service: alpha, calendar"), "{out}");

    let log = log.lock().unwrap();
    assert!(
        log.iter().any(|l| l.starts_with("/beta/v2/mail ")),
        "{log:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// A HubSpot-shaped fake: the code is exchanged and refreshed at
/// `/oauth/v3/token` with the client credentials in the form body, access
/// tokens last 30 minutes, and the account is the number `portalId`.
fn fake_hubspot() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        let mut n = 1;
        for stream in listener.incoming().flatten() {
            let (target, headers, body) = read_request(&stream);
            let auth = header(&headers, "authorization").unwrap_or_default();
            log2.lock().unwrap().push(format!("{target} {auth} {body}"));
            let mut s = stream;
            let token = |n: i32| {
                format!(
                    r#"{{"access_token":"access-{n}","refresh_token":"refresh-1","expires_in":1800,"hub_id":247935561,"token_type":"bearer"}}"#
                )
            };
            if target.starts_with("/oauth/authorize") {
                let loc = format!(
                    "{}?code=the-code&state={}",
                    query(&target, "redirect_uri").unwrap(),
                    query(&target, "state").unwrap()
                );
                reply(&mut s, "302 Found", &format!("Location: {loc}\r\n"), "");
            } else if target == "/oauth/v3/token" {
                let body_creds = body.contains("client_id=cid")
                    && body.contains("client_secret=the-secret")
                    && !auth.starts_with("Basic");
                if !body_creds {
                    reply(&mut s, "401 Unauthorized", "", r#"{"status":"error"}"#);
                } else if body.contains("grant_type=authorization_code") {
                    reply(&mut s, "200 OK", "", &token(n));
                } else if body.contains("grant_type=refresh_token")
                    && body.contains("refresh_token=refresh-1")
                {
                    n += 1;
                    reply(&mut s, "200 OK", "", &token(n));
                } else {
                    reply(&mut s, "400 Bad Request", "", r#"{"status":"BAD_GRANT"}"#);
                }
            } else if auth != format!("Bearer access-{n}") {
                reply(&mut s, "401 Unauthorized", "", r#"{"status":"error"}"#);
            } else if target == "/account-info/v3/details" {
                reply(
                    &mut s,
                    "200 OK",
                    "",
                    r#"{"portalId":247935561,"uiDomain":"app-na2.hubspot.com"}"#,
                );
            } else if target.starts_with("/crm/v3/objects/contacts") {
                reply(&mut s, "200 OK", "", r#"{"results":[{"id":"1"}]}"#);
            } else {
                reply(&mut s, "404 Not Found", "", "");
            }
        }
    });
    (port, log)
}

/// Someone who added `hubspot` themselves (`sesame provider add`, every field
/// stored) upgrades to the version where it is built in: the fields equal to
/// the built-in show as `built-in`, only real changes as `user`. Login reads
/// the numeric `portalId`; a token about to expire refreshes at the same v3
/// endpoint with the credentials in the body. `setup` prints the built-in's steps.
#[test]
fn hubspot_upgrade_v3_body_refresh_numeric_identity() {
    let (port, log) = fake_hubspot();
    let tmp = std::env::temp_dir().join(format!("sesame-hubspot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let config = tmp.join("config");
    std::fs::create_dir_all(&config).unwrap();
    let sesame = |args: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sesame"));
        c.args(args).env("SESAME_CONFIG_DIR", &config);
        c
    };
    let run = |args: &[&str]| {
        let out = sesame(args).output().unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };
    let db = || rusqlite::Connection::open(config.join("sesame.db")).unwrap();
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    };

    // The built-in's setup: its four steps, the fixed localhost callback, the scopes.
    let (ok, out, err) = run(&["setup", "hubspot"]);
    assert!(ok, "{err}");
    for want in [
        "Install the HubSpot CLI and sign it in",
        "Create a private OAuth app project",
        "Set the redirect URL and scopes, then upload",
        "Copy the client ID and secret",
        r#""redirectUrls" to ["http://localhost:8754/callback"]"#,
        "hs project upload --forceCreate",
        "oauth, crm.objects.contacts.read, crm.objects.contacts.write",
        "crm.objects.owners.read, crm.objects.tickets.read, crm.objects.tickets.write",
    ] {
        assert!(out.contains(want), "no `{want}` in:\n{out}");
    }

    // Before the upgrade: every field of the definition stored as the person's,
    // as `sesame provider add hubspot` left it, but pointed at the fake.
    let (ok, out, err) = run(&["provider", "show", "hubspot"]);
    assert!(ok, "{err}");
    let shown: serde_json::Value = serde_json::from_str(&out).unwrap();
    let base = format!("http://127.0.0.1:{port}");
    let free = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let changed = serde_json::json!({
        "auth_url": format!("{base}/oauth/authorize"),
        "token_url": format!("{base}/oauth/v3/token"),
        "api_base": base,
        "hosts": ["127.0.0.1"],
        "redirect_port": free,
        "identity_url": format!("{base}/account-info/v3/details"),
    });
    {
        let db = db();
        for (field, entry) in shown.as_object().unwrap() {
            let value = changed.get(field).unwrap_or(&entry["value"]);
            db.execute(
                "INSERT INTO provider_fields (provider, field, value) VALUES ('hubspot', ?1, ?2)",
                [field, &value.to_string()],
            )
            .unwrap();
        }
    }
    let (ok, out, err) = run(&["provider", "show", "hubspot"]);
    assert!(ok, "{err}");
    let shown: serde_json::Value = serde_json::from_str(&out).unwrap();
    for (field, entry) in shown.as_object().unwrap() {
        let from = if changed.get(field).is_some() {
            "user"
        } else {
            "built-in"
        };
        assert_eq!(entry["from"], from, "{field}: {entry}");
    }
    assert_eq!(shown["client_auth"]["value"], "body");
    assert_eq!(shown["redirect_host"]["value"], "localhost");

    let mut c = sesame(&["client", "hubspot", "--client-id", "cid", "--secret-stdin"]);
    let mut child = c.stdin(Stdio::piped()).spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"the-secret\n")
        .unwrap();
    assert!(child.wait().unwrap().success());

    let (auth, rest) = browser_login(&sesame, &["login", "hubspot", "--no-browser"]);
    let q = |k: &str| {
        auth.query_pairs()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.into_owned())
    };
    assert_eq!(
        q("redirect_uri").unwrap(),
        format!("http://localhost:{free}/callback")
    );
    assert!(
        q("scope")
            .unwrap()
            .starts_with("oauth crm.objects.contacts.read ")
    );
    assert_eq!(q("code_challenge_method").as_deref(), Some("S256"));
    assert!(
        rest.contains("Logged in to `hubspot` (247935561)"),
        "{rest}"
    );
    let (_, out, _) = run(&["providers"]);
    assert!(out.contains("logged in (247935561)"), "{out}");

    let expires = || {
        db().query_row(
            "SELECT expires_at FROM tokens WHERE provider = 'hubspot'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
    };
    assert!((expires() - now() - 1800).abs() < 60, "{}", expires());

    let (ok, out, err) = run(&["api", "hubspot", "/crm/v3/objects/contacts?limit=1"]);
    assert!(ok, "{err}");
    assert!(out.contains(r#""id":"1""#), "{out}");

    // 29 and a half minutes later: the token has 30 seconds left and is refreshed first.
    db().execute(
        "UPDATE tokens SET expires_at = ?1 WHERE provider = 'hubspot'",
        [now() + 30],
    )
    .unwrap();
    let (ok, out, err) = run(&["api", "hubspot", "/crm/v3/objects/contacts?limit=1"]);
    assert!(ok, "{err}");
    assert!(out.contains(r#""id":"1""#), "{out}");
    assert!(expires() > now() + 1700);

    let log = log.lock().unwrap();
    let refreshes: Vec<_> = log
        .iter()
        .filter(|l| l.contains("grant_type=refresh_token"))
        .collect();
    assert_eq!(refreshes.len(), 1, "{log:?}");
    assert!(refreshes[0].starts_with("/oauth/v3/token "), "{log:?}");
    assert!(refreshes[0].contains("client_secret=the-secret"), "{log:?}");
    // Before the expiry, not after a 401: each API call went out once, the
    // second already with the refreshed token.
    let calls: Vec<_> = log.iter().filter(|l| l.starts_with("/crm")).collect();
    assert_eq!(calls.len(), 2, "{log:?}");
    assert!(calls[1].contains("Bearer access-2"), "{log:?}");
    let _ = std::fs::remove_dir_all(&tmp);
}
