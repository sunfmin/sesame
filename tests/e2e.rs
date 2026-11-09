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
        out.contains("acme, figma, github, google, jira, notion"),
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
