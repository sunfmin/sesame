//! The whole flow against a fake provider on 127.0.0.1: client, login (the
//! test plays the browser), api, refresh after a 401, token, logout.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

/// A request the fake server got, and what it answers.
struct Request {
    target: String,
    auth: String,
    body: String,
}
type Reply = (&'static str, String, String);

/// An HTTP server on 127.0.0.1 answering with `handle`; it logs each request
/// as `<target> <body>`.
fn serve(
    mut handle: impl FnMut(&Request) -> Reply + Send + 'static,
) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
            let (mut auth, mut len) = (String::new(), 0usize);
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                if h.trim().is_empty() {
                    break;
                }
                let lower = h.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                if lower.starts_with("authorization:") {
                    auth = h["authorization:".len()..].trim().to_string();
                }
            }
            let mut body = vec![0; len];
            reader.read_exact(&mut body).unwrap();
            let body = String::from_utf8(body).unwrap();
            log2.lock().unwrap().push(format!("{target} {body}"));
            let (status, extra, b) = handle(&Request { target, auth, body });
            let mut s = stream;
            write!(
                s,
                "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{b}",
                b.len()
            )
            .unwrap();
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

/// The provider's authorization page approving at once: a redirect to the
/// `redirect_uri` with a code and the `state`.
fn approve(target: &str) -> Reply {
    let loc = format!(
        "{}?code=the-code&state={}",
        query(target, "redirect_uri").unwrap(),
        query(target, "state").unwrap()
    );
    ("302 Found", format!("Location: {loc}\r\n"), String::new())
}

fn ok(b: &str) -> Reply {
    ("200 OK", String::new(), b.into())
}

fn fake_provider() -> (u16, Arc<Mutex<Vec<String>>>) {
    let mut access = "access-1".to_string();
    serve(move |r| {
        if r.target.starts_with("/authorize") {
            approve(&r.target)
        } else if r.target == "/token" {
            if r.body.contains("grant_type=authorization_code") {
                assert!(r.body.contains("code=the-code") && r.body.contains("code_verifier="));
                ok(r#"{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}"#)
            } else {
                assert!(r.body.contains("refresh_token=refresh-1"));
                access = "access-2".into();
                ok(r#"{"access_token":"access-2","expires_in":3600}"#)
            }
        } else if r.target == "/sites" {
            ok(r#"[{"id":"site-9","name":"acme","url":"https://acme.example"}]"#)
        } else if r.target.starts_with("/ex/site-9/me") {
            if r.auth == format!("Bearer {access}") && access == "access-2" {
                ok(r#"{"me":"felix"}"#)
            } else {
                // The first call is refused, to make the CLI refresh.
                access = "access-1-revoked".into();
                ("401 Unauthorized", String::new(), "{}".into())
            }
        } else {
            ("404 Not Found", String::new(), String::new())
        }
    })
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

/// A provider shaped like Slack: scopes in `user_scope`, no PKCE, the user
/// token under `authed_user`, an https callback whose address the person
/// pastes, failures as HTTP 200 with `"ok": false`; then a pasted token.
#[test]
fn https_paste_user_token_ok_field_pasted_token() {
    let (port, log) = serve(|r| {
        let t = r.target.as_str();
        if t.starts_with("/authorize") {
            approve(t)
        } else if t == "/token" {
            ok(
                r#"{"ok":true,"access_token":"xoxb-bot","team":{"id":"T1","name":"Acme"},
                   "authed_user":{"id":"U1","access_token":"xoxp-1","token_type":"user"}}"#,
            )
        } else if t == "/api/auth.test" {
            if ["Bearer xoxp-1", "Bearer xoxp-pasted"].contains(&r.auth.as_str()) {
                ok(r#"{"ok":true,"user":"felix"}"#)
            } else {
                ok(r#"{"ok":false,"error":"invalid_auth"}"#)
            }
        } else if t.starts_with("/api/chat.postMessage") {
            ok(r#"{"ok":false,"error":"channel_not_found"}"#)
        } else {
            ("404 Not Found", String::new(), String::new())
        }
    });
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
        "--account-path",
        "/team/name",
        "--redirect",
        "https-paste",
        "--redirect-port",
        "8751",
        "--ok-field",
        "ok",
    ]);
    assert!(ok_, "{err}");
    let (_, out, _) = run(&["provider", "show", "chat"]);
    let shown: serde_json::Value = serde_json::from_str(&out).unwrap();
    for (k, v) in [
        ("scope_param", serde_json::json!("user_scope")),
        ("pkce", serde_json::json!(false)),
        ("token_path", serde_json::json!("/authed_user")),
        ("account_path", serde_json::json!("/team/name")),
        ("redirect", serde_json::json!("https-paste")),
        ("ok_field", serde_json::json!("ok")),
    ] {
        assert_eq!(
            shown[k],
            serde_json::json!({"value": v, "from": "user"}),
            "{k}"
        );
    }
    let (_, out, _) = run(&["setup", "chat"]);
    assert!(out.contains("https://localhost:8751/callback"), "{out}");
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
            landed.starts_with("https://localhost:8751/callback?code="),
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
    assert!(err.contains(r#""ok": false"#), "{err}");

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
