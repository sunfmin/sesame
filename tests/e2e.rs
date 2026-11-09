//! The whole flow against a fake provider on 127.0.0.1: client, login (the
//! test plays the browser), api, refresh after a 401, token, logout.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

fn fake_provider() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        let mut access = "access-1".to_string();
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
            let mut s = stream;
            let reply = |s: &mut std::net::TcpStream, status: &str, extra: &str, b: &str| {
                write!(s, "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()).unwrap();
            };
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
    let tmp = std::env::temp_dir().join(format!("saas-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (config, store) = (tmp.join("config"), tmp.join("store"));
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join("providers.toml"),
        format!(
            r#"[fake]
auth_url = "http://127.0.0.1:{port}/authorize"
token_url = "http://127.0.0.1:{port}/token"
api_base = "http://127.0.0.1:{port}/ex/{{resource_id}}"
hosts = ["127.0.0.1"]
scopes = ["read"]
resources_url = "http://127.0.0.1:{port}/sites"
"#
        ),
    )
    .unwrap();
    let saas = |args: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_saas"));
        c.args(args)
            .env("SAAS_CONFIG_DIR", &config)
            .env("SAAS_STORE_DIR", &store);
        c
    };

    let st = saas(&["client", "fake", "--client-id", "cid", "--no-secret"])
        .status()
        .unwrap();
    assert!(st.success());

    let mut login = saas(&["login", "fake", "--no-browser"])
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

    let out = saas(&["api", "fake", "/me"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), r#"{"me":"felix"}"#);

    let out = saas(&["token", "fake"]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "access-2");

    let out = saas(&["api", "fake", "https://evil.example/steal"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("refusing to send the token"));

    assert!(saas(&["logout", "fake"]).status().unwrap().success());
    assert!(!saas(&["token", "fake"]).status().unwrap().success());

    let log = log.lock().unwrap();
    assert!(
        log.iter().any(|l| l.contains("grant_type=refresh_token")),
        "{log:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
