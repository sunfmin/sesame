//! The whole flow against a fake provider on 127.0.0.1: client, login (the
//! test plays the browser), api, refresh after a 401, token, logout.
#[path = "support/harness.rs"]
mod harness;

use harness::{FakeProvider, FakeVault, Machine, SA_TOKEN, VAULT, field, param};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn login_call_refresh_logout() {
    let mut access = "access-1".to_string();
    let fake = FakeProvider::serve(move |r| match r.target.as_str() {
        "/token" if r.body.contains("grant_type=authorization_code") => {
            assert!(r.body.contains("code=the-code") && r.body.contains("code_verifier="));
            (
                "200 OK",
                r#"{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}"#
                    .into(),
            )
        }
        "/token" => {
            assert!(r.body.contains("refresh_token=refresh-1"));
            access = "access-2".into();
            (
                "200 OK",
                r#"{"access_token":"access-2","expires_in":3600}"#.into(),
            )
        }
        "/sites" => (
            "200 OK",
            r#"[{"id":"site-9","name":"acme","url":"https://acme.example"}]"#.into(),
        ),
        t if t.starts_with("/ex/site-9/me") => {
            if r.header("authorization") == format!("Bearer {access}") && access == "access-2" {
                ("200 OK", r#"{"me":"felix"}"#.into())
            } else {
                // The first call is refused, to make the CLI refresh.
                access = "access-1-revoked".into();
                ("401 Unauthorized", "{}".into())
            }
        }
        _ => ("404 Not Found", String::new()),
    });
    let m = Machine::new("e2e");
    let sites = format!("{}/sites", fake.base());
    fake.add(
        &m,
        "fake",
        "/ex/{resource_id}",
        &["--scope", "read", "--resources-url", &sites],
    );
    assert!(
        m.run(&["client", "fake", "--client-id", "cid", "--no-secret"])
            .ok
    );
    m.login_in_browser(&["login", "fake", "--no-browser"]);

    let out = m.run(&["api", "fake", "/me"]);
    assert!(out.ok, "{}", out.stderr);
    assert_eq!(out.stdout, r#"{"me":"felix"}"#);

    assert_eq!(m.run(&["token", "fake"]).stdout.trim(), "access-2");

    // `--json`: the token with its expiry, one line; the refresh gave 3600 seconds.
    let out = m.run(&["token", "fake", "--json"]);
    assert!(out.ok);
    let line = out.stdout;
    assert_eq!(line.lines().count(), 1, "{line}");
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["access_token"], "access-2");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_at = v["expires_at"]
        .as_u64()
        .expect("expires_at in unix seconds");
    assert!(
        (now + 3500..=now + 3600).contains(&expires_at),
        "{expires_at} vs {now}"
    );

    let out = m.run(&["api", "fake", "https://evil.example/steal"]);
    assert!(!out.ok);
    assert!(out.stderr.contains("refusing to send the token"));

    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(m.config().join("sesame.db"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    assert!(m.run(&["logout", "fake"]).ok);
    assert!(!m.run(&["token", "fake"]).ok);

    assert!(!fake.refreshes().is_empty(), "{:?}", fake.requests());
}

/// First use: no client yet. Every command names the next one to run, and a
/// provider added with `sesame provider add` prints its own setup steps.
#[test]
fn first_use_points_to_setup() {
    let m = Machine::new("setup");
    let out = m.run(&[
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
    assert!(out.ok, "{out}");

    let out = m.run(&["setup", "acme"]);
    let text = out.text();
    assert!(out.ok, "{out}");
    assert!(text.contains("1. Register the app"), "{out}");
    assert!(text.contains("Open: https://acme.example/apps"), "{out}");
    assert!(
        text.contains("Callback: http://localhost:9321/callback; scopes: read, write"),
        "{out}"
    );
    assert!(
        text.contains("sesame client acme --client-id <client id>"),
        "{out}"
    );

    let out = m.run(&["setup", "jira"]);
    assert!(
        out.ok && out.text().contains("http://localhost:8749/callback"),
        "{out}"
    );

    let out = m.run(&["setup", "nope"]);
    assert!(!out.ok);
    assert!(out.text().contains("unknown provider `nope`"), "{out}");
    assert!(
        out.text()
            .contains("acme, figma, github, google, hubspot, jira, linear, notion"),
        "{out}"
    );

    let out = m.run(&["providers"]);
    assert!(out.text().contains("next: sesame setup acme"), "{out}");

    for cmd in [
        &["login", "acme", "--no-browser"][..],
        &["api", "acme", "/x"],
    ] {
        let out = m.run(cmd);
        assert!(!out.ok);
        assert!(
            out.text().contains("run `sesame setup acme`"),
            "{cmd:?}: {out}"
        );
    }

    assert!(
        m.run(&["client", "acme", "--client-id", "cid", "--no-secret"])
            .ok
    );
    let out = m.run(&["providers"]);
    assert!(out.text().contains("next: sesame login acme"), "{out}");
    let out = m.run(&["api", "acme", "/x"]);
    assert!(
        !out.ok && out.text().contains("run `sesame login acme`"),
        "{out}"
    );

    let out = m.run(&["--help"]).text();
    assert!(out.starts_with("If you are an AI"), "{out}");
    assert!(out.contains("sesame setup <provider>"), "{out}");
    assert!(!out.contains("providers.toml"), "{out}");
}

/// `provider set` on a built-in stores only the changed field, `rm` brings the
/// built-in back, and an invalid value writes nothing.
#[test]
fn provider_set_show_rm() {
    let m = Machine::new("provider");
    let show = |name: &str| -> serde_json::Value {
        let out = m.run(&["provider", "show", name]);
        assert!(out.ok, "{}", out.stderr);
        serde_json::from_str(&out.stdout).unwrap()
    };
    let field_db_rows = || {
        let db = rusqlite::Connection::open(m.config().join("sesame.db")).unwrap();
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

    let out = m.run(&[
        "provider", "set", "google", "--scope", "email", "--scope", "openid",
    ]);
    assert!(out.ok, "{}", out.stderr);
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
    let out = m.run(&["setup", "google"]).stdout;
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
        let out = m.run(bad);
        assert!(!out.ok, "{bad:?} was accepted");
        assert!(
            out.stderr.starts_with("sesame: "),
            "{bad:?}: {}",
            out.stderr
        );
    }
    assert_eq!(field_db_rows(), 1);
    assert_eq!(show("google"), after);
    let out = m.run(&["provider", "show", "bad"]);
    assert!(
        !out.ok && out.stderr.contains("unknown provider `bad`"),
        "{out}"
    );

    let out = m.run(&["provider", "add", "jira", "--host", "x.example"]);
    assert!(
        !out.ok && out.stderr.contains("sesame provider set jira"),
        "{out}"
    );

    let out = m.run(&["provider", "rm", "google"]);
    assert!(out.ok && out.stderr.contains("built-in"), "{out}");
    assert_eq!(show("google"), before);
    assert_eq!(field_db_rows(), 0);

    let out = m.run(&["provider", "set", "nope", "--scope", "x"]);
    assert!(
        !out.ok && out.stderr.contains("sesame provider add nope"),
        "{out}"
    );
}

/// The device flow end to end with a client that has no secret: pending, then
/// slow_down, then a token; the account read after login; an expired code; and
/// `--browser` taking the loopback redirect on 127.0.0.1.
#[test]
fn device_flow_and_browser_fallback() {
    let mut devices = 0;
    let mut polls = 0;
    let fake = FakeProvider::serve(move |r| match r.target.as_str() {
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
        "/token" if r.body.contains("device_code=dev-expired") => {
            ("400 Bad Request", r#"{"error":"expired_token"}"#.into())
        }
        "/token" if r.body.contains("grant_type=urn") => {
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
    let m = Machine::new("device");
    let base = fake.base();
    fake.add(
        &m,
        "hub",
        "",
        &[
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
        ],
    );
    let out = m.run(&["provider", "show", "hub"]);
    assert!(out.ok, "{out}");
    let shown: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(shown["redirect_host"]["value"], "127.0.0.1");
    assert_eq!(shown["device_url"]["from"], "user");
    assert_eq!(shown["identity_field"]["value"], "login");
    let out = m.run(&["setup", "hub"]);
    assert!(
        out.ok && out.text().contains("--no-secret") && out.text().contains("enters the code"),
        "{out}"
    );

    let out = m.run(&["client", "hub", "--client-id", "cid", "--no-secret"]);
    assert!(out.ok, "{out}");

    let started = std::time::Instant::now();
    let out = m.run(&["login", "hub", "--no-browser"]);
    let text = out.text();
    assert!(out.ok, "{out}");
    assert!(
        text.contains("https://example.com/device") && text.contains("WDJB-MJHT"),
        "{out}"
    );
    assert!(text.contains("Logged in to `hub` (octo)"), "{out}");
    // The slow_down's interval of 1s was kept to.
    assert!(started.elapsed() >= std::time::Duration::from_secs(1));
    let out = m.run(&["providers"]);
    assert!(out.text().contains("logged in (octo)"), "{out}");
    let out = m.run(&["token", "hub"]);
    assert!(out.ok && out.text().trim() == "device-token", "{out}");

    let out = m.run(&["login", "hub", "--no-browser"]);
    assert!(!out.ok && out.text().contains("expired"), "{out}");

    // --browser: the loopback redirect, on 127.0.0.1 rather than localhost.
    let (auth_url, _) = m.login_in_browser(&["login", "hub", "--browser", "--no-browser"]);
    let redirect = param(&auth_url, "redirect_uri").unwrap();
    assert!(redirect.starts_with("http://127.0.0.1:"), "{redirect}");
    assert_eq!(m.run(&["token", "hub"]).text().trim(), "browser-token");

    let log = fake.requests();
    assert!(
        log.iter().all(|r| !r.to_string().contains("client_secret")),
        "{log:?}"
    );
    let device = &fake.to("/device")[0].body;
    assert!(
        device.contains("client_id=cid") && device.contains("scope=repo"),
        "{device}"
    );
    let polls = log
        .iter()
        .filter(|r| r.body.contains("device_code=dev-ok"))
        .count();
    assert_eq!(polls, 3, "{log:?}");
}

/// The https-paste flow: nothing listens on the https callback, the person
/// pastes the address the browser ended on, whose state must be this login's;
/// then a token pasted on stdin, with no OAuth login.
#[test]
fn https_paste_login_and_pasted_token() {
    let fake = FakeProvider::serve(|r| match r.target.as_str() {
        "/token" => ("200 OK", r#"{"access_token":"tok-1"}"#.into()),
        "/api/auth.test" => ("200 OK", r#"{"user":"felix"}"#.into()),
        _ => ("404 Not Found", "{}".into()),
    });
    let m = Machine::new("paste");
    fake.add(
        &m,
        "chat",
        "/api",
        // Not slack's 8751: a fixed port is one provider's only.
        &["--redirect", "https-paste", "--redirect-port", "8761"],
    );
    let out = m.run(&["setup", "chat"]).stdout;
    assert!(out.contains("https://localhost:8761/callback"), "{out}");
    assert!(
        m.run(&["client", "chat", "--client-id", "cid", "--no-secret"])
            .ok
    );

    // Login: play the browser up to the https redirect, which nothing answers,
    // and paste the address it would end on. `tamper` edits that address.
    let login = |tamper: &dyn Fn(String) -> String| {
        m.login_pasting(&["login", "chat", "--no-browser"], |landed| {
            assert!(
                landed.starts_with("https://localhost:8761/callback?code="),
                "{landed}"
            );
            tamper(landed)
        })
    };

    let out = login(&|u| {
        let (head, _) = u.split_once("state=").unwrap();
        format!("{head}state=forged")
    });
    assert!(!out.ok && out.stderr.contains("state mismatch"), "{out}");
    assert!(
        !m.run(&["token", "chat"]).ok,
        "a forged state stored a token"
    );

    let out = login(&|u| u);
    assert!(out.ok, "{out}");
    assert_eq!(m.run(&["token", "chat"]).stdout.trim(), "tok-1");
    let out = m.run(&["api", "chat", "/auth.test"]);
    assert!(out.ok && out.stdout.contains(r#""user":"felix""#), "{out}");

    // The fallback: a token pasted on stdin, no OAuth login.
    assert!(m.run(&["logout", "chat"]).ok);
    assert!(
        m.run_with_stdin(&["login", "chat", "--token-stdin"], "xoxp-pasted\n")
            .ok
    );
    let out = m.run(&["api", "chat", "/auth.test"]);
    assert!(out.ok && out.stdout.contains("felix"), "{out}");
    let out = m.run(&["providers"]).stdout;
    assert!(out.contains("logged in (pasted token)"), "{out}");
    // A pasted token has no known expiry.
    let out = m.run(&["token", "chat", "--json"]);
    assert!(out.ok, "{}", out.stderr);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&out.stdout).unwrap(),
        serde_json::json!({"access_token": "xoxp-pasted", "expires_at": null})
    );
}

/// Two services of one provider: each login adds the service's scopes to those
/// granted, on one shared token; `api <service>` uses the service's base; a 403
/// for a missing scope names the login that adds it; names are one namespace.
#[test]
fn services_share_one_token() {
    let mut logins = 0;
    let fake = FakeProvider::serve(move |r| {
        match r.target.as_str() {
        "/token" if r.body.contains("grant_type=authorization_code") => {
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
    let m = Machine::new("services");
    let base = fake.base();
    fake.add(
        &m,
        "fake",
        "",
        &[
            "--scope",
            "openid",
            "--auth-param",
            "include_granted_scopes=true",
            "--service",
            &format!("name=alpha,api-base={base}/alpha/v1,scope=a.read,about=Alpha"),
            "--service",
            &format!(r#"{{"name": "beta", "api_base": "{base}/beta/v2", "scopes": ["b.read"]}}"#),
        ],
    );
    // `set` changes only the keys given of a service.
    let out = m.run(&[
        "provider",
        "set",
        "fake",
        "--service",
        "name=beta,scope=b.read,scope=b.send",
    ]);
    assert!(out.ok, "{out}");
    let out = m.run(&["provider", "show", "fake"]);
    assert!(out.ok, "{out}");
    let shown: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
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
        let out = m.run(&args);
        assert!(!out.ok && out.text().contains(want), "{args:?}: {out}");
    }

    let out = m.run(&["client", "alpha", "--client-id", "cid", "--no-secret"]);
    assert!(out.ok, "{out}");
    let out = m.run(&["providers"]);
    assert!(out.text().contains("next: sesame login alpha"), "{out}");

    let scope_of = |u: &url::Url| {
        assert_eq!(
            param(u, "include_granted_scopes").as_deref(),
            Some("true"),
            "{u}"
        );
        param(u, "scope").unwrap()
    };
    let (u, rest) = m.login_in_browser(&["login", "alpha", "--no-browser"]);
    assert_eq!(scope_of(&u), "openid a.read");
    assert!(rest.contains("Logged in to `fake` for `alpha`"), "{rest}");
    let out = m.run(&["providers"]).text();
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
    let out = m.run(&["api", "alpha", "/things"]);
    assert!(out.ok && out.text().contains(r#"{"alpha":true}"#), "{out}");
    let out = m.run(&["api", "beta", "/mail"]);
    assert!(
        !out.ok && out.text().contains("run `sesame login beta`"),
        "{out}"
    );
    // Through the provider with a full URL, the hint finds the service by its base.
    let out = m.run(&["api", "fake", &format!("{base}/beta/v2/mail")]);
    assert!(
        !out.ok && out.text().contains("run `sesame login beta`"),
        "{out}"
    );

    let (u, _) = m.login_in_browser(&["login", "beta", "--no-browser"]);
    assert_eq!(scope_of(&u), "openid a.read b.read b.send");
    let out = m.run(&["providers"]).text();
    assert!(
        out.lines()
            .filter(|l| l.contains(" authorized") && !l.contains("not authorized"))
            .count()
            == 2,
        "{out}"
    );
    // One token, the newest, for the provider and both its services.
    for name in ["fake", "alpha", "beta"] {
        let out = m.run(&["token", name]);
        assert!(out.ok && out.text().trim() == "tok-2", "{name}: {out}");
    }
    let out = m.run(&["api", "beta", "ok"]);
    assert!(out.ok && out.text().contains(r#"{"beta":true}"#), "{out}");
    let db = rusqlite::Connection::open(m.config().join("sesame.db")).unwrap();
    let rows: i64 = db
        .query_row("SELECT count(*) FROM tokens", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 1);

    let out = m.run(&["provider", "set", "fake", "--drop-service", "beta"]);
    assert!(out.ok, "{out}");
    let out = m.run(&["api", "beta", "ok"]);
    assert!(
        !out.ok && out.text().contains("unknown provider `beta`"),
        "{out}"
    );
    assert!(
        out.text().contains("or a service: alpha, calendar"),
        "{out}"
    );

    assert!(
        !fake.to("/beta/v2/mail").is_empty(),
        "{:?}",
        fake.requests()
    );
}

/// Someone who added `hubspot` themselves (`sesame provider add`, every field
/// stored) upgrades to the version where it is built in: the fields equal to
/// the built-in show as `built-in`, only real changes as `user`. Login reads
/// the numeric `portalId`; a token about to expire refreshes at the same v3
/// endpoint with the credentials in the body. `setup` prints the built-in's steps.
#[test]
fn hubspot_upgrade_v3_body_refresh_numeric_identity() {
    // A HubSpot-shaped fake: the code is exchanged and refreshed at
    // `/oauth/v3/token` with the client credentials in the form body, the
    // account is the number `portalId`, and its tokens last `lasts` seconds
    // (1800 until the test changes it).
    let lasts = Arc::new(AtomicU64::new(1800));
    let lasts2 = lasts.clone();
    let mut n = 1;
    let fake = FakeProvider::serve(move |r| {
        let auth = r.header("authorization");
        let token = |n: i32| {
            let lasts = lasts2.load(Ordering::SeqCst);
            format!(
                r#"{{"access_token":"access-{n}","refresh_token":"refresh-1","expires_in":{lasts},"hub_id":247935561,"token_type":"bearer"}}"#
            )
        };
        if r.target == "/oauth/v3/token" {
            let body_creds = r.body.contains("client_id=cid")
                && r.body.contains("client_secret=the-secret")
                && !auth.starts_with("Basic");
            if !body_creds {
                ("401 Unauthorized", r#"{"status":"error"}"#.into())
            } else if r.body.contains("grant_type=authorization_code") {
                ("200 OK", token(n))
            } else if r.is_refresh() && r.body.contains("refresh_token=refresh-1") {
                n += 1;
                ("200 OK", token(n))
            } else {
                ("400 Bad Request", r#"{"status":"BAD_GRANT"}"#.into())
            }
        } else if auth != format!("Bearer access-{n}") {
            ("401 Unauthorized", r#"{"status":"error"}"#.into())
        } else if r.target == "/account-info/v3/details" {
            (
                "200 OK",
                r#"{"portalId":247935561,"uiDomain":"app-na2.hubspot.com"}"#.into(),
            )
        } else if r.target.starts_with("/crm/v3/objects/contacts") {
            ("200 OK", r#"{"results":[{"id":"1"}]}"#.into())
        } else {
            ("404 Not Found", String::new())
        }
    });
    let m = Machine::new("hubspot");
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    };

    // The built-in's setup: its four steps, the fixed localhost callback, the scopes.
    let out = m.run(&["setup", "hubspot"]);
    assert!(out.ok, "{}", out.stderr);
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
        assert!(out.stdout.contains(want), "no `{want}` in:\n{out}");
    }

    // Before the upgrade: every field of the definition stored as the person's,
    // as `sesame provider add hubspot` left it, but pointed at the fake.
    let out = m.run(&["provider", "show", "hubspot"]);
    assert!(out.ok, "{}", out.stderr);
    let shown: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let base = fake.base();
    let free = std::net::TcpListener::bind("127.0.0.1:0")
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
        let db = rusqlite::Connection::open(m.config().join("sesame.db")).unwrap();
        for (field, entry) in shown.as_object().unwrap() {
            let value = changed.get(field).unwrap_or(&entry["value"]);
            db.execute(
                "INSERT INTO provider_fields (provider, field, value) VALUES ('hubspot', ?1, ?2)",
                [field, &value.to_string()],
            )
            .unwrap();
        }
    }
    let out = m.run(&["provider", "show", "hubspot"]);
    assert!(out.ok, "{}", out.stderr);
    let shown: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
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

    let client = ["client", "hubspot", "--client-id", "cid", "--secret-stdin"];
    assert!(m.run_with_stdin(&client, "the-secret\n").ok);

    let (auth, rest) = m.login_in_browser(&["login", "hubspot", "--no-browser"]);
    let q = |k: &str| param(&auth, k);
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
    let out = m.run(&["providers"]).stdout;
    assert!(out.contains("logged in (247935561)"), "{out}");

    let token_json = |args: &[&str]| {
        let out = m.run(args);
        assert!(out.ok, "{}", out.stderr);
        serde_json::from_str::<serde_json::Value>(&out.stdout).unwrap()
    };
    let expires = |t: &serde_json::Value| t["expires_at"].as_i64().unwrap();
    let t = token_json(&["token", "hubspot", "--json"]);
    assert!((expires(&t) - now() - 1800).abs() < 60, "{t}");

    let contacts = ["api", "hubspot", "/crm/v3/objects/contacts?limit=1"];
    let out = m.run(&contacts);
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains(r#""id":"1""#), "{out}");

    // A token with 30 seconds left (what the fake gives for the next refresh,
    // which `--min-life` asks for) is refreshed before the call.
    lasts.store(30, Ordering::SeqCst);
    let t = token_json(&["token", "hubspot", "--json", "--min-life", "3600"]);
    assert_eq!(t["access_token"], "access-2");
    assert!((expires(&t) - now() - 30).abs() < 30, "{t}");
    lasts.store(1800, Ordering::SeqCst);
    let out = m.run(&contacts);
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains(r#""id":"1""#), "{out}");
    let t = token_json(&["token", "hubspot", "--json"]);
    assert_eq!(t["access_token"], "access-3");
    assert!(expires(&t) > now() + 1700, "{t}");

    let logged = fake.requests();
    let refreshes = fake.refreshes();
    assert_eq!(refreshes.len(), 2, "{logged:?}");
    assert!(
        refreshes[1].target.starts_with("/oauth/v3/token"),
        "{logged:?}"
    );
    assert!(
        refreshes[1].body.contains("client_secret=the-secret"),
        "{logged:?}"
    );
    // Before the expiry, not after a 401: each API call went out once, the
    // second already with the refreshed token.
    let calls = fake.to("/crm");
    assert_eq!(calls.len(), 2, "{logged:?}");
    assert!(
        calls[1].header("authorization").contains("Bearer access-3"),
        "{logged:?}"
    );
    let refreshes = || fake.refreshes().len();

    // A holder that hands the token on: 1000 seconds left is enough for
    // `token` alone, not for `--min-life 1700`, which refreshes first.
    lasts.store(1000, Ordering::SeqCst);
    let t = token_json(&["token", "hubspot", "--json", "--min-life", "3600"]);
    assert_eq!(t["access_token"], "access-4");
    lasts.store(1800, Ordering::SeqCst);
    let t = token_json(&["token", "hubspot", "--json"]);
    assert_eq!(t["access_token"], "access-4");
    assert!((expires(&t) - now() - 1000).abs() < 30, "{t}");
    assert_eq!(refreshes(), 3);
    let t = token_json(&["token", "hubspot", "--json", "--min-life", "1700"]);
    assert_eq!(t["access_token"], "access-5");
    assert!((expires(&t) - now() - 1800).abs() < 30, "{t}");
    let stored = token_json(&["token", "hubspot", "--json"]);
    assert_eq!(expires(&stored), expires(&t), "stored");
    assert_eq!(refreshes(), 4);
    // Fresh enough now: no refresh. Asked for more than the provider gives:
    // refreshed, and printed all the same with the expiry it has.
    let t = token_json(&["token", "hubspot", "--json", "--min-life", "1700"]);
    assert_eq!(t["access_token"], "access-5");
    assert_eq!(refreshes(), 4);
    let t = token_json(&["token", "hubspot", "--json", "--min-life", "3600"]);
    assert_eq!(t["access_token"], "access-6");
    assert!((expires(&t) - now() - 1800).abs() < 30, "{t}");
    assert_eq!(refreshes(), 5);

    let out = m.run(&["token", "--help"]);
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("--min-life <SECONDS>"), "{out}");
}

/// Guild's split: a Hub holds the login, `sesame token <service>` there
/// refreshes as needed; another machine, with no `sesame.db` at all, calls the
/// API with the token handed in the environment and the definition the Hub
/// shows, never refreshing it.
#[test]
fn handed_token_without_db() {
    let fake = FakeProvider::serve(|r| {
        let auth = r.header("authorization");
        match r.target.as_str() {
            "/token" if r.body.contains("grant_type=authorization_code") => {
                // Within a minute of expiring: the next use refreshes.
                let b =
                    r#"{"access_token":"access-1","refresh_token":"refresh-1","expires_in":30}"#;
                ("200 OK", b.into())
            }
            "/token" => {
                assert!(r.body.contains("refresh_token=refresh-1"), "{}", r.body);
                let b =
                    r#"{"access_token":"access-2","refresh_token":"refresh-1","expires_in":3600}"#;
                ("200 OK", b.into())
            }
            "/alpha/v1/things" if auth == "Bearer access-2" => {
                ("200 OK", r#"{"alpha":true}"#.into())
            }
            "/alpha/v1/broken" if auth == "Bearer access-2" => {
                ("200 OK", r#"{"errors":["no"]}"#.into())
            }
            _ => ("401 Unauthorized", "{}".into()),
        }
    });
    let hub = Machine::new("handed-hub");
    let remote = Machine::new("handed-remote");

    // The Hub: the provider, its client and the login.
    let base = fake.base();
    fake.add(
        &hub,
        "fake",
        "",
        &[
            "--api-header",
            "X-Fake-Version: 7",
            "--error-field",
            "errors",
            "--service",
            &format!("name=alpha,api-base={base}/alpha/v1,scope=a.read"),
        ],
    );
    let out = hub.run(&["client", "fake", "--client-id", "cid", "--no-secret"]);
    assert!(out.ok, "{out}");
    hub.login_in_browser(&["login", "alpha", "--no-browser"]);
    // `sesame token <service>` on the Hub refreshes the expiring token.
    let out = hub.run(&["token", "alpha"]);
    assert!(out.ok && out.text().trim() == "access-2", "{out}");
    let refreshes = || fake.refreshes().len();
    assert_eq!(refreshes(), 1);
    let out = hub.run(&["provider", "show", "fake"]);
    assert!(out.ok, "{out}");
    let definitions = format!(r#"{{"fake": {}}}"#, out.text());

    // The other machine: an empty config dir, the token and the definition handed.
    let handed = |var: &str, token: &str, args: &[&str]| {
        let mut c = remote.cmd(args);
        c.env(var, token).env("SESAME_PROVIDERS", &definitions);
        let out = remote.output(c, "");
        (out.ok, out.text())
    };
    let (ok, out) = handed(
        "SESAME_TOKEN_ALPHA",
        "access-2",
        &["api", "alpha", "/things"],
    );
    assert!(ok && out.contains(r#"{"alpha":true}"#), "{out}");
    // The provider's variable serves its services too.
    let (ok, out) = handed(
        "SESAME_TOKEN_FAKE",
        "access-2",
        &["api", "alpha", "/things"],
    );
    assert!(ok && out.contains(r#"{"alpha":true}"#), "{out}");
    let (ok, out) = handed("SESAME_TOKEN_ALPHA", "access-2", &["token", "alpha"]);
    assert!(ok && out.trim() == "access-2", "{out}");
    // A handed token's expiry is not told to sesame.
    let (ok, out) = handed(
        "SESAME_TOKEN_ALPHA",
        "access-2",
        &["token", "alpha", "--json"],
    );
    assert!(ok, "{out}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&out).unwrap(),
        serde_json::json!({"access_token": "access-2", "expires_at": null})
    );
    // `--min-life` refreshes nothing for a handed token: it is printed as it is.
    let (ok, out) = handed(
        "SESAME_TOKEN_ALPHA",
        "access-2",
        &["token", "alpha", "--json", "--min-life", "1700"],
    );
    assert!(ok, "{out}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&out).unwrap(),
        serde_json::json!({"access_token": "access-2", "expires_at": null})
    );
    assert_eq!(refreshes(), 1, "a handed token was refreshed");
    // error_fields apply.
    let (ok, out) = handed(
        "SESAME_TOKEN_ALPHA",
        "access-2",
        &["api", "alpha", "/broken"],
    );
    assert!(!ok && out.contains("carries `errors`"), "{out}");
    // The token goes only to the provider's hosts.
    let (ok, out) = handed(
        "SESAME_TOKEN_ALPHA",
        "access-2",
        &["api", "alpha", "https://evil.example/x"],
    );
    assert!(!ok && out.contains("refusing to send the token"), "{out}");
    // A refused handed token is not refreshed: its holder hands a new one.
    let (ok, out) = handed(
        "SESAME_TOKEN_ALPHA",
        "access-1",
        &["api", "alpha", "/things"],
    );
    assert!(!ok, "{out}");
    assert!(
        out.contains("the token handed in `SESAME_TOKEN_ALPHA` was refused or has expired"),
        "{out}"
    );
    assert_eq!(refreshes(), 1, "a handed token was refreshed");
    assert_eq!(
        std::fs::read_dir(remote.config()).unwrap().count(),
        0,
        "the handed mode wrote to its config dir"
    );

    let log = fake.requests();
    let calls = fake.to("/alpha/v1/things");
    assert_eq!(calls.len(), 3, "{log:?}");
    let sent = |i: usize| {
        (
            calls[i].header("authorization"),
            calls[i].header("x-fake-version"),
        )
    };
    assert_eq!(sent(0), ("Bearer access-2".into(), "7".into()), "{log:?}");
    assert_eq!(sent(2), ("Bearer access-1".into(), "7".into()), "{log:?}");
}

/// A provider's built-in public client: used while no client is stored, with
/// no secret, through the device flow only; a stored client replaces it, and
/// `client --reset` brings it back.
#[test]
fn built_in_public_client() {
    let fake = FakeProvider::serve(move |r| match r.target.as_str() {
        "/device" => {
            let id = r
                .body
                .split('&')
                .find_map(|kv| kv.strip_prefix("client_id="))
                .unwrap_or_default()
                .to_string();
            let b = format!(
                r#"{{"device_code":"dev-{id}","user_code":"AAAA-BBBB","verification_uri":"https://example.com/device","expires_in":60,"interval":0}}"#
            );
            ("200 OK", b)
        }
        "/token" => ("200 OK", r#"{"access_token":"tok","scope":"repo"}"#.into()),
        _ => ("404 Not Found", "{}".into()),
    });
    let m = Machine::new("public");
    let in_use = || {
        let out = m.run(&["provider", "show", "pub"]);
        assert!(out.ok, "{out}");
        let shown: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
        assert_eq!(shown["public_client_id"]["value"], "builtin-id");
        shown["public_client_id"]["in_use"].as_bool().unwrap()
    };
    let line = |out: &str| {
        out.lines()
            .find(|l| l.starts_with("pub "))
            .unwrap_or_default()
            .to_string()
    };
    let token_calls = || {
        fake.to("/token")
            .into_iter()
            .map(|r| r.body)
            .collect::<Vec<_>>()
    };

    let base = fake.base();
    fake.add(
        &m,
        "pub",
        "",
        &[
            "--scope",
            "repo",
            "--device-url",
            &format!("{base}/device"),
            "--redirect-host",
            "127.0.0.1",
            "--public-client-id",
            "builtin-id",
        ],
    );

    // No client stored: the built-in one, with no secret.
    let out = m.run(&["providers"]).text();
    let l = line(&out);
    assert!(
        l.contains("not logged in")
            && l.contains("built-in client")
            && l.contains("sesame login pub"),
        "{out}"
    );
    assert!(in_use());
    let out = m.run(&["setup", "pub"]);
    assert!(out.ok && out.text().contains("No setup is needed"), "{out}");
    let out = m.run(&["login", "pub", "--no-browser"]);
    assert!(out.ok && out.text().contains("Logged in to `pub`"), "{out}");
    let calls = token_calls();
    assert!(
        calls.len() == 1
            && calls[0].contains("device_code=dev-builtin-id")
            && calls[0].contains("client_id=builtin-id")
            && !calls[0].contains("client_secret"),
        "{calls:?}"
    );

    // --browser with the built-in client: refused before anything is sent.
    let out = m.run(&["login", "pub", "--browser", "--no-browser"]);
    let text = out.text();
    assert!(
        !out.ok
            && text.contains("only with the device flow")
            && text.contains("`sesame setup pub`"),
        "{out}"
    );
    assert!(fake.to("/authorize").is_empty());

    // A stored client replaces it, secret and all.
    let out = m.run_with_stdin(
        &["client", "pub", "--client-id", "mine", "--secret-stdin"],
        "s3cret\n",
    );
    assert!(out.ok, "{out}");
    let out = m.run(&["providers"]).text();
    assert!(line(&out).contains("your client"), "{out}");
    assert!(!in_use());
    let out = m.run(&["login", "pub", "--no-browser"]);
    assert!(out.ok, "{out}");
    let calls = token_calls();
    assert!(
        calls[1].contains("device_code=dev-mine")
            && calls[1].contains("client_id=mine")
            && calls[1].contains("client_secret=s3cret"),
        "{calls:?}"
    );

    // --reset: back to the built-in client.
    let out = m.run(&["client", "pub", "--reset"]);
    assert!(
        out.ok && out.text().contains("login uses the built-in client"),
        "{out}"
    );
    let out = m.run(&["providers"]).text();
    assert!(line(&out).contains("built-in client"), "{out}");
    assert!(in_use());
    let out = m.run(&["login", "pub", "--no-browser"]);
    assert!(out.ok, "{out}");
    let calls = token_calls();
    assert!(
        calls[2].contains("client_id=builtin-id") && !calls[2].contains("client_secret"),
        "{calls:?}"
    );
    let out = m.run(&["client", "pub", "--reset"]);
    assert!(
        out.ok && out.text().contains("There was no stored"),
        "{out}"
    );
}

/// With `SESAME_1PASSWORD_VAULT` set, every command keeps its clients, tokens
/// and provider fields in the vault, through a real `op` process: nothing
/// secret under the config dir, no secret or service account token in any
/// `op` argv, the token in every `op`'s environment. What the vault store
/// reads and writes, call by call, is `store::vault`'s tests.
#[test]
fn one_password_vault_store() {
    let mut refreshes = 0;
    let fake = FakeProvider::serve(move |r| {
        match r.target.as_str() {
        "/device" => (
            "200 OK",
            r#"{"device_code":"dev","user_code":"WDJB-MJHT","verification_uri":"https://example.com/device","expires_in":60,"interval":0}"#.into(),
        ),
        "/token" if r.body.contains("grant_type=urn") => (
            "200 OK",
            r#"{"access_token":"device-token","refresh_token":"refresh-secret-1","expires_in":3600,"scope":"repo"}"#.into(),
        ),
        "/token" if r.body.contains("grant_type=authorization_code") => (
            "200 OK",
            r#"{"access_token":"browser-token","refresh_token":"refresh-secret-1","expires_in":3600}"#.into(),
        ),
        "/token" if r.is_refresh() => {
            assert!(r.body.contains("refresh_token=refresh-secret-1"), "{}", r.body);
            refreshes += 1;
            let b = format!(
                r#"{{"access_token":"refreshed-{refreshes}","refresh_token":"refresh-secret-1","expires_in":3600}}"#
            );
            ("200 OK", b)
        }
        "/user" => ("200 OK", r#"{"login":"octo"}"#.into()),
        "/me" => ("200 OK", r#"{"me":"octo"}"#.into()),
        _ => ("404 Not Found", "{}".into()),
    }
    });
    let vault = FakeVault::new();
    let m = Machine::new("vault").with_vault(&vault);
    let config = m.config();

    let base = fake.base();
    fake.add(
        &m,
        "hub",
        "",
        &[
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
        ],
    );
    let out = m.run(&["provider", "set", "hub", "--about", "The hub"]);
    assert!(out.ok, "{out}");
    let out = m.run(&["provider", "show", "hub"]);
    assert!(out.ok, "{out}");
    let shown: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(shown["about"]["value"], "The hub");
    assert_eq!(shown["device_url"]["from"], "user");
    let defs = vault.item("sesame-providers").expect("definitions item");
    assert!(field(&defs, "hub").unwrap().1.contains("The hub"));

    let out = m.run_with_stdin(
        &["client", "hub", "--client-id", "cid", "--secret-stdin"],
        "client-secret-xyz\n",
    );
    assert!(out.ok, "{out}");

    // The device flow.
    let out = m.run(&["login", "hub", "--no-browser"]);
    assert!(
        out.ok && out.text().contains("Logged in to `hub` (octo)"),
        "{out}"
    );
    let item = vault.item("sesame.hub").expect("the provider's item");
    assert_eq!(item["tags"], serde_json::json!(["sesame"]));
    assert_eq!(item["category"], "SECURE_NOTE");
    for (label, kind) in [
        ("client_id", "STRING"),
        ("client_secret", "CONCEALED"),
        ("access_token", "CONCEALED"),
        ("refresh_token", "CONCEALED"),
        ("account", "STRING"),
    ] {
        assert_eq!(field(&item, label).unwrap().0, kind, "{label}");
    }
    assert_eq!(
        vault.read(&format!("op://{VAULT}/sesame.hub/refresh_token")),
        "refresh-secret-1"
    );

    let out = m.run(&["api", "hub", "/me"]);
    assert!(out.ok && out.text().contains(r#"{"me":"octo"}"#), "{out}");
    // A refresh, written back.
    let out = m.run(&["token", "hub", "--json", "--min-life", "7200"]);
    assert!(
        out.ok && out.text().contains(r#""access_token":"refreshed-1""#),
        "{out}"
    );
    assert_eq!(
        vault.read(&format!("op://{VAULT}/sesame.hub/access_token")),
        "refreshed-1"
    );

    // The loopback flow (`--browser`), the test playing the browser.
    m.login_in_browser(&["login", "hub", "--browser", "--no-browser"]);
    assert_eq!(m.run(&["token", "hub"]).text().trim(), "browser-token");

    // A pasted token.
    let out = m.run_with_stdin(&["login", "hub", "--token-stdin"], "pasted-secret-token");
    assert!(out.ok, "{out}");
    let out = m.run(&["providers"]);
    assert!(
        out.ok && out.text().contains("logged in (octo, pasted token)"),
        "{out}"
    );
    assert!(out.text().contains("your client"), "{out}");
    assert_eq!(
        m.run(&["token", "hub"]).text().trim(),
        "pasted-secret-token"
    );

    // Nothing of sesame's under the config dir holds a secret: no sesame.db at all.
    assert!(!config.join("sesame.db").exists());
    let secrets = [
        "client-secret-xyz",
        "device-token",
        "browser-token",
        "refreshed-1",
        "refresh-secret-1",
        "pasted-secret-token",
        SA_TOKEN,
    ];
    for entry in std::fs::read_dir(config).unwrap() {
        let path = entry.unwrap().path();
        let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).to_string();
        for s in secrets {
            assert!(!text.contains(s), "{} holds {s}", path.display());
        }
    }
    // Nor any `op` argv; every call had the service account token, in its environment.
    let calls = vault.calls();
    for (argv, had_token) in &calls {
        assert!(had_token, "{argv:?}");
        for s in secrets {
            assert!(!argv.iter().any(|a| a.contains(s)), "{s} in {argv:?}");
        }
    }

    // Nothing of sesame's left in the item: `op` archives it.
    for args in [&["client", "hub", "--reset"][..], &["logout", "hub"]] {
        let out = m.run(args);
        assert!(out.ok, "{out}");
    }
    assert!(vault.item("sesame.hub").is_none());
}

/// A vault named but unusable is one clear error, never sesame.db instead.
#[test]
fn one_password_vault_errors() {
    let vault = FakeVault::new();
    let m = Machine::new("vault-err").with_vault(&vault);
    let sesame = |setup: &dyn Fn(&mut Command)| {
        let mut c = m.cmd(&["token", "github"]);
        setup(&mut c);
        let out = m.output(c, "");
        assert!(!out.ok);
        out.stderr
    };

    let err = sesame(&|c| {
        c.env_remove("OP_SERVICE_ACCOUNT_TOKEN");
    });
    assert!(
        err.contains("SESAME_1PASSWORD_VAULT is set (`scratch`)")
            && err.contains("OP_SERVICE_ACCOUNT_TOKEN is not set"),
        "{err}"
    );
    let err = sesame(&|c| {
        c.env("PATH", "/usr/bin:/bin");
    });
    assert!(err.contains("`op` is not on PATH"), "{err}");
    let err = sesame(&|c| {
        c.env("SESAME_1PASSWORD_VAULT", "elsewhere");
    });
    assert!(
        err.contains("cannot read the 1Password vault `elsewhere`") && err.lines().count() == 1,
        "{err}"
    );
    let err = sesame(&|c| {
        c.env("FAKE_OP_TOKEN", "another");
    });
    assert!(err.contains("authentication failed"), "{err}");
    assert!(!m.config().join("sesame.db").exists());
}

/// `sesame store migrate` copies sesame.db into the vault: a run cut short by
/// the write budget goes on when run again, an item the vault already holds
/// otherwise is reported and left as it is, a second run writes nothing, and
/// after a full copy sesame.db is renamed and every command works from the
/// vault alone.
#[test]
fn one_password_vault_migrate() {
    let fake = FakeProvider::serve(move |r| {
        match r.target.as_str() {
        "/device" => (
            "200 OK",
            r#"{"device_code":"dev","user_code":"WDJB-MJHT","verification_uri":"https://example.com/device","expires_in":60,"interval":0}"#.into(),
        ),
        "/token" if r.body.contains("grant_type=urn") => (
            "200 OK",
            r#"{"access_token":"device-token","refresh_token":"refresh-secret-1","expires_in":3600,"scope":"repo"}"#.into(),
        ),
        "/user" => ("200 OK", r#"{"login":"octo"}"#.into()),
        "/me" => ("200 OK", r#"{"me":"octo"}"#.into()),
        _ => ("404 Not Found", "{}".into()),
    }
    });
    let vault = FakeVault::new();
    let m = Machine::new("migrate").with_vault(&vault);
    let config = m.config();
    // `in_vault` false: the same machine before it set SESAME_1PASSWORD_VAULT.
    let run = |in_vault: bool, args: &[&str], stdin: &str, setup: &dyn Fn(&mut Command)| {
        let mut c = m.cmd(args);
        if !in_vault {
            c.env_remove("SESAME_1PASSWORD_VAULT");
        }
        setup(&mut c);
        m.output(c, stdin)
    };
    let local = |args: &[&str], stdin: &str| run(false, args, stdin, &|_| {});
    // A migrate run: (ok, output, writes it made).
    let migrate = |setup: &dyn Fn(&mut Command)| {
        let out = run(true, &["store", "migrate"], "", setup);
        (out.ok, out.text(), out.writes)
    };

    // sesame.db: a token with refresh (`hub`), a client only (`cli`), a
    // pasted token (`pst`), and the user provider fields defining them.
    let base = fake.base();
    for name in ["hub", "cli", "pst"] {
        let (device, user) = (format!("{base}/device"), format!("{base}/user"));
        let args = fake.add_args(
            name,
            "",
            &[
                "--scope",
                "repo",
                "--device-url",
                &device,
                "--identity-url",
                &user,
                "--identity-field",
                "login",
            ],
        );
        let out = local(&args.iter().map(String::as_str).collect::<Vec<_>>(), "");
        assert!(out.ok, "{out}");
    }
    let out = local(
        &["client", "hub", "--client-id", "hub-id", "--secret-stdin"],
        "hub-secret\n",
    );
    assert!(out.ok, "{out}");
    let out = local(&["login", "hub", "--no-browser"], "");
    assert!(
        out.ok && out.text().contains("Logged in to `hub` (octo)"),
        "{out}"
    );
    let out = local(
        &["client", "cli", "--client-id", "cli-id", "--no-secret"],
        "",
    );
    assert!(out.ok, "{out}");
    let out = local(&["login", "pst", "--token-stdin"], "pasted-secret");
    assert!(out.ok, "{out}");
    let db = config.join("sesame.db");
    assert!(db.exists());

    // Without the vault: refuses, saying what to set.
    let out = local(&["store", "migrate"], "");
    assert!(
        !out.ok && out.text().contains("SESAME_1PASSWORD_VAULT is not set"),
        "{out}"
    );
    assert!(vault.calls().is_empty());

    // The vault already holds another client for `cli`.
    let other = serde_json::json!({
        "title": "sesame.cli",
        "category": "SECURE_NOTE",
        "tags": ["sesame"],
        "fields": [{"label": "client_id", "type": "STRING", "value": "other-id"}],
    });
    vault.op(
        &["item", "create", "--vault", VAULT, "--format", "json"],
        &other.to_string(),
    );
    let conflicting = vault.item("sesame.cli").unwrap();

    // Cut short by the budget after one write: says so, keeps sesame.db.
    let budget = (vault.writes() + 1).to_string();
    let (ok, out, wrote) = migrate(&|c| {
        c.env("FAKE_OP_MAX_WRITES", &budget);
    });
    assert!(!ok && out.contains("sesame store migrate` again"), "{out}");
    // One write made, the next refused.
    assert_eq!(wrote, 2, "{out}");
    assert!(vault.item("sesame-providers").is_some() && vault.item("sesame.hub").is_none());
    assert!(db.exists());

    // Goes on: copies the rest, reports the conflict and leaves it as it is.
    let (ok, out, wrote) = migrate(&|_| {});
    assert!(
        !ok && out.contains("Conflict") && out.contains("`cli`"),
        "{out}"
    );
    assert_eq!(wrote, 2, "{out}");
    assert_eq!(vault.item("sesame.cli").unwrap(), conflicting);
    assert!(db.exists());
    // Again: nothing written, the conflict still reported.
    let (ok, out, wrote) = migrate(&|_| {});
    assert!(!ok && out.contains("`cli`"), "{out}");
    assert_eq!(wrote, 0, "{out}");

    // Keep the vault's client: drop sesame.db's. Now everything is in the vault.
    let out = local(&["client", "cli", "--reset"], "");
    assert!(out.ok, "{out}");
    let (ok, out, wrote) = migrate(&|_| {});
    assert!(ok, "{out}");
    assert_eq!(wrote, 0, "{out}");
    assert!(!db.exists());
    let moved: Vec<_> = std::fs::read_dir(config)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().contains("sesame.db.migrated-"))
        .collect();
    assert_eq!(moved.len(), 1, "{moved:?}");
    let moved = &moved[0];
    assert!(
        out.contains("plaintext")
            && out.contains(&format!("rm {}", moved.display()))
            && out.contains(&format!("mv {} {}", moved.display(), db.display())),
        "{out}"
    );

    // Run again over the same database: writes nothing.
    std::fs::copy(moved, &db).unwrap();
    let (ok, out, wrote) = migrate(&|_| {});
    assert!(ok && out.contains("already holds all"), "{out}");
    assert_eq!(wrote, 0, "{out}");
    assert!(!db.exists());

    // From the vault alone, sesame.db out of the way.
    for entry in std::fs::read_dir(config).unwrap() {
        let p = entry.unwrap().path();
        if p.to_string_lossy().contains("sesame.db.") {
            std::fs::remove_file(p).unwrap();
        }
    }
    let item = vault.item("sesame.hub").unwrap();
    assert_eq!(field(&item, "client_secret").unwrap().0, "CONCEALED");
    assert_eq!(
        vault.read(&format!("op://{VAULT}/sesame.hub/refresh_token")),
        "refresh-secret-1"
    );
    let out = m.run(&["token", "hub"]);
    assert!(out.ok && out.text().trim() == "device-token", "{out}");
    let out = m.run(&["api", "hub", "/me"]);
    assert!(out.ok && out.text().contains(r#"{"me":"octo"}"#), "{out}");
    let out = m.run(&["token", "pst"]);
    assert!(out.ok && out.text().trim() == "pasted-secret", "{out}");
    let out = m.run(&["providers"]);
    assert!(
        out.ok && out.text().contains("logged in (octo)") && out.text().contains("pasted token"),
        "{out}"
    );
    assert!(!db.exists());
}

/// The vault's local copy (docs/adr/0002), across two machines: a call with a
/// valid token makes no `op` call at all, provider resolution included; the
/// copy on disk holds no secret in plaintext and opens only under the service
/// account token that sealed it; and what one machine writes reaches another
/// at that one's next refresh, without it refreshing again. Which items a
/// sync reads is `store::vault`'s tests.
#[test]
fn one_password_local_copy() {
    // A login's token lasts 30 s, inside MIN_LIFE, so the first call
    // refreshes it; a refresh's lasts an hour.
    let mut refreshes = 0;
    let fake = FakeProvider::serve(move |r| {
        match r.target.as_str() {
        "/device" => (
            "200 OK",
            r#"{"device_code":"dev","user_code":"WDJB-MJHT","verification_uri":"https://example.com/device","expires_in":60,"interval":0}"#.into(),
        ),
        "/token" if r.body.contains("grant_type=urn") => (
            "200 OK",
            r#"{"access_token":"login-token","refresh_token":"refresh-secret","expires_in":30}"#.into(),
        ),
        "/token" if r.is_refresh() => {
            refreshes += 1;
            let b = format!(
                r#"{{"access_token":"refreshed-{refreshes}","refresh_token":"refresh-secret","expires_in":3600}}"#
            );
            ("200 OK", b)
        }
        "/me" => ("200 OK", r#"{"me":"octo"}"#.into()),
        _ => ("404 Not Found", "{}".into()),
    }
    });
    let vault = FakeVault::new();
    let a = Machine::new("copy-a").with_vault(&vault);
    let b = Machine::new("copy-b").with_vault(&vault);
    // `sesame` on a machine under another service account token.
    let as_sa = |m: &Machine, sa: &str, args: &[&str]| {
        let mut c = m.cmd(args);
        c.env("OP_SERVICE_ACCOUNT_TOKEN", sa)
            .env("FAKE_OP_TOKEN", sa);
        m.output(c, "")
    };
    let refresh_bodies = || {
        fake.refreshes()
            .into_iter()
            .map(|r| r.body)
            .collect::<Vec<_>>()
    };

    let base = fake.base();
    fake.add(
        &a,
        "hub",
        "",
        &[
            "--device-url",
            &format!("{base}/device"),
            "--about",
            "first",
        ],
    );
    let out = a.run_with_stdin(
        &["client", "hub", "--client-id", "cid-1", "--secret-stdin"],
        "client-secret-1\n",
    );
    assert!(out.ok, "{out}");
    let out = a.run(&["login", "hub", "--no-browser"]);
    assert!(out.ok, "{out}");

    // Machine B, no copy yet: it fills one from the vault (a list and a read
    // of each item), then calls with the token as the vault holds it.
    let out = b.run(&["provider", "show", "hub"]);
    assert!(out.ok && out.text().contains("first"), "{out}");

    // A's login token is expiring: the first call refreshes, the next makes
    // no `op` call at all.
    let out = a.run(&["api", "hub", "/me"]);
    assert!(out.ok && out.text().contains("octo"), "{out}");
    assert_eq!(refresh_bodies().len(), 1);
    for args in [
        &["api", "hub", "/me"][..],
        &["token", "hub"],
        &["provider", "show", "hub"],
    ] {
        let out = a.run(args);
        assert!(out.ok, "{out}");
        assert_eq!((out.calls, out.writes), (0, 0), "{args:?}");
    }
    assert_eq!(a.run(&["token", "hub"]).text().trim(), "refreshed-1");

    // B's copy still has the login token, expiring: its next call syncs, finds
    // A's refreshed token, and uses it without refreshing (no write).
    let out = b.run(&["token", "hub"]);
    assert!(out.ok && out.text().trim() == "refreshed-1", "{out}");
    assert_eq!((out.writes, refresh_bodies().len()), (0, 1));
    assert_eq!(b.run(&["api", "hub", "/me"]).calls, 0);

    // A changes the provider's fields and client. B goes on with its copy
    // until its next refresh, which reads both and refreshes with A's client.
    let out = a.run(&["provider", "set", "hub", "--about", "second"]);
    assert!(out.ok, "{out}");
    let out = a.run_with_stdin(
        &["client", "hub", "--client-id", "cid-2", "--secret-stdin"],
        "client-secret-2\n",
    );
    assert!(out.ok, "{out}");
    let out = b.run(&["provider", "show", "hub"]);
    assert!(
        out.ok && out.text().contains("first") && out.calls == 0,
        "{out}"
    );
    let out = b.run(&["token", "hub", "--min-life", "7200"]);
    assert!(out.ok && out.text().trim() == "refreshed-2", "{out}");
    let last = refresh_bodies().pop().unwrap();
    assert!(last.contains("client_id=cid-2"), "{last}");
    let out = b.run(&["provider", "show", "hub"]);
    assert!(
        out.ok && out.text().contains("second") && out.calls == 0,
        "{out}"
    );

    // Nothing under either config dir holds a secret in plaintext.
    let secrets = [
        "login-token",
        "refreshed-1",
        "refreshed-2",
        "refresh-secret",
        "client-secret-1",
        "client-secret-2",
        SA_TOKEN,
    ];
    for m in [&a, &b] {
        let files: Vec<_> = std::fs::read_dir(m.config())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert!(
            files.iter().any(|f| f.ends_with("1password-copy")),
            "{files:?}"
        );
        for path in files {
            let bytes = std::fs::read(&path).unwrap();
            for s in secrets {
                assert!(
                    !bytes.windows(s.len()).any(|w| w == s.as_bytes()),
                    "{} holds {s}",
                    path.display()
                );
            }
        }
    }

    // Under another service account token (one rotated) the copy does not
    // open: it is rebuilt from the vault, then used again.
    let other = "ops_another-service-account";
    let out = as_sa(&a, other, &["token", "hub"]);
    assert!(
        out.ok && out.text().trim() == "refreshed-2" && out.calls > 0,
        "{out}"
    );
    assert_eq!(as_sa(&a, other, &["token", "hub"]).calls, 0);
    // And a damaged copy the same.
    let copy = a.config().join("1password-copy");
    let mut bytes = std::fs::read(&copy).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&copy, bytes).unwrap();
    let out = as_sa(&a, other, &["token", "hub"]);
    assert!(
        out.ok && out.text().trim() == "refreshed-2" && out.calls > 0,
        "{out}"
    );

    // A logout elsewhere reaches B at its next sync (`sesame providers`).
    let out = a.run(&["logout", "hub"]);
    assert!(out.ok, "{out}");
    let out = b.run(&["providers"]);
    let text = out.text();
    let hub = text
        .lines()
        .find(|l| l.starts_with("hub "))
        .unwrap_or_default();
    assert!(out.ok && hub.contains("not logged in"), "{out}");
    let out = b.run(&["token", "hub"]);
    assert!(!out.ok && out.text().contains("not logged in"), "{out}");
    // Not logged in: it looked in the vault (another machine may have).
    assert_eq!(out.calls, 2);
}
