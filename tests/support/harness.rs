//! What every end-to-end test drives sesame through: a [`Machine`] (a config
//! dir of its own, removed on drop), a [`FakeProvider`] on 127.0.0.1 that plays
//! the consent page, and a [`FakeVault`] for the 1Password store. Only this file
//! knows how login prints its authorization URL and how `/authorize` answers.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// A directory under the system temp dir, removed when dropped, a failed
/// test's included.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sesame-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What a command did. With a vault attached, also the `op` calls it made and
/// how many of them wrote.
#[derive(Debug)]
pub struct Out {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
    pub calls: usize,
    pub writes: usize,
}

impl Out {
    /// stdout then stderr, as a person at the terminal reads them.
    pub fn text(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

impl std::fmt::Display for Out {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}{}", self.stdout, self.stderr)
    }
}

/// One machine sesame runs on: its config dir, and the vault it opted in to.
pub struct Machine<'v> {
    dir: Scratch,
    vault: Option<&'v FakeVault>,
}

impl<'v> Machine<'v> {
    pub fn new(tag: &str) -> Self {
        Machine {
            dir: Scratch::new(tag),
            vault: None,
        }
    }

    /// The machine keeps its store in `vault`, as one that set
    /// `SESAME_1PASSWORD_VAULT` does.
    pub fn with_vault(mut self, vault: &'v FakeVault) -> Self {
        self.vault = Some(vault);
        self
    }

    pub fn config(&self) -> &Path {
        &self.dir.0
    }

    /// `sesame <args>` on this machine, nothing of the test's own environment
    /// that sesame reads let through.
    pub fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sesame"));
        c.args(args).env("SESAME_CONFIG_DIR", self.config());
        for (k, _) in std::env::vars() {
            if k.starts_with("SESAME_TOKEN_")
                || k == "SESAME_PROVIDERS"
                || k == "SESAME_1PASSWORD_VAULT"
            {
                c.env_remove(k);
            }
        }
        if let Some(v) = self.vault {
            v.env(&mut c);
        }
        c
    }

    /// `sh -c <script>` on this machine, with this sesame first on PATH: a
    /// command line sesame printed, run as printed.
    pub fn sh(&self, script: &str) -> Out {
        let sesame = self.cmd(&[]);
        let mut sh = Command::new("sh");
        sh.arg("-c").arg(script);
        for (k, v) in sesame.get_envs() {
            match v {
                Some(v) => sh.env(k, v),
                None => sh.env_remove(k),
            };
        }
        let path = sesame
            .get_envs()
            .find(|(k, _)| *k == "PATH")
            .and_then(|(_, v)| v.map(|v| v.to_string_lossy().into_owned()))
            .unwrap_or_else(|| std::env::var("PATH").unwrap());
        let bin = Path::new(sesame.get_program()).parent().unwrap();
        sh.env("PATH", format!("{}:{path}", bin.display()));
        self.output(sh, "")
    }

    pub fn run(&self, args: &[&str]) -> Out {
        self.output(self.cmd(args), "")
    }

    pub fn run_with_stdin(&self, args: &[&str], input: &str) -> Out {
        self.output(self.cmd(args), input)
    }

    /// Runs `c` (from [`Machine::cmd`], changed as the test needs) with `input`
    /// on its stdin.
    pub fn output(&self, mut c: Command, input: &str) -> Out {
        let before = self.op_calls();
        let mut child = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        self.out(
            before,
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into(),
            String::from_utf8_lossy(&out.stderr).into(),
        )
    }

    /// Signs in with `args`, playing the browser through the provider's
    /// redirect to sesame's loopback; the login must succeed. Returns the
    /// authorization URL and what login printed after it.
    pub fn login_in_browser(&self, args: &[&str]) -> (url::Url, String) {
        let (before, mut login, mut err, auth_url) = self.start_login(args);
        let page = reqwest::blocking::get(auth_url.as_str())
            .unwrap()
            .text()
            .unwrap();
        assert!(page.contains("Signed in"), "{page}");
        drop(login.stdin.take());
        let out = self.finish_login(before, login, &mut err);
        assert!(out.ok, "login failed: {}", out.stderr);
        (auth_url, out.stderr)
    }

    /// Signs in with `args` where nothing answers the redirect: plays the
    /// browser up to it, and pastes `edit(<address it would end on>)`.
    pub fn login_pasting(&self, args: &[&str], edit: impl Fn(String) -> String) -> Out {
        self.login_landing(args, |landed, mut stdin| {
            writeln!(stdin, "{}", edit(landed)).unwrap();
        })
    }

    /// Signs in with `args`, playing the browser up to the provider's
    /// redirect and handing its address and login's stdin to `act`, which
    /// plays the rest (a request to the loopback, a paste); stdin is closed
    /// once `act` returns, and login is waited for.
    pub fn login_landing(&self, args: &[&str], act: impl FnOnce(String, ChildStdin)) -> Out {
        let (before, mut login, mut err, auth_url) = self.start_login(args);
        let no_follow = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let resp = no_follow.get(auth_url).send().unwrap();
        let landed = resp.headers()["location"].to_str().unwrap().to_string();
        act(landed, login.stdin.take().unwrap());
        self.finish_login(before, login, &mut err)
    }

    /// Starts a login and reads its stderr up to the authorization URL.
    fn start_login(&self, args: &[&str]) -> (usize, Child, BufReader<ChildStderr>, url::Url) {
        let before = self.op_calls();
        let mut login = self
            .cmd(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
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
                break url::Url::parse(&format!("http{u}")).unwrap();
            }
        };
        (before, login, err, auth_url)
    }

    fn finish_login(&self, before: usize, login: Child, err: &mut BufReader<ChildStderr>) -> Out {
        let mut rest = String::new();
        err.read_to_string(&mut rest).unwrap();
        let out = login.wait_with_output().unwrap();
        self.out(
            before,
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into(),
            rest,
        )
    }

    fn op_calls(&self) -> usize {
        self.vault.map_or(0, |v| v.calls().len())
    }

    fn out(&self, before: usize, ok: bool, stdout: String, stderr: String) -> Out {
        let calls = self
            .vault
            .map(|v| v.calls().split_off(before))
            .unwrap_or_default();
        Out {
            ok,
            stdout,
            stderr,
            calls: calls.len(),
            writes: calls.iter().filter(|(a, _)| is_write(a)).count(),
        }
    }
}

fn is_write(argv: &[String]) -> bool {
    argv.len() > 1 && ["create", "edit", "delete"].contains(&argv[1].as_str())
}

/// The query parameter `k` of `u`.
pub fn param(u: &url::Url, k: &str) -> Option<String> {
    u.query_pairs()
        .find(|(n, _)| n == k)
        .map(|(_, v)| v.into_owned())
}

/// One request a fake provider got: its target, headers (names lowercased)
/// and body.
#[derive(Debug, Clone)]
pub struct Request {
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Request {
    fn read(stream: &TcpStream) -> Request {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
        let mut headers = Vec::new();
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h).unwrap() == 0 || h.trim().is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }
        let mut r = Request {
            target,
            headers,
            body: String::new(),
        };
        let len = r.header("content-length").parse().unwrap_or(0);
        let mut body = vec![0; len];
        reader.read_exact(&mut body).unwrap();
        r.body = String::from_utf8(body).unwrap();
        r
    }

    /// The header `name` (lowercase), or "".
    pub fn header(&self, name: &str) -> String {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    /// The query parameter `k` of the target.
    pub fn query(&self, k: &str) -> Option<String> {
        param(
            &url::Url::parse(&format!("http://x{}", self.target)).unwrap(),
            k,
        )
    }

    pub fn is_refresh(&self) -> bool {
        self.body.contains("grant_type=refresh_token")
    }
}

/// `<target> <body>`: the request as a log line.
impl std::fmt::Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} {}", self.target, self.body)
    }
}

/// A fake OAuth provider on 127.0.0.1. A request whose path ends in
/// `/authorize` is the consent page, answered straight back to its
/// `redirect_uri` with `code=the-code` and its `state`; every other gets what
/// `answer` gives: a status line and a JSON body. Every request is logged.
pub struct FakeProvider {
    port: u16,
    log: Arc<Mutex<Vec<Request>>>,
}

impl FakeProvider {
    pub fn serve(
        mut answer: impl FnMut(&Request) -> (&'static str, String) + Send + 'static,
    ) -> FakeProvider {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        std::thread::spawn(move || {
            for mut s in listener.incoming().flatten() {
                let r = Request::read(&s);
                log2.lock().unwrap().push(r.clone());
                let path = r.target.split('?').next().unwrap_or("");
                if path.ends_with("/authorize") {
                    let loc = format!(
                        "{}?code=the-code&state={}",
                        r.query("redirect_uri").unwrap(),
                        r.query("state").unwrap()
                    );
                    let _ = write!(
                        s,
                        "HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    continue;
                }
                let (status, b) = answer(&r);
                let _ = write!(
                    s,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                    b.len()
                );
            }
        });
        FakeProvider { port, log }
    }

    /// `http://127.0.0.1:<port>`.
    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// `sesame provider add <name>` on `m` for this provider: its
    /// `/authorize` and `/token`, the API at `<base><api_path>` on 127.0.0.1,
    /// and `extra` flags. It must succeed.
    pub fn add(&self, m: &Machine, name: &str, api_path: &str, extra: &[&str]) {
        let args = self.add_args(name, api_path, extra);
        let out = m.run(&args.iter().map(String::as_str).collect::<Vec<_>>());
        assert!(out.ok, "{out}");
    }

    /// The arguments [`FakeProvider::add`] runs.
    pub fn add_args(&self, name: &str, api_path: &str, extra: &[&str]) -> Vec<String> {
        let base = self.base();
        let mut args: Vec<String> = [
            "provider",
            "add",
            name,
            "--auth-url",
            &format!("{base}/authorize"),
            "--token-url",
            &format!("{base}/token"),
            "--api-base",
            &format!("{base}{api_path}"),
            "--host",
            "127.0.0.1",
        ]
        .map(String::from)
        .into();
        args.extend(extra.iter().map(|a| a.to_string()));
        args
    }

    /// Every request so far.
    pub fn requests(&self) -> Vec<Request> {
        self.log.lock().unwrap().clone()
    }

    /// The requests whose target starts with `prefix`.
    pub fn to(&self, prefix: &str) -> Vec<Request> {
        self.requests()
            .into_iter()
            .filter(|r| r.target.starts_with(prefix))
            .collect()
    }

    /// The refresh-token grants so far.
    pub fn refreshes(&self) -> Vec<Request> {
        self.requests()
            .into_iter()
            .filter(Request::is_refresh)
            .collect()
    }
}

/// A 1Password vault for a test: the fake `op` (tests/support/fake_op.rs) on
/// a PATH of its own, its items and call log in a scratch dir.
pub struct FakeVault {
    _scratch: Scratch,
    dir: PathBuf,
    bin: PathBuf,
}

pub const VAULT: &str = "scratch";
pub const SA_TOKEN: &str = "ops_service-account-secret";

impl FakeVault {
    pub fn new() -> FakeVault {
        let scratch = Scratch::new("vault");
        let dir = scratch.0.join("op");
        let bin = scratch.0.join("bin");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        // cargo test builds the example next to sesame, in target/<profile>/examples.
        let fake = Path::new(env!("CARGO_BIN_EXE_sesame"))
            .parent()
            .unwrap()
            .join("examples/fake-op");
        assert!(
            fake.exists(),
            "{} missing: run `cargo test`",
            fake.display()
        );
        std::os::unix::fs::symlink(&fake, bin.join("op")).unwrap();
        FakeVault {
            _scratch: scratch,
            dir,
            bin,
        }
    }

    /// Sets `c` up to use the vault, as a machine that opted in would.
    fn env<'a>(&self, c: &'a mut Command) -> &'a mut Command {
        c.env("SESAME_1PASSWORD_VAULT", VAULT)
            .env("OP_SERVICE_ACCOUNT_TOKEN", SA_TOKEN)
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
            .env("FAKE_OP_DIR", &self.dir)
            .env("FAKE_OP_TOKEN", SA_TOKEN)
            .env("FAKE_OP_VAULT", VAULT)
    }

    /// Every `op` call so far: its argv, and whether it had the token.
    pub fn calls(&self) -> Vec<(Vec<String>, bool)> {
        std::fs::read_to_string(self.dir.join("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                let argv = v["argv"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| a.as_str().unwrap().to_string())
                    .collect();
                (argv, v["token"].as_bool().unwrap())
            })
            .collect()
    }

    /// How many `op` calls so far wrote.
    pub fn writes(&self) -> usize {
        self.calls().iter().filter(|(a, _)| is_write(a)).count()
    }

    /// The items not archived.
    pub fn items(&self) -> Vec<serde_json::Value> {
        std::fs::read(self.dir.join("items.json"))
            .map(|b| serde_json::from_slice::<Vec<serde_json::Value>>(&b).unwrap())
            .unwrap_or_default()
            .into_iter()
            .filter(|i| i["state"] != "ARCHIVED")
            .collect()
    }

    pub fn item(&self, title: &str) -> Option<serde_json::Value> {
        self.items().into_iter().find(|i| i["title"] == title)
    }

    /// `op <args>` with `input` on stdin, as a person would run it; it must
    /// succeed. Returns its stdout.
    pub fn op(&self, args: &[&str], input: &str) -> String {
        let mut c = Command::new(self.bin.join("op"));
        self.env(&mut c);
        let mut child = c
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// `op read op://<vault>/<title>/<field>`.
    pub fn read(&self, reference: &str) -> String {
        self.op(&["read", reference], "")
    }
}

/// The field `label` of an item: (type, value).
pub fn field(item: &serde_json::Value, label: &str) -> Option<(String, String)> {
    item["fields"]
        .as_array()?
        .iter()
        .find(|f| f["label"] == label)
        .map(|f| {
            (
                f["type"].as_str().unwrap().to_string(),
                f["value"].as_str().unwrap().to_string(),
            )
        })
}
