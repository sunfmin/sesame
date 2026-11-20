mod api;
mod guide;
mod oauth;
mod providers;
mod refresh;
mod setup;
mod source;
mod standing;
mod store;
// build.rs runs it to stamp the version; compiled here too, for its tests.
#[cfg_attr(not(test), allow(dead_code))]
mod version;
mod wire;

use clap::{Parser, Subcommand};
use standing::who;
use std::io::Read;
use std::process::ExitCode;
use store::{Client, Store};

const FOR_AI: &str = "\
If you are an AI using sesame for someone:
  1. Run `sesame providers` to see where each provider stands.
  2. For one showing `no client`, run `sesame setup <provider>` and walk the person
     through its steps. One with a `built-in client` (github) needs no setup. Never ask for a client secret or a token in the chat: the
     person runs `sesame client` (or `sesame login --token`) in their own terminal,
     which prompts for it.
  3. Have the person run `sesame login <service>` (or `<provider>`) and approve access
     in the browser themselves. A service (gmail, calendar, ...) shares its provider's
     client and token; logging in to it adds its scopes.
  4. Then call the API: `sesame api <service> <path>`.
  5. When the person wants a platform sesame does not know, run `sesame provider guide`
     and follow it.";

/// Sign in to SaaS APIs from the terminal and call them with the stored token.
#[derive(Parser)]
#[command(name = "sesame", version = env!("SESAME_VERSION"), before_help = FOR_AI)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List the providers and their services, and whether you are signed in to each.
    Providers,
    /// Add, change, show or remove a provider definition (stored in sesame.db, or the 1Password vault of `SESAME_1PASSWORD_VAULT`).
    Provider {
        #[command(subcommand)]
        cmd: Box<ProviderCmd>,
    },
    /// Move what sesame keeps from one store to another.
    Store {
        #[command(subcommand)]
        cmd: StoreCmd,
    },
    /// Print the steps to register a provider's OAuth app and get to a working login.
    Setup { provider: String },
    /// Store your own OAuth client (app) to sign in to a provider with, in place
    /// of the built-in one where the provider has one (github); `--reset` forgets it.
    Client {
        provider: String,
        #[arg(long, required_unless_present = "reset")]
        client_id: Option<String>,
        /// Read the client secret from stdin instead of prompting.
        #[arg(long)]
        secret_stdin: bool,
        /// The client has no secret (public client with PKCE).
        #[arg(long, conflicts_with = "secret_stdin")]
        no_secret: bool,
        /// Forget your stored client: login goes back to the built-in one, if any.
        #[arg(long, conflicts_with_all = ["client_id", "secret_stdin", "no_secret"])]
        reset: bool,
    },
    /// Sign in through the provider's OAuth page and store the token. A provider
    /// with a device endpoint (github) prints a code to enter on its page instead.
    /// For a service (gmail), signs in to its provider asking for the scopes
    /// already granted and the service's: the one token then covers both.
    /// `--token` stores a token you paste instead.
    Login {
        /// A provider, or a service of one.
        provider: String,
        /// Store a token you got another way (e.g. from the provider's app page)
        /// instead of the OAuth login; asks for it with hidden input. It has no
        /// refresh: when it stops working, paste a new one.
        #[arg(long, conflicts_with_all = ["scopes", "no_browser", "browser", "site"])]
        token: bool,
        /// Like --token, reading the token from stdin.
        #[arg(long, conflicts_with_all = ["token", "scopes", "no_browser", "browser", "site"])]
        token_stdin: bool,
        /// Scope to ask for instead of the defaults; repeatable.
        #[arg(long = "scope")]
        scopes: Vec<String>,
        /// Print the URL only; do not try to open a browser.
        #[arg(long)]
        no_browser: bool,
        /// Sign in through the loopback redirect even when the provider offers
        /// the device flow (needs the client secret where the provider does).
        #[arg(long)]
        browser: bool,
        /// Which site to use when the login reaches several (Jira).
        #[arg(long)]
        site: Option<String>,
    },
    /// Forget the stored token.
    Logout { provider: String },
    /// Print a valid access token, refreshing it if needed (for curl and scripts),
    /// or the token handed in the environment.
    #[command(after_help = source::HELP)]
    Token {
        provider: String,
        /// Print one JSON line, `{"access_token": "…", "expires_at": <unix seconds>}`,
        /// instead of the token alone; `expires_at` is null when sesame knows no
        /// expiry (a pasted token, a handed one).
        #[arg(long)]
        json: bool,
        /// Refresh the stored token first where it expires within these
        /// seconds (60 without it), for a holder that hands it on and needs
        /// it to last. The provider's new token is printed even where it
        /// lasts less: its expiry (`--json`) says how long. A handed token is
        /// printed as it is.
        #[arg(long, value_name = "SECONDS")]
        min_life: Option<u64>,
    },
    /// Call the API with the provider's stored token, or one handed in the environment.
    #[command(after_help = source::HELP)]
    Api(api::Call),
}

#[derive(Subcommand)]
enum StoreCmd {
    /// Copy every client, token and provider field in sesame.db into the
    /// 1Password vault of `SESAME_1PASSWORD_VAULT`, then rename sesame.db
    /// (not delete it). Overwrites nothing: what the vault already holds for a
    /// provider is reported as a conflict. Run it again to go on after a run
    /// cut short; once everything is copied it writes nothing.
    Migrate,
}

#[derive(Subcommand)]
enum ProviderCmd {
    /// Add a provider; the flags marked (required) must be given.
    Add {
        name: String,
        #[command(flatten)]
        fields: providers::FieldFlags,
    },
    /// Change a provider's fields; a repeatable flag replaces its whole list.
    /// For a built-in provider only the changed fields are stored: the rest
    /// follows each new sesame version.
    Set {
        name: String,
        #[command(flatten)]
        fields: providers::FieldFlags,
    },
    /// Print the definition in force as JSON, each field marked `built-in`, `user` or `default`.
    Show { name: String },
    /// Remove a provider you added, or your changes to a built-in one.
    Rm { name: String },
    /// How to connect a platform sesame does not know: the steps and the questions
    /// to answer from its docs, one per field. Written for an AI.
    Guide,
    /// Read a platform's OAuth metadata (RFC 8414, OpenID Connect) and print a draft
    /// `sesame provider add`. Takes a domain, an issuer or a metadata URL; writes nothing.
    Discover { url: String },
    /// Print the `sesame provider add` command that makes this definition again.
    Export { name: String },
}

fn main() -> ExitCode {
    store::take_token();
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sesame: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.cmd {
        Cmd::Providers => {
            let store = Store::open_current()?;
            for (name, p) in providers::all(&store)? {
                let st = standing::standing(&store, &name, &p)?;
                let state = st.state.label();
                let source = st.source().map(|s| s.label()).unwrap_or_default();
                let next_col =
                    |n: Option<&String>| n.map(|n| format!("next: {n}")).unwrap_or_default();
                let next = next_col(st.next().as_ref());
                println!("{name:<12} {state:<24} {source:<16} {next:<28} {}", p.about);
                for (s, svc) in st.services.iter().zip(p.services.values()) {
                    let (service, state) = (&s.name, s.label());
                    let next = next_col(s.next.as_ref());
                    println!(
                        "  {service:<10} {state:<24} {:<16} {next:<28} {}",
                        "", svc.about
                    );
                }
            }
        }
        Cmd::Provider { cmd } => provider(*cmd)?,
        Cmd::Store {
            cmd: StoreCmd::Migrate,
        } => store::migrate()?,
        Cmd::Setup { provider } => {
            let t = providers::find(&Store::open()?, &provider)?;
            print!("{}", setup::render(&t.provider, &t.p));
        }
        Cmd::Client {
            provider, reset, ..
        } if reset => {
            let store = Store::open()?;
            let t = providers::find(&store, &provider)?;
            let had = store.delete_client(&t.provider)?;
            let then = if oauth::client(&store, &t.provider, &t.p)?.is_some() {
                "login uses the built-in client"
            } else {
                "it has no built-in client: store one with `sesame client` to log in"
            };
            let what = if had {
                "Forgot your"
            } else {
                "There was no stored"
            };
            eprintln!("{what} `{}` client; {then}.", t.provider);
        }
        Cmd::Client {
            provider,
            client_id,
            secret_stdin,
            no_secret,
            ..
        } => {
            let store = Store::open()?;
            let provider = providers::find(&store, &provider)?.provider;
            let client_id = client_id.ok_or("give --client-id, or --reset")?;
            let client_secret = if no_secret {
                None
            } else if secret_stdin {
                let mut s = String::new();
                std::io::stdin()
                    .read_to_string(&mut s)
                    .map_err(|e| e.to_string())?;
                Some(s.trim().to_string())
            } else {
                Some(rpassword::prompt_password("Client secret: ").map_err(|e| e.to_string())?)
            };
            store.save_client(
                &provider,
                &Client {
                    client_id,
                    client_secret,
                },
            )?;
            eprintln!("Stored the `{provider}` client.");
        }
        Cmd::Login {
            provider,
            token,
            token_stdin,
            ..
        } if token || token_stdin => {
            let store = Store::open()?;
            let t = providers::find(&store, &provider)?;
            let (provider, p) = (t.provider, t.p);
            let pasted = if token_stdin {
                let mut s = String::new();
                std::io::stdin()
                    .read_to_string(&mut s)
                    .map_err(|e| e.to_string())?;
                s
            } else {
                rpassword::prompt_password("Token: ").map_err(|e| e.to_string())?
            };
            let t = oauth::save_pasted(&store, &provider, &p, &pasted)?;
            eprintln!("Stored the pasted `{provider}` token{}.", who(&t));
        }
        Cmd::Login {
            provider,
            scopes,
            no_browser,
            browser,
            site,
            ..
        } => {
            let store = Store::open()?;
            let t = providers::find(&store, &provider)?;
            let opts = oauth::LoginOptions {
                scopes: (!scopes.is_empty()).then_some(scopes),
                open_browser: !no_browser && std::env::var_os("SSH_CONNECTION").is_none(),
                site,
                loopback: browser,
            };
            let token = oauth::login(&store, &t, &opts)?;
            let service = t
                .service
                .as_ref()
                .map(|s| format!(" for `{s}`"))
                .unwrap_or_default();
            eprintln!("Logged in to `{}`{service}{}.", t.provider, who(&token));
        }
        Cmd::Logout { provider } => {
            let store = Store::open()?;
            let provider = providers::find(&store, &provider)?.provider;
            store.delete_token(&provider)?;
            eprintln!("Logged out of `{provider}` (the token of all its services).");
        }
        Cmd::Token {
            provider,
            json,
            min_life,
        } => {
            let (t, source) = source::find(&provider, Store::open)?;
            let token = source.token(&t, min_life.unwrap_or(refresh::MIN_LIFE))?;
            if json {
                let v = serde_json::json!({
                    "access_token": token.access_token,
                    "expires_at": token.expires_at,
                });
                println!("{v}");
            } else {
                println!("{}", token.access_token);
            }
        }
        Cmd::Api(call) => return call.run(),
    }
    Ok(ExitCode::SUCCESS)
}

/// `sesame provider …`.
fn provider(cmd: ProviderCmd) -> Result<(), String> {
    match cmd {
        ProviderCmd::Add { name, fields } => {
            providers::add(&Store::open()?, &name, fields.0)?;
            eprintln!("Added the provider `{name}`; next: sesame setup {name}");
        }
        ProviderCmd::Set { name, fields } => {
            providers::set(&Store::open()?, &name, fields.0)?;
            eprintln!("Changed the provider `{name}`; see it with `sesame provider show {name}`.");
        }
        ProviderCmd::Show { name } => {
            let v = providers::show(&Store::open()?, &name)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
            );
        }
        ProviderCmd::Rm { name } => eprintln!("{}", providers::remove(&Store::open()?, &name)?),
        ProviderCmd::Guide => print!("{}", guide::render()),
        ProviderCmd::Discover { url } => print!("{}", guide::discover(&url)?),
        ProviderCmd::Export { name } => print!("{}", providers::export(&Store::open()?, &name)?),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// A command opens the store once and hands it down: only the command
    /// entry points (`main.rs`, `api.rs`) open it, never a function they call.
    #[test]
    fn only_commands_open_the_store() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![src.clone()];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let path = e.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let rel = path.strip_prefix(&src).unwrap().to_string_lossy();
                if ["main.rs", "api.rs"].contains(&rel.as_ref()) {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                assert!(
                    !text.contains(concat!("Store", "::open(")),
                    "{rel} opens the store: take a `&Store` from the command instead"
                );
            }
        }
    }
}
