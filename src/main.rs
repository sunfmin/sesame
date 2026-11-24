mod api;
mod guide;
mod help;
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

use clap::{FromArgMatches, Parser, Subcommand};
use help::groups;
use standing::who;
use std::io::Read;
use std::process::ExitCode;
use store::{Client, Store};

agent_help::binary!("sesame");

/// Sign in to SaaS APIs that have no CLI of their own, from the terminal, and call their REST APIs with the stored token.
///
/// A provider is one OAuth login and its one token (`google`, `github`); a service is one API of a provider, reached with its token (`gmail`, `calendar`). sesame keeps clients, tokens and the person's provider definitions in `sesame.db`, or in the 1Password vault `{const:VAULT_VAR}` names, through the `op` CLI.
///
/// Run `sesame <command> --help` before a command's first run. If you are an AI using sesame for someone:
///
/// 1. Run `sesame providers` to see where each provider stands.
/// 2. For one showing `no client`, run `sesame setup <provider>` and walk the person through its steps. One with a `built-in client` (github) needs no setup.
/// 3. Have the person run `sesame login <service>` (or `<provider>`) in their own terminal and approve access in the browser themselves (see [signing in](help:signing-in)).
/// 4. Then call the API: `sesame api <service> <path>`.
/// 5. When the person wants a platform sesame does not know, run `sesame provider guide` and follow it.
///
/// ## Rules to know first
///
/// - Never ask for a client secret or a token in the chat: the person runs `sesame client` (or `sesame login --token`) in their own terminal, which prompts for it.
/// - stdout is not one JSON object: `sesame api` prints the API's answer as it came (pretty-printed on a terminal), `sesame token` the token, `sesame provider show` JSON, and the other commands text. What sesame says goes to stderr; a failure is one line there starting `sesame:` and a non-zero exit.
/// - `sesame api` and `sesame token` take a token handed in the environment before the stored one (see [handed tokens](help:handed-token)).
#[derive(Parser)]
#[command(
    name = "sesame",
    version = env!("SESAME_VERSION"),
    disable_help_subcommand = true,
    verbatim_doc_comment
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List the providers and their services, and where you stand with each.
    ///
    /// Run it first. It prints one line per provider, then one per service of it, indented: the name, whether a client is stored and you are signed in, where the token comes from, the next step (`next: sesame setup jira`), and what it is. Reads the store; with the 1Password store it syncs its local copy first.
    #[command(next_help_heading = groups::AGENT, verbatim_doc_comment)]
    Providers,
    /// Add, change, show or remove a provider definition.
    ///
    /// Definitions are stored in `sesame.db`, or the 1Password vault of `{const:VAULT_VAR}`. A built-in provider's fields you did not `set` follow each new version of sesame.
    #[command(next_help_heading = groups::AGENT, verbatim_doc_comment)]
    Provider {
        #[command(subcommand)]
        cmd: Box<ProviderCmd>,
    },
    /// Move what sesame keeps from one store to another.
    #[command(next_help_heading = groups::PERSON, verbatim_doc_comment)]
    Store {
        #[command(subcommand)]
        cmd: StoreCmd,
    },
    /// Print the steps to register a provider's OAuth app and get to a working login.
    ///
    /// Run it for a provider `sesame providers` shows with `no client`, and walk the person through the steps; it writes nothing.
    #[command(next_help_heading = groups::AGENT, verbatim_doc_comment)]
    Setup {
        /// A provider, or a service of one.
        #[arg(verbatim_doc_comment)]
        provider: String,
    },
    /// Store your own OAuth client (app) to sign in to a provider with.
    ///
    /// It takes the place of the built-in one where the provider has one (github); `--reset` forgets it. Without `--secret-stdin` or `--no-secret` it prompts for the client secret with hidden input: the person runs it, never the chat (see [signing in](help:signing-in)).
    #[command(next_help_heading = groups::PERSON, verbatim_doc_comment)]
    Client {
        /// A provider, or a service of one.
        #[arg(verbatim_doc_comment)]
        provider: String,
        /// The client's id, from the provider's app page.
        #[arg(long, required_unless_present = "reset", verbatim_doc_comment)]
        client_id: Option<String>,
        /// Read the client secret from stdin instead of prompting.
        #[arg(long, verbatim_doc_comment)]
        secret_stdin: bool,
        /// The client has no secret (public client with PKCE).
        #[arg(long, conflicts_with = "secret_stdin", verbatim_doc_comment)]
        no_secret: bool,
        /// Forget your stored client: login goes back to the built-in one, if any.
        #[arg(long, conflicts_with_all = ["client_id", "secret_stdin", "no_secret"], verbatim_doc_comment)]
        reset: bool,
    },
    /// Sign in through the provider's OAuth page and store the token.
    ///
    /// A provider with a device endpoint (github) prints a code to enter on its page instead. For a service (gmail), it signs in to its provider asking for the scopes already granted and the service's: the one token then covers both. `--token` stores a token you paste instead. The person runs it and approves access themselves (see [signing in](help:signing-in)).
    #[command(next_help_heading = groups::PERSON, verbatim_doc_comment)]
    Login {
        /// A provider, or a service of one.
        #[arg(verbatim_doc_comment)]
        provider: String,
        /// Store a token you got another way (e.g. from the provider's app page) instead of the OAuth login; asks for it with hidden input. It has no refresh: when it stops working, paste a new one.
        #[arg(long, conflicts_with_all = ["scopes", "no_browser", "browser", "site"], verbatim_doc_comment)]
        token: bool,
        /// Like --token, reading the token from stdin.
        #[arg(long, conflicts_with_all = ["token", "scopes", "no_browser", "browser", "site"], verbatim_doc_comment)]
        token_stdin: bool,
        /// Scope to ask for instead of the defaults; repeatable.
        #[arg(long = "scope", verbatim_doc_comment)]
        scopes: Vec<String>,
        /// Print the URL only; do not try to open a browser.
        #[arg(long, verbatim_doc_comment)]
        no_browser: bool,
        /// Sign in through the loopback redirect even when the provider offers the device flow (needs the client secret where the provider does).
        #[arg(long, verbatim_doc_comment)]
        browser: bool,
        /// Which site to use when the login reaches several (Jira).
        #[arg(long, verbatim_doc_comment)]
        site: Option<String>,
    },
    /// Forget the stored token.
    ///
    /// It forgets the token of the provider and so of all its services, in the store only: the grant on the provider's side stays.
    #[command(next_help_heading = groups::AGENT, verbatim_doc_comment)]
    Logout {
        /// A provider, or a service of one.
        #[arg(verbatim_doc_comment)]
        provider: String,
    },
    /// Print a valid access token, refreshing it if needed (for curl and scripts), or the token handed in the environment.
    ///
    /// It prints the token alone on one line, or with `--json` one JSON object. A token handed in the environment is printed as it is, never refreshed (see [handed tokens](help:handed-token)).
    #[command(next_help_heading = groups::AGENT, verbatim_doc_comment)]
    Token {
        /// A provider, or a service of one.
        #[arg(verbatim_doc_comment)]
        provider: String,
        /// Print one JSON line, `{"access_token": "…", "expires_at": <unix seconds>}`, instead of the token alone; `expires_at` is null when sesame knows no expiry (a pasted token, a handed one).
        #[arg(long, verbatim_doc_comment)]
        json: bool,
        /// Refresh the stored token first where it expires within these seconds ({const:MIN_LIFE} without it), for a holder that hands it on and needs it to last. The provider's new token is printed even where it lasts less: its expiry (`--json`) says how long. A handed token is printed as it is.
        #[arg(long, value_name = "SECONDS", verbatim_doc_comment)]
        min_life: Option<u64>,
    },
    /// Call the API with the provider's stored token, or one handed in the environment.
    ///
    /// The path is resolved under the API base; a full URL is sent only to a host the provider lists. On a 401 the stored token is refreshed and the call made once more; on a 403 for want of a scope it says which login adds it. The answer goes to stdout as it came, pretty-printed on a terminal; the status line goes to stderr when it is an error or with `-i`. It exits non-zero when the API answered an error status, or an error field the provider names (GraphQL `errors`). A token handed in the environment is used as it is (see [handed tokens](help:handed-token)).
    #[command(next_help_heading = groups::AGENT, verbatim_doc_comment)]
    Api(api::Call),
    /// Show one topic of this manual, or all of it.
    ///
    /// `sesame help <topic>` shows a topic, `sesame help all` the whole manual, every command and topic in full; without a topic it shows what `sesame --help` does. An unknown topic is a usage error naming the topics.
    #[command(next_help_heading = groups::AGENT, verbatim_doc_comment)]
    Help {
        /// The topic, such as `signing-in`, or `all`.
        #[arg(verbatim_doc_comment)]
        topic: Option<String>,
    },
}

#[derive(Subcommand)]
enum StoreCmd {
    /// Copy every client, token and provider field in sesame.db into the 1Password vault of `{const:VAULT_VAR}`, then rename sesame.db (not delete it).
    ///
    /// Overwrites nothing: what the vault already holds for a provider is reported as a conflict. Run it again to go on after a run cut short; once everything is copied it writes nothing.
    #[command(verbatim_doc_comment)]
    Migrate,
}

#[derive(Subcommand)]
enum ProviderCmd {
    /// Add a provider; the flags marked (required) must be given.
    ///
    /// It refuses an invalid value, or a fixed `--redirect-port` another provider already uses, before writing anything. Next: `sesame setup <name>`.
    #[command(verbatim_doc_comment)]
    Add {
        /// The provider's name, used on the command line.
        #[arg(verbatim_doc_comment)]
        name: String,
        #[command(flatten)]
        fields: providers::FieldFlags,
    },
    /// Change a provider's fields; a repeatable flag replaces its whole list.
    ///
    /// For a built-in provider only the changed fields are stored: the rest follows each new sesame version. It refuses an invalid value before writing anything.
    #[command(verbatim_doc_comment)]
    Set {
        /// The provider's name.
        #[arg(verbatim_doc_comment)]
        name: String,
        #[command(flatten)]
        fields: providers::FieldFlags,
    },
    /// Print the definition in force as JSON, each field marked `built-in`, `user` or `default`.
    #[command(verbatim_doc_comment)]
    Show {
        /// The provider's name.
        #[arg(verbatim_doc_comment)]
        name: String,
    },
    /// Remove a provider you added, or your changes to a built-in one.
    #[command(verbatim_doc_comment)]
    Rm {
        /// The provider's name.
        #[arg(verbatim_doc_comment)]
        name: String,
    },
    /// How to connect a platform sesame does not know: the steps and the questions to answer from its docs, one per field.
    ///
    /// Written for an AI: run it and follow it when the person wants a platform sesame does not know. Its answer is its output, on stdout; it writes nothing.
    #[command(verbatim_doc_comment)]
    Guide,
    /// Read a platform's OAuth metadata (RFC 8414, OpenID Connect) and print a draft `sesame provider add`.
    ///
    /// Takes a domain, an issuer or a metadata URL; writes nothing. The draft holds only what the metadata says: `sesame provider guide` says how to find the rest.
    #[command(verbatim_doc_comment)]
    Discover {
        /// A domain, an OAuth issuer, or a metadata URL.
        #[arg(verbatim_doc_comment)]
        url: String,
    },
    /// Print the `sesame provider add` command that makes this definition again.
    #[command(verbatim_doc_comment)]
    Export {
        /// The provider's name.
        #[arg(verbatim_doc_comment)]
        name: String,
    },
}

fn main() -> ExitCode {
    store::take_token();
    match run(parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sesame: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Parse without the manual when the line parses; `--help`, `-h` and a line
/// clap refuses go through the manual, so every help answer and usage error
/// is its text.
fn parse() -> Cli {
    Cli::try_parse().unwrap_or_else(|_| {
        let command = help::manual()
            .clap()
            .expect("checked by the_manual_is_whole");
        command
            .try_get_matches()
            .and_then(|m| Cli::from_arg_matches(&m))
            .unwrap_or_else(|e| e.exit())
    })
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
        Cmd::Help { topic } => match help::answer(topic.as_deref()) {
            Ok(markdown) => print!("{markdown}"),
            Err(e) => e.exit(),
        },
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
    #[test]
    fn the_command_tree_is_well_formed() {
        <super::Cli as clap::CommandFactory>::command().debug_assert();
    }

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
