//! Where a provider stands: the client in force, what that and the token make
//! the state and the next command to run, and which services the token
//! covers. The one place that is decided; `sesame providers` renders it and
//! a command that needs a token words its error from it.
use crate::oauth::{self, ClientSource};
use crate::providers::Provider;
use crate::store::{Client, Store, Token};

/// Whether a provider can be used yet.
#[derive(Debug, Clone, PartialEq)]
pub enum State {
    /// A token is stored; `who` is ` (site, account, pasted token)` or empty.
    LoggedIn { who: String },
    /// No token and no client to log in with: register one first.
    NoClient,
    /// No token, and a client to log in with.
    NotLoggedIn,
}

impl State {
    /// What `sesame providers` says of it.
    pub fn label(&self) -> String {
        match self {
            State::LoggedIn { who } => format!("logged in{who}"),
            State::NoClient => "no client".into(),
            State::NotLoggedIn => "not logged in".into(),
        }
    }
}

/// Where one service of the provider stands.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceStanding {
    pub name: String,
    /// The token covers every one of the service's scopes.
    pub authorized: bool,
    /// The command that adds its scopes, when it is not authorized and there
    /// is a client to log in with.
    pub next: Option<String>,
}

impl ServiceStanding {
    pub fn label(&self) -> &'static str {
        if self.authorized {
            "authorized"
        } else {
            "not authorized"
        }
    }
}

pub struct Standing {
    pub name: String,
    /// The client in force (`oauth::client`), if any.
    pub client: Option<(Client, ClientSource)>,
    pub state: State,
    /// Each of the provider's services, in its order.
    pub services: Vec<ServiceStanding>,
}

impl Standing {
    /// The command to run next, if any.
    pub fn next(&self) -> Option<String> {
        let name = &self.name;
        match self.state {
            State::LoggedIn { .. } => None,
            State::NoClient => Some(format!("sesame setup {name}")),
            State::NotLoggedIn => Some(format!("sesame login {name}")),
        }
    }

    /// The source of the client in force, if any.
    pub fn source(&self) -> Option<ClientSource> {
        self.client.as_ref().map(|(_, s)| *s)
    }
}

/// Where `name` stands, as the store has it now.
pub fn standing(store: &Store, name: &str, p: &Provider) -> Result<Standing, String> {
    Ok(of(
        name,
        p,
        oauth::client(store, name, p)?,
        store.token(name)?,
    ))
}

/// The error of a command that needs a token and found none, naming the
/// command to run next.
pub fn no_token(store: &Store, name: &str, p: &Provider) -> Result<String, String> {
    let s = of(name, p, oauth::client(store, name, p)?, None);
    Ok(match s.state {
        State::NoClient => oauth::no_client(name),
        _ => format!("not logged in to `{name}`; run `sesame login {name}`"),
    })
}

/// Where a provider stands with this client in force and this token.
fn of(
    name: &str,
    p: &Provider,
    client: Option<(Client, ClientSource)>,
    token: Option<Token>,
) -> Standing {
    let state = match (&client, &token) {
        (_, Some(t)) => State::LoggedIn { who: who(t) },
        (None, None) => State::NoClient,
        (Some(_), None) => State::NotLoggedIn,
    };
    let granted = token.as_ref().map(oauth::granted);
    let services = p
        .services
        .iter()
        .map(|(service, svc)| {
            let authorized = granted
                .as_ref()
                .is_some_and(|has| svc.scopes.iter().all(|s| has.contains(s)));
            let next = (client.is_some() && !authorized).then(|| format!("sesame login {service}"));
            ServiceStanding {
                name: service.clone(),
                authorized,
                next,
            }
        })
        .collect();
    Standing {
        name: name.into(),
        client,
        state,
        services,
    }
}

/// ` (site, account)` for a token, from what login learned, and whether it
/// was pasted; empty if nothing.
pub fn who(t: &Token) -> String {
    let parts: Vec<&str> = [&t.resource_name, &t.account]
        .into_iter()
        .flatten()
        .map(String::as_str)
        .chain(t.pasted.then_some("pasted token"))
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{Service, built_in};

    fn token(scope: Option<&str>) -> Token {
        Token {
            access_token: "a".into(),
            refresh_token: None,
            expires_at: None,
            scope: scope.map(String::from),
            resource_id: None,
            resource_name: None,
            pasted: false,
            account: None,
        }
    }

    /// A provider with a built-in client or none, and three services: one
    /// needing `a b`, one `c`, one nothing.
    fn provider(built_in_client: bool) -> Provider {
        let mut p = built_in("google");
        p.public_client_id = built_in_client.then(|| "pub".into());
        let svc = |scopes: &[&str]| Service {
            about: String::new(),
            api_base: "https://x.example".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            setup: vec![],
        };
        p.services = [
            ("ab".into(), svc(&["a", "b"])),
            ("c".into(), svc(&["c"])),
            ("none".into(), svc(&[])),
        ]
        .into();
        p
    }

    #[derive(Clone, Copy)]
    enum Has {
        Nothing,
        BuiltIn,
        User,
    }

    #[test]
    fn standing_table() {
        let pasted = Token {
            pasted: true,
            ..token(None)
        };
        let named = Token {
            resource_name: Some("site".into()),
            account: Some("octo".into()),
            ..token(Some("a,b"))
        };
        let logged_in = |who: &str| State::LoggedIn { who: who.into() };
        let (setup, login) = (Some("sesame setup p"), Some("sesame login p"));
        let svc = |name: &str, authorized: bool, next: bool| ServiceStanding {
            name: name.into(),
            authorized,
            next: next.then(|| format!("sesame login {name}")),
        };
        // (what, client, token, state, label, next, source, [ab, c, none])
        type Case<'a> = (
            &'a str,
            Has,
            Option<Token>,
            State,
            &'a str,
            Option<&'a str>,
            Option<ClientSource>,
            [ServiceStanding; 3],
        );
        #[rustfmt::skip]
        let cases: Vec<Case> = vec![
            ("no client, no token", Has::Nothing, None, State::NoClient, "no client", setup, None,
                [svc("ab", false, false), svc("c", false, false), svc("none", false, false)]),
            ("built-in client, no token", Has::BuiltIn, None, State::NotLoggedIn, "not logged in", login, Some(ClientSource::BuiltIn),
                [svc("ab", false, true), svc("c", false, true), svc("none", false, true)]),
            ("user client, no token", Has::User, None, State::NotLoggedIn, "not logged in", login, Some(ClientSource::User),
                [svc("ab", false, true), svc("c", false, true), svc("none", false, true)]),
            ("logged in, no who", Has::User, Some(token(Some("a b c"))), logged_in(""), "logged in", None, Some(ClientSource::User),
                [svc("ab", true, false), svc("c", true, false), svc("none", true, false)]),
            ("logged in, site and account", Has::BuiltIn, Some(named), logged_in(" (site, octo)"), "logged in (site, octo)", None, Some(ClientSource::BuiltIn),
                [svc("ab", true, false), svc("c", false, true), svc("none", true, false)]),
            ("pasted, no client left", Has::Nothing, Some(pasted.clone()), logged_in(" (pasted token)"), "logged in (pasted token)", None, None,
                [svc("ab", false, false), svc("c", false, false), svc("none", true, false)]),
            ("pasted, user client", Has::User, Some(pasted), logged_in(" (pasted token)"), "logged in (pasted token)", None, Some(ClientSource::User),
                [svc("ab", false, true), svc("c", false, true), svc("none", true, false)]),
            ("some scopes of a service", Has::User, Some(token(Some("a c"))), logged_in(""), "logged in", None, Some(ClientSource::User),
                [svc("ab", false, true), svc("c", true, false), svc("none", true, false)]),
        ];
        for (what, has, t, state, label, next, source, services) in cases {
            let store = Store::in_memory().unwrap();
            if let Has::User = has {
                let c = Client {
                    client_id: "mine".into(),
                    client_secret: None,
                };
                store.save_client("p", &c).unwrap();
            }
            if let Some(t) = &t {
                store.save_token("p", t).unwrap();
            }
            let p = provider(matches!(has, Has::BuiltIn));
            let s = standing(&store, "p", &p).unwrap();
            assert_eq!(s.state, state, "{what}");
            assert_eq!(s.state.label(), label, "{what}");
            assert_eq!(s.next().as_deref(), next, "{what}");
            assert_eq!(s.source(), source, "{what}");
            assert_eq!(s.services, services, "{what}");
            let labels: Vec<_> = s.services.iter().map(ServiceStanding::label).collect();
            let want: Vec<_> = services
                .iter()
                .map(|s| {
                    if s.authorized {
                        "authorized"
                    } else {
                        "not authorized"
                    }
                })
                .collect();
            assert_eq!(labels, want, "{what}");
        }
    }

    #[test]
    fn the_user_client_wins_over_the_built_in() {
        let store = Store::in_memory().unwrap();
        let c = Client {
            client_id: "mine".into(),
            client_secret: None,
        };
        store.save_client("p", &c).unwrap();
        let s = standing(&store, "p", &provider(true)).unwrap();
        assert_eq!(s.client, Some((c, ClientSource::User)));
    }

    #[test]
    fn no_token_names_the_next_command() {
        let store = Store::in_memory().unwrap();
        let err = no_token(&store, "p", &provider(false)).unwrap();
        assert_eq!(err, oauth::no_client("p"));
        let err = no_token(&store, "p", &provider(true)).unwrap();
        assert_eq!(err, "not logged in to `p`; run `sesame login p`");
    }
}
