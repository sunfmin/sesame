//! When the stored token is used as it is and when it is refreshed first.
//! `decide` makes every such choice from what the store holds, the time and
//! the refresh mode, and nothing else; `valid_token` runs it against the
//! store the command opened and the provider's token endpoint.
use crate::oauth;
use crate::providers::Provider;
use crate::store::{Store, Token};

/// The least life, in seconds, a stored token is used with: one that expires
/// sooner is refreshed first.
pub const MIN_LIFE: u64 = 60;

/// When `valid_token` refreshes the stored token.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Refresh {
    /// Where it expires within these seconds (never fewer than `MIN_LIFE`).
    Within(u64),
    /// Always: the provider refused it.
    Now,
}

/// How far the store has been read.
#[derive(Debug, PartialEq)]
pub enum Read {
    /// Once, as this machine had it.
    First,
    /// Again, after the store caught up with what other machines wrote;
    /// `before` is the access token the first read found, if any.
    CaughtUp { before: Option<String> },
}

/// What to do with the token a read found.
#[derive(Debug, PartialEq)]
pub enum Step {
    /// Use it as it is.
    Use(Token),
    /// Let the store catch up (another machine may have logged in or
    /// refreshed already), then read again.
    CatchUp,
    /// Refresh it with its refresh token.
    Refresh(Token, String),
    /// There is no token, even after catching up.
    NotLoggedIn,
    /// It must be refreshed and cannot be.
    NoRefreshToken,
}

/// The one place each refresh rule is decided: given the token `read` found
/// (`None` for none), the time in Unix seconds and the mode, what to do next.
pub fn decide(token: Option<Token>, read: &Read, now: u64, refresh: Refresh) -> Step {
    let fresh = |t: &Token| match refresh {
        Refresh::Within(secs) => t.expires_at.is_none_or(|e| e > now + secs.max(MIN_LIFE)),
        Refresh::Now => false,
    };
    match (read, token) {
        (Read::First, Some(t)) if fresh(&t) => Step::Use(t),
        (Read::First, _) => Step::CatchUp,
        (Read::CaughtUp { .. }, None) => Step::NotLoggedIn,
        (Read::CaughtUp { before }, Some(t)) => {
            // For `Now`, any token other than the one refused is new.
            let other = refresh == Refresh::Now && before.as_ref() != Some(&t.access_token);
            if fresh(&t) || other {
                return Step::Use(t);
            }
            match t.refresh_token.clone() {
                Some(r) => Step::Refresh(t, r),
                None => Step::NoRefreshToken,
            }
        }
    }
}

/// The stored token, refreshed first as `refresh` says. The provider's new
/// token is returned even where it lasts less than asked: its expiry says so.
/// The read, the refresh and the write hold the store's lock, so a second
/// process refreshing the same provider waits and then sees the new token.
pub fn valid_token(
    store: &Store,
    name: &str,
    p: &Provider,
    refresh: Refresh,
) -> Result<Token, String> {
    run(
        store,
        name,
        refresh,
        oauth::now(),
        |store, token, refresh_token| oauth::refresh(store, name, p, token, refresh_token),
        |store| Ok(oauth::client(store, name, p)?.is_some()),
    )
}

/// `valid_token` with the token endpoint (`grant`: the stored token and its
/// refresh token to the new token) and whether there is a client to log in
/// with (`has_client`, for the error) given.
fn run(
    store: &Store,
    name: &str,
    refresh: Refresh,
    now: u64,
    grant: impl FnOnce(&Store, &Token, String) -> Result<Token, String>,
    has_client: impl FnOnce(&Store) -> Result<bool, String>,
) -> Result<Token, String> {
    store.locked(|store| {
        let mut read = Read::First;
        loop {
            let token = store.token(name)?;
            let before = token.as_ref().map(|t| t.access_token.clone());
            match decide(token, &read, now, refresh) {
                Step::Use(t) => return Ok(t),
                Step::CatchUp => {
                    store.sync(name)?;
                    read = Read::CaughtUp { before };
                }
                Step::Refresh(t, refresh_token) => {
                    let new = grant(store, &t, refresh_token)?;
                    store.save_token(name, &new)?;
                    return Ok(new);
                }
                Step::NotLoggedIn if !has_client(store)? => return Err(oauth::no_client(name)),
                Step::NotLoggedIn => {
                    return Err(format!(
                        "not logged in to `{name}`; run `sesame login {name}`"
                    ));
                }
                Step::NoRefreshToken => {
                    return Err(format!(
                        "`{name}` token expired and has no refresh token; run `sesame login {name}`"
                    ));
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;

    fn token(access: &str, expires_in: Option<u64>, refresh: Option<&str>) -> Token {
        Token {
            access_token: access.into(),
            refresh_token: refresh.map(String::from),
            expires_at: expires_in.map(|s| NOW + s),
            scope: None,
            resource_id: None,
            resource_name: None,
            pasted: false,
            account: None,
        }
    }

    fn caught_up(before: Option<&str>) -> Read {
        Read::CaughtUp {
            before: before.map(String::from),
        }
    }

    #[test]
    fn decide_table() {
        let a = |s| token("a", s, Some("r"));
        let within = Refresh::Within(MIN_LIFE);
        let use_ = |t: Token| Step::Use(t);
        let refresh = |t: Token| Step::Refresh(t, "r".into());
        #[rustfmt::skip]
        let cases: Vec<(&str, Option<Token>, Read, Refresh, Step)> = vec![
            ("fresh: used", Some(a(Some(3600))), Read::First, within, use_(a(Some(3600)))),
            ("no expiry: used", Some(a(None)), Read::First, within, use_(a(None))),
            ("within MIN_LIFE: catch up first", Some(a(Some(30))), Read::First, within, Step::CatchUp),
            ("exactly MIN_LIFE left: catch up", Some(a(Some(60))), Read::First, within, Step::CatchUp),
            ("expired: catch up", Some(token("a", None, None)).map(|mut t| { t.expires_at = Some(NOW - 1); t }), Read::First, within, Step::CatchUp),
            ("--min-life below MIN_LIFE counts as MIN_LIFE", Some(a(Some(30))), Read::First, Refresh::Within(10), Step::CatchUp),
            ("--min-life 1700, 1000 left: catch up", Some(a(Some(1000))), Read::First, Refresh::Within(1700), Step::CatchUp),
            ("--min-life 1700, 1800 left: used", Some(a(Some(1800))), Read::First, Refresh::Within(1700), use_(a(Some(1800)))),
            ("none here: catch up", None, Read::First, within, Step::CatchUp),
            ("refused: catch up even when fresh", Some(a(Some(3600))), Read::First, Refresh::Now, Step::CatchUp),
            ("still none after catching up", None, caught_up(None), within, Step::NotLoggedIn),
            ("another machine logged in", Some(a(Some(3600))), caught_up(None), within, use_(a(Some(3600)))),
            ("another machine refreshed", Some(a(Some(3600))), caught_up(Some("old")), within, use_(a(Some(3600)))),
            ("still stale: refresh", Some(a(Some(30))), caught_up(Some("a")), within, refresh(a(Some(30)))),
            ("stale, no refresh token", Some(token("a", Some(30), None)), caught_up(Some("a")), within, Step::NoRefreshToken),
            ("refused and newer: used", Some(a(Some(3600))), caught_up(Some("old")), Refresh::Now, use_(a(Some(3600)))),
            ("refused, none before, one now: used", Some(a(Some(3600))), caught_up(None), Refresh::Now, use_(a(Some(3600)))),
            ("refused and not newer: refresh", Some(a(Some(3600))), caught_up(Some("a")), Refresh::Now, refresh(a(Some(3600)))),
            ("refused, not newer, no refresh token", Some(token("a", None, None)), caught_up(Some("a")), Refresh::Now, Step::NoRefreshToken),
        ];
        for (what, t, read, mode, want) in cases {
            assert_eq!(decide(t, &read, NOW, mode), want, "{what}");
        }
    }

    fn store_with(t: Option<Token>) -> Store {
        let s = Store::in_memory().unwrap();
        if let Some(t) = t {
            s.save_token("p", &t).unwrap();
        }
        s
    }

    fn no_grant(_: &Store, _: &Token, _: String) -> Result<Token, String> {
        panic!("refreshed")
    }

    #[test]
    fn fresh_token_is_used_without_the_endpoint() {
        let s = store_with(Some(token("a", Some(3600), Some("r"))));
        let got = run(&s, "p", Refresh::Within(MIN_LIFE), NOW, no_grant, |_| {
            Ok(true)
        });
        assert_eq!(got.unwrap().access_token, "a");
    }

    #[test]
    fn stale_token_is_refreshed_and_stored() {
        let s = store_with(Some(token("a", Some(30), Some("r1"))));
        let got = run(
            &s,
            "p",
            Refresh::Within(MIN_LIFE),
            NOW,
            |_, old, r| {
                assert_eq!((old.access_token.as_str(), r.as_str()), ("a", "r1"));
                Ok(token("b", Some(3600), Some("r2")))
            },
            |_| Ok(true),
        )
        .unwrap();
        assert_eq!(got.access_token, "b");
        assert_eq!(s.token("p").unwrap(), Some(got));
    }

    #[test]
    fn refused_token_is_refreshed_even_when_fresh() {
        let s = store_with(Some(token("a", Some(3600), Some("r"))));
        let got = run(
            &s,
            "p",
            Refresh::Now,
            NOW,
            |_, _, _| Ok(token("b", Some(3600), Some("r"))),
            |_| Ok(true),
        );
        assert_eq!(got.unwrap().access_token, "b");
    }

    #[test]
    fn a_failed_refresh_stores_nothing() {
        let s = store_with(Some(token("a", Some(30), Some("r"))));
        let got = run(
            &s,
            "p",
            Refresh::Within(MIN_LIFE),
            NOW,
            |_, _, _| Err("refused".into()),
            |_| Ok(true),
        );
        assert_eq!(got.unwrap_err(), "refused");
        assert_eq!(s.token("p").unwrap().unwrap().access_token, "a");
    }

    #[test]
    fn errors_name_the_next_command() {
        let s = store_with(None);
        let within = Refresh::Within(MIN_LIFE);
        let err = run(&s, "p", within, NOW, no_grant, |_| Ok(true)).unwrap_err();
        assert!(err.contains("run `sesame login p`"), "{err}");
        let err = run(&s, "p", within, NOW, no_grant, |_| Ok(false)).unwrap_err();
        assert!(err.contains("run `sesame setup p`"), "{err}");
        let s = store_with(Some(token("a", Some(30), None)));
        let err = run(&s, "p", within, NOW, no_grant, |_| Ok(true)).unwrap_err();
        assert!(err.contains("has no refresh token"), "{err}");
    }
}
