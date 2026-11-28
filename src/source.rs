//! Where a command's token comes from, decided once for `sesame api` and
//! `sesame token`: handed in the environment by whoever holds the login
//! (another machine's `sesame token <service>`), or stored. A handed token
//! needs no db, no client and is never refreshed: when the provider refuses
//! it, its holder hands a new one. A stored one is refreshed as `refresh`
//! decides, and once more when the provider refuses it.
//!
//! This module is the one place the environment variables are named.
use crate::providers::{self, Fields, Target};
use crate::refresh::{self, Refresh};
use crate::store::{Store, Token};
use serde_json::Value;
use std::collections::BTreeMap;

/// Where the token of a command comes from.
pub enum Source {
    Handed(Handed),
    /// The store, opened once for the command and its refreshes.
    Stored(Store),
}

/// What to do when the provider refused the token.
#[derive(Debug, PartialEq)]
pub enum Refused {
    /// Call again with this token.
    Retry(Token),
    /// Nothing to call again with: tell the person this.
    Tell(String),
}

/// `name`'s target and where its token comes from: the environment when a
/// token is handed for it, else the store `open` opens.
pub fn find(
    name: &str,
    open: impl FnOnce() -> Result<Store, String>,
) -> Result<(Target, Source), String> {
    if let Some((t, h)) = handed(name)? {
        return Ok((t, Source::Handed(h)));
    }
    let store = open()?;
    Ok((providers::find(&store, name)?, Source::Stored(store)))
}

impl Source {
    /// The token to call `t` with: a handed one as it is, a stored one
    /// refreshed first where it expires within `min_life` seconds.
    pub fn token(&self, t: &Target, min_life: u64) -> Result<Token, String> {
        match self {
            Source::Handed(h) => Ok(h.token.clone()),
            Source::Stored(s) => {
                refresh::valid_token(s, &t.provider, &t.p, Refresh::Within(min_life))
            }
        }
    }

    /// What to do now that the provider refused `token`, the one `token` gave.
    pub fn refused(&self, t: &Target, token: &Token) -> Result<Refused, String> {
        self.refused_with(t, token, |s| {
            refresh::valid_token(s, &t.provider, &t.p, Refresh::Now)
        })
    }

    /// `refused`, with the refresh of a stored token given.
    fn refused_with(
        &self,
        t: &Target,
        token: &Token,
        refresh: impl FnOnce(&Store) -> Result<Token, String>,
    ) -> Result<Refused, String> {
        match self {
            Source::Handed(h) => Ok(Refused::Tell(format!(
                "sesame: the token handed in `{}` was refused or has expired; its holder must hand a new one",
                h.var
            ))),
            Source::Stored(s) if token.refresh_token.is_some() => Ok(Refused::Retry(refresh(s)?)),
            // Never refreshed, so caught up here: another machine may have
            // logged in again since this one's copy of the token.
            Source::Stored(s) => match s.locked(|s| s.latest_token(&t.provider))? {
                Some(other) if other.access_token != token.access_token => {
                    Ok(Refused::Retry(other))
                }
                _ => Ok(Refused::Tell(format!(
                    "sesame: the `{p}` token was refused and has no refresh token; run `sesame login {p}`",
                    p = t.provider
                ))),
            },
        }
    }
}

/// The start of a handed token's variable; the rest is the service's or
/// provider's name, in upper case with `-` as `_`.
pub const TOKEN_PREFIX: &str = "SESAME_TOKEN_";
/// The variable holding the handed definitions of providers not built in.
pub const PROVIDERS_VAR: &str = "SESAME_PROVIDERS";

/// The environment variable holding the handed token of a provider or service.
pub fn var(name: &str) -> String {
    format!("{TOKEN_PREFIX}{}", name.to_uppercase().replace('-', "_"))
}

pub struct Handed {
    /// The variable it was handed in.
    pub var: String,
    pub token: Token,
}

/// `name`'s target and the token handed for it, when one is: the service's
/// variable, else its provider's. `None` when neither is set, and the db is used.
fn handed(name: &str) -> Result<Option<(Target, Handed)>, String> {
    if !std::env::vars_os().any(|(k, _)| k.to_string_lossy().starts_with(TOKEN_PREFIX)) {
        return Ok(None);
    }
    let t = match providers::find_handed(definitions()?, name) {
        Ok(t) => t,
        Err(e) if std::env::var_os(var(name)).is_some() => return Err(e),
        // Perhaps a provider of the db's, not handed.
        Err(_) => return Ok(None),
    };
    let names = t.service.iter().chain([&t.provider]);
    let Some((var, access)) = names
        .map(|n| var(n))
        .find_map(|v| std::env::var(&v).ok().map(|a| (v, a)))
    else {
        return Ok(None);
    };
    let access_token = access.trim().to_string();
    if access_token.is_empty() {
        return Err(format!("`{var}` is set but empty: hand a token in it"));
    }
    let token = Token {
        access_token,
        refresh_token: None,
        expires_at: None,
        scope: None,
        resource_id: None,
        resource_name: None,
        pasted: false,
        account: None,
    };
    Ok(Some((t, Handed { var, token })))
}

/// The definitions handed in `SESAME_PROVIDERS`, as fields by provider.
fn definitions() -> Result<BTreeMap<String, Fields>, String> {
    let Ok(text) = std::env::var(PROVIDERS_VAR) else {
        return Ok(BTreeMap::new());
    };
    let err = |e: String| format!("{PROVIDERS_VAR}: {e}");
    let all: BTreeMap<String, Fields> =
        serde_json::from_str(&text).map_err(|e| err(e.to_string()))?;
    all.into_iter()
        .map(|(name, shown)| {
            let fields = shown
                .into_iter()
                .map(|(k, v)| match v {
                    Value::Object(mut m) if m.contains_key("value") => {
                        Ok((k, m.remove("value").unwrap_or_default()))
                    }
                    _ => Err(err(format!(
                        "`{name}`.`{k}`: not `{{\"value\": …}}` as `sesame provider show` prints it"
                    ))),
                })
                .collect::<Result<Fields, String>>()?;
            Ok((name, fields))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(access: &str, refresh: Option<&str>) -> Token {
        Token {
            access_token: access.into(),
            refresh_token: refresh.map(String::from),
            expires_at: None,
            scope: None,
            resource_id: None,
            resource_name: None,
            pasted: false,
            account: None,
        }
    }

    fn stored(t: &Token) -> (Target, Source) {
        let s = Store::in_memory().unwrap();
        s.save_token("github", t).unwrap();
        (providers::find(&s, "github").unwrap(), Source::Stored(s))
    }

    fn no_refresh(_: &Store) -> Result<Token, String> {
        panic!("refreshed")
    }

    #[test]
    fn a_refused_handed_token_is_not_refreshed_and_its_holder_is_named() {
        let s = Store::in_memory().unwrap();
        let t = providers::find(&s, "github").unwrap();
        let src = Source::Handed(Handed {
            var: var("github"),
            token: token("h", None),
        });
        assert_eq!(src.token(&t, refresh::MIN_LIFE).unwrap(), token("h", None));
        let got = src.refused_with(&t, &token("h", None), no_refresh).unwrap();
        assert_eq!(
            got,
            Refused::Tell(
                "sesame: the token handed in `SESAME_TOKEN_GITHUB` was refused or has expired; its holder must hand a new one"
                    .into()
            )
        );
    }

    #[test]
    fn a_refused_stored_token_is_refreshed_once() {
        let old = token("a", Some("r"));
        let (t, src) = stored(&old);
        let got = src
            .refused_with(&t, &old, |s| {
                assert_eq!(s.token("github").unwrap(), Some(old.clone()));
                Ok(token("b", Some("r")))
            })
            .unwrap();
        assert_eq!(got, Refused::Retry(token("b", Some("r"))));
    }

    #[test]
    fn a_failed_refresh_of_a_refused_token_is_the_error() {
        let old = token("a", Some("r"));
        let (t, src) = stored(&old);
        let got = src.refused_with(&t, &old, |_| Err("refresh refused".into()));
        assert_eq!(got.unwrap_err(), "refresh refused");
    }

    #[test]
    fn a_refused_stored_token_without_a_refresh_token_names_the_login() {
        let old = token("a", None);
        let (t, src) = stored(&old);
        let got = src.refused_with(&t, &old, no_refresh).unwrap();
        assert_eq!(
            got,
            Refused::Tell(
                "sesame: the `github` token was refused and has no refresh token; run `sesame login github`"
                    .into()
            )
        );
    }

    #[test]
    fn a_refused_token_without_a_refresh_token_is_retried_with_another_the_store_holds_now() {
        let (t, src) = stored(&token("new", None));
        let got = src.refused_with(&t, &token("old", None), no_refresh);
        assert_eq!(got.unwrap(), Refused::Retry(token("new", None)));
    }

    #[test]
    fn nothing_handed_opens_the_store_once() {
        let mut opened = 0;
        let (t, src) = find("github", || {
            opened += 1;
            Store::in_memory()
        })
        .unwrap();
        assert_eq!((t.provider.as_str(), opened), ("github", 1));
        assert!(matches!(src, Source::Stored(_)));
    }
}
