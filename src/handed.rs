//! A handed token: an access token given to `sesame api` and `sesame token`
//! in the environment by whoever holds the login (another machine's
//! `sesame token <service>`), instead of one from `sesame.db`. Nothing is
//! read from or written to the db, no client is needed and nothing is
//! refreshed: when the provider refuses the token, its holder hands a new one.
//!
//! This module is the one place the environment variables are named.
use crate::providers::{self, Fields, Target};
use crate::store::Token;
use serde_json::Value;
use std::collections::BTreeMap;

macro_rules! token_prefix {
    () => {
        "SESAME_TOKEN_"
    };
}
macro_rules! providers_var {
    () => {
        "SESAME_PROVIDERS"
    };
}

/// For `--help`: how to hand a token, and a definition sesame does not build in.
pub const HELP: &str = concat!(
    "Handed token: with `",
    token_prefix!(),
    "<NAME>` set, where <NAME> is the service's or provider's name in upper case \
     with `-` as `_` (`",
    token_prefix!(),
    "GMAIL`, `",
    token_prefix!(),
    "GOOGLE`), `api` and `token` use that access token instead of sesame.db: \
     nothing is read from or written to the db, and nothing is refreshed. The \
     service's variable is used before its provider's. A provider that is not \
     built in is defined by `",
    providers_var!(),
    "`, a JSON object of `sesame provider show` outputs by provider name \
     (`{\"acme\": <sesame provider show acme>}`)."
);

/// The environment variable holding the handed token of a provider or service.
pub fn var(name: &str) -> String {
    format!(
        "{}{}",
        token_prefix!(),
        name.to_uppercase().replace('-', "_")
    )
}

pub struct Handed {
    /// The variable it was handed in.
    pub var: String,
    pub token: Token,
}

/// `name`'s target and the token handed for it, when one is: the service's
/// variable, else its provider's. `None` when neither is set, and the db is used.
pub fn find(name: &str) -> Result<Option<(Target, Handed)>, String> {
    if !std::env::vars_os().any(|(k, _)| k.to_string_lossy().starts_with(token_prefix!())) {
        return Ok(None);
    }
    let all = providers::without_store(definitions()?)?;
    let t = match providers::find_in(all, name) {
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
    let Ok(text) = std::env::var(providers_var!()) else {
        return Ok(BTreeMap::new());
    };
    let err = |e: String| format!("{}: {e}", providers_var!());
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
