//! `sesame store migrate`: copies `sesame.db` into the 1Password vault the
//! environment selects (sesame#2), so switching the vault on keeps the logins.
//!
//! Never overwrites: what the vault already holds for a provider is either the
//! same (copied before: nothing to write) or a conflict, reported and left as
//! it is. One write for all provider fields and one per provider's login, each
//! only where something is missing, so a run cut short (the service account's
//! write budget, an error) goes on where it stopped when run again. Only when
//! everything is in the vault is `sesame.db` renamed, not deleted.
use super::vault::{TOKEN_VAR, VAULT_VAR, Vault};
use super::{Client, Token, sqlite};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn migrate() -> Result<(), String> {
    let Some(vault) = Vault::from_env()? else {
        return Err(format!(
            "`sesame store migrate` copies sesame.db into a 1Password vault, but {VAULT_VAR} is \
             not set: set it to the vault's name and {TOKEN_VAR} to the token of a service \
             account that can read and write that vault (README, \"Keeping logins in 1Password\")"
        ));
    };
    let path = sqlite::path();
    if !path.exists() {
        eprintln!(
            "There is no {}: nothing to copy into the 1Password vault `{}`.",
            path.display(),
            vault.name()
        );
        return Ok(());
    }
    let conflicts = {
        let db = sqlite::Sqlite::open()?;
        vault.locked(|| copy(&db, &vault))?
    };
    if !conflicts.is_empty() {
        return Err(format!(
            "kept {} as it is: the vault already holds something else for {}. For each, keep \
             either: sesame.db's, by archiving that in 1Password (`sesame.<provider>`, or the \
             provider's field in `sesame-providers`); or the vault's, by removing it from \
             sesame.db with `{VAULT_VAR}= sesame logout <provider>`, `{VAULT_VAR}= sesame client \
             <provider> --reset` or `{VAULT_VAR}= sesame provider rm <provider>`. Then run \
             `sesame store migrate` again.",
            path.display(),
            conflicts.join(", ")
        ));
    }
    let moved = retire(&path)?;
    let dir = path.parent().unwrap_or(Path::new("."));
    eprintln!(
        "Everything in sesame.db is in the 1Password vault `{v}`; moved sesame.db to {m}.\n\
         It still holds your clients and tokens in plaintext. Once sesame works from the vault, \
         delete it: rm {m}\n\
         To go back to sesame.db: unset {VAULT_VAR} and mv {m} {d}",
        v = vault.name(),
        m = moved.display(),
        d = dir.join("sesame.db").display(),
    );
    Ok(())
}

/// Copies what the vault lacks; the conflicts, as `what (provider)`.
fn copy(db: &sqlite::Sqlite, vault: &Vault) -> Result<Vec<String>, String> {
    let mut conflicts = Vec::new();
    let stopped = |done: usize, e: String| {
        format!(
            "{e}\nStopped after copying {done} item(s); sesame.db is kept. Run \
             `sesame store migrate` again to go on from here."
        )
    };
    let mut done = 0;

    // Provider fields: one write for all of them.
    let have = vault.provider_fields().map_err(|e| stopped(done, e))?;
    let mut add = BTreeMap::new();
    for (provider, fields) in db.provider_fields()? {
        match have.get(&provider) {
            _ if fields.is_empty() => {}
            None => {
                add.insert(provider, fields);
            }
            Some(h) if *h == fields => {}
            Some(_) => {
                eprintln!("Conflict: the vault holds other provider fields for `{provider}`.");
                conflicts.push(format!("the provider fields of `{provider}`"));
            }
        }
    }
    if !add.is_empty() {
        vault
            .save_many_provider_fields(&add)
            .map_err(|e| stopped(done, e))?;
        let names: Vec<&str> = add.keys().map(String::as_str).collect();
        eprintln!("Copied the provider fields of {}.", names.join(", "));
        done += 1;
    }

    // Clients and tokens: one write per provider.
    for provider in db.logins()? {
        let client = db.client(&provider)?.and_then(client_as_kept);
        let token = db.token(&provider)?.and_then(token_as_kept);
        let in_vault = (|| Ok((vault.client(&provider)?, vault.token(&provider)?)))()
            .map_err(|e: String| stopped(done, e))?;
        let (vc, vt) = in_vault;
        let mut clash = Vec::new();
        if client.is_some() && vc.is_some() && vc != client {
            clash.push("client");
        }
        if token.is_some() && vt.is_some() && vt != token {
            clash.push("token");
        }
        if !clash.is_empty() {
            let what = clash.join(" and ");
            eprintln!("Conflict: the vault holds another {what} for `{provider}`.");
            conflicts.push(format!("the {what} of `{provider}`"));
            continue;
        }
        let client = client.filter(|_| vc.is_none());
        let token = token.filter(|_| vt.is_none());
        if client.is_none() && token.is_none() {
            continue;
        }
        vault
            .save_login(&provider, client.as_ref(), token.as_ref())
            .map_err(|e| stopped(done, e))?;
        let what = match (&client, &token) {
            (Some(_), Some(_)) => "client and token",
            (Some(_), None) => "client",
            _ => "token",
        };
        eprintln!("Copied the `{provider}` {what}.");
        done += 1;
    }
    if done == 0 && conflicts.is_empty() {
        eprintln!(
            "The vault `{}` already holds all of sesame.db.",
            vault.name()
        );
    }
    Ok(conflicts)
}

/// The client as the vault keeps it: an empty value is no value.
fn client_as_kept(c: Client) -> Option<Client> {
    Some(Client {
        client_id: some(c.client_id)?,
        client_secret: c.client_secret.and_then(some),
    })
}

/// The token as the vault keeps it: an empty value is no value.
fn token_as_kept(t: Token) -> Option<Token> {
    Some(Token {
        access_token: some(t.access_token)?,
        refresh_token: t.refresh_token.and_then(some),
        expires_at: t.expires_at,
        scope: t.scope.and_then(some),
        resource_id: t.resource_id.and_then(some),
        resource_name: t.resource_name.and_then(some),
        account: t.account.and_then(some),
        pasted: t.pasted,
    })
}

fn some(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

/// Renames `sesame.db` to `sesame.db.migrated-<date>` (`-2`, … if taken).
fn retire(path: &Path) -> Result<PathBuf, String> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let base = format!("{}.migrated-{}", path.display(), date(secs));
    let to = (1..)
        .map(|n| match n {
            1 => PathBuf::from(&base),
            n => PathBuf::from(format!("{base}-{n}")),
        })
        .find(|p| !p.exists())
        .expect("a free name");
    std::fs::rename(path, &to).map_err(|e| format!("moving {}: {e}", path.display()))?;
    Ok(to)
}

/// `YYYY-MM-DD` (UTC) of Unix seconds.
fn date(secs: u64) -> String {
    // Howard Hinnant's civil_from_days.
    let z = (secs / 86400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_of_unix_seconds() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_795_132_800), "2026-11-20");
    }

    #[test]
    fn empty_values_are_no_values() {
        let c = Client {
            client_id: "id".into(),
            client_secret: Some(String::new()),
        };
        assert_eq!(client_as_kept(c).unwrap().client_secret, None);
        let c = Client {
            client_id: String::new(),
            client_secret: None,
        };
        assert!(client_as_kept(c).is_none());
    }
}
