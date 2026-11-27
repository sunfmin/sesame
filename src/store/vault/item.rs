//! What sesame keeps in a 1Password item, and how it lies there: each value a
//! top-level field titled as below (`op read
//! op://<vault>/sesame.<provider>/refresh_token`), secrets concealed, an empty
//! value no value. A provider's item holds its client and token; the
//! definitions item one text field per provider, its fields as JSON. Fields
//! sesame does not keep (another's, in a section) and the notes are not read.
//! Items are opcore's (the SDK's model; `op` shows a field's title as its
//! `label`, `Text` as `STRING`, `Concealed` as `CONCEALED`). Pure: the vault
//! store reads and writes items, this says what is in them.
use super::super::{Client, Token};
use crate::providers::Fields;
use opcore::{FieldType, Item, ItemField};
use serde_json::Value;
use std::collections::BTreeMap;

const CLIENT_ID: &str = "client_id";
const CLIENT_SECRET: &str = "client_secret";
pub const CLIENT_FIELDS: [&str; 2] = [CLIENT_ID, CLIENT_SECRET];
const EXPIRES_AT: &str = "expires_at";
const ACCESS_TOKEN: &str = "access_token";
const REFRESH_TOKEN: &str = "refresh_token";
const SCOPE: &str = "scope";
const RESOURCE_ID: &str = "resource_id";
const RESOURCE_NAME: &str = "resource_name";
const ACCOUNT: &str = "account";
const PASTED: &str = "pasted";
pub const TOKEN_FIELDS: [&str; 8] = [
    ACCESS_TOKEN,
    REFRESH_TOKEN,
    EXPIRES_AT,
    SCOPE,
    RESOURCE_ID,
    RESOURCE_NAME,
    ACCOUNT,
    PASTED,
];

/// What sesame keeps in an item: field title → (concealed, value).
pub type Kept = BTreeMap<String, (bool, String)>;

/// Whether a field of a provider's item is sesame's: its client's or token's.
pub fn is_provider_field(label: &str) -> bool {
    CLIENT_FIELDS.contains(&label) || TOKEN_FIELDS.contains(&label)
}

/// The client kept, if it has an id.
pub fn client_of(k: &Kept) -> Option<Client> {
    value(k, CLIENT_ID).map(|client_id| Client {
        client_id,
        client_secret: value(k, CLIENT_SECRET),
    })
}

/// The token kept, if it has an access token. Refused: an expiry that is no
/// number, saying which field.
pub fn token_of(k: &Kept) -> Result<Option<Token>, String> {
    let Some(access_token) = value(k, ACCESS_TOKEN) else {
        return Ok(None);
    };
    let expires_at = value(k, EXPIRES_AT)
        .map(|t| t.parse().map_err(|e| format!("{EXPIRES_AT}: `{t}`: {e}")))
        .transpose()?;
    Ok(Some(Token {
        access_token,
        refresh_token: value(k, REFRESH_TOKEN),
        expires_at,
        scope: value(k, SCOPE),
        resource_id: value(k, RESOURCE_ID),
        resource_name: value(k, RESOURCE_NAME),
        account: value(k, ACCOUNT),
        pasted: value(k, PASTED).is_some_and(|p| p == "true"),
    }))
}

/// Every provider's fields kept in the definitions item. Refused: a value
/// that is no JSON object, saying whose.
pub fn definitions(k: &Kept) -> Result<BTreeMap<String, Fields>, String> {
    k.iter()
        .map(|(provider, (_, v))| {
            let fields = serde_json::from_str(v).map_err(|e| format!("{provider}: {e}"))?;
            Ok((provider.clone(), fields))
        })
        .collect()
}

/// Replaces the client kept with `c`.
pub fn put_client(k: &mut Kept, c: &Client) {
    k.retain(|l, _| !CLIENT_FIELDS.contains(&l.as_str()));
    put(k, CLIENT_ID, false, Some(c.client_id.clone()));
    put(k, CLIENT_SECRET, true, c.client_secret.clone());
}

/// Replaces the token kept with `t`.
pub fn put_token(k: &mut Kept, t: &Token) {
    k.retain(|l, _| !TOKEN_FIELDS.contains(&l.as_str()));
    put(k, ACCESS_TOKEN, true, Some(t.access_token.clone()));
    put(k, REFRESH_TOKEN, true, t.refresh_token.clone());
    put(k, EXPIRES_AT, false, t.expires_at.map(|e| e.to_string()));
    put(k, SCOPE, false, t.scope.clone());
    put(k, RESOURCE_ID, false, t.resource_id.clone());
    put(k, RESOURCE_NAME, false, t.resource_name.clone());
    put(k, ACCOUNT, false, t.account.clone());
    put(k, PASTED, false, t.pasted.then(|| "true".into()));
}

/// Replaces `provider`'s fields kept in the definitions item; none removes
/// them.
pub fn put_definition(k: &mut Kept, provider: &str, fields: &Fields) {
    k.remove(provider);
    let value = (!fields.is_empty()).then(|| Value::Object(fields.clone()).to_string());
    put(k, provider, false, value);
}

/// Keeps `value` under `label`: an empty value is no value.
fn put(k: &mut Kept, label: &str, concealed: bool, value: Option<String>) {
    if let Some(v) = value.filter(|v| !v.is_empty()) {
        k.insert(label.into(), (concealed, v));
    }
}

fn value(k: &Kept, label: &str) -> Option<String> {
    k.get(label).map(|(_, v)| v.clone())
}

/// Whether an item's field is one sesame keeps: top level (no section),
/// titled as `ours` says.
pub fn is_ours(f: &ItemField, ours: impl Fn(&str) -> bool) -> bool {
    let in_section = f.section_id.as_deref().is_some_and(|s| !s.is_empty());
    !in_section && !f.title.is_empty() && ours(&f.title)
}

/// What sesame keeps in `item`, of the fields `ours` names.
pub fn kept(item: &Item, ours: impl Fn(&str) -> bool) -> Kept {
    let mut k = Kept::new();
    for f in item.fields.iter().filter(|f| is_ours(f, &ours)) {
        let concealed = f.field_type == FieldType::Concealed;
        put(&mut k, &f.title, concealed, Some(f.value.clone()));
    }
    k
}

/// The item's fields for `k`; each field's id is its title, so
/// `op://<vault>/<title>/<label>` reads it.
pub fn fields(k: &Kept) -> Vec<ItemField> {
    k.iter()
        .map(|(label, (concealed, v))| ItemField {
            id: label.clone(),
            title: label.clone(),
            field_type: match concealed {
                true => FieldType::Concealed,
                false => FieldType::Text,
            },
            value: v.clone(),
            ..Default::default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(title: &str, kind: FieldType, value: &str, section: Option<&str>) -> ItemField {
        ItemField {
            id: title.into(),
            title: title.into(),
            section_id: section.map(String::from),
            field_type: kind,
            value: value.into(),
            ..Default::default()
        }
    }

    #[test]
    fn kept_reads_only_sesames_top_level_fields() {
        let item = Item {
            notes: "n".into(),
            fields: vec![
                field("access_token", FieldType::Concealed, "a", Some("")),
                field("access_token", FieldType::Text, "s", Some("other")),
                field("mine", FieldType::Text, "m", None),
                field("scope", FieldType::Text, "", None),
            ],
            ..Default::default()
        };
        let k = kept(&item, is_provider_field);
        assert_eq!(
            k,
            BTreeMap::from([("access_token".into(), (true, "a".into()))])
        );
        // And the fields keep the titles as ids, top level.
        let f = &fields(&k)[0];
        assert_eq!(
            (f.id.as_str(), f.title.as_str()),
            ("access_token", "access_token")
        );
        assert_eq!(
            (f.field_type, f.section_id.as_deref()),
            (FieldType::Concealed, None)
        );
    }
}
