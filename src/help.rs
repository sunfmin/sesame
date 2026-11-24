//! The manual: every command's help, written as Markdown on the type that is
//! its one home, the topics that belong to no command, and the names they
//! place by `{const:…}`. `sesame --help` answers its index, `sesame <command>
//! --help` a command, `sesame help <topic>` a topic, `sesame help all` all of
//! it.
use agent_help::{Help, Topic};
use clap::CommandFactory;

use crate::Cli;

/// Who runs a command, the group the index lists it under.
pub mod groups {
    pub const AGENT: &str = "Run by the agent";
    pub const PERSON: &str = "Run by the person, in their own terminal";
}

#[doc = include_str!("help/signing-in.md")]
#[derive(Topic)]
#[topic(name = "signing-in")]
pub struct SigningIn;

#[doc = include_str!("help/handed-token.md")]
#[derive(Topic)]
#[topic(name = "handed-token")]
pub struct HandedToken;

/// The manual, assembled from the parser's command tree (the provider
/// fields' flags made from the field table among it), the topics and the
/// names of the environment variables.
pub fn manual() -> Help {
    Help::new(Cli::command())
        .topic::<SigningIn>()
        .topic::<HandedToken>()
        .constant("TOKEN_PREFIX", crate::source::TOKEN_PREFIX)
        .constant("PROVIDERS_VAR", crate::source::PROVIDERS_VAR)
        .constant("VAULT_VAR", crate::store::VAULT_VAR)
        .constant("MIN_LIFE", crate::refresh::MIN_LIFE)
}

/// What `help [<topic>]` answers: the index, a topic, or `all`; an unknown
/// topic is a usage error naming the topics.
pub fn answer(topic: Option<&str>) -> Result<String, clap::Error> {
    let manual = manual();
    match topic {
        None => Ok(manual.index().expect("checked by the_manual_is_whole")),
        Some(topic) => manual
            .topic_help(topic)
            .map_err(|e| clap::Error::raw(clap::error::ErrorKind::InvalidValue, format!("{e}\n"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::fields::FIELDS;

    #[test]
    fn the_manual_is_whole() {
        agent_help::check(&manual()).unwrap();
    }

    #[test]
    fn no_help_names_what_its_reader_cannot_open() {
        let all = manual().manual().unwrap();
        for word in ["{const:", "ADR", "docs/", "src/"] {
            assert!(!all.contains(word), "the manual holds {word:?}");
        }
    }

    /// The field table is the one home of each field's help: `provider add`
    /// and `set` list every field of it, flag and type.
    #[test]
    fn provider_add_and_set_list_every_field() {
        for command in ["add", "set"] {
            let help = manual().command_help(&["provider", command]).unwrap();
            for f in FIELDS {
                let line = help
                    .lines()
                    .find(|l| l.starts_with(&format!("- `--{} <", f.flag)))
                    .unwrap_or_else(|| panic!("`provider {command}` misses --{}", f.flag));
                assert!(line.contains(f.help), "{line}");
                assert!(line.contains(&f.kind.describe()), "{line}");
            }
        }
    }
}
