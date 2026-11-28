# Glossary

- **Provider**: a SaaS whose API sesame signs in to (`github`, `google`). One
  client, one token, one set of hosts the token may go to.
- **Service**: one API of a provider, reached with the provider's token
  (`gmail` of `google`). Its name is used like a provider's: the two share one
  namespace.
- **Built-in definition**: a provider's fields as sesame ships them
  (`src/providers/built_in.rs`).
- **Stored fields**: the person's own fields for a provider, kept in the
  store; for a built-in provider only those that differ from the built-in.
- **Handed definitions**: provider fields given in the environment instead of
  the store (with a handed token), read as if stored.
- **Definition in force**: the built-in definition, if any, with the stored
  (or handed) fields over it. The one place a definition is validated.
- **Target**: what a name on the command line means: a provider, or one of its
  services.
- **Config dir**: where the store keeps its files (`~/.config/sesame`, or
  `$SESAME_CONFIG_DIR`). The store's concern; nothing else reads it.
- **Local copy**: with the 1Password store, each machine's copy of the vault's
  sesame items, opcore's Copy (ADR 0006): sealed on disk beside the lock, the
  writes the vault has not taken yet beside it; read at any age, synced on
  demand.
