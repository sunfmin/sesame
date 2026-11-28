# sesame

Sign in to SaaS APIs that have no CLI of their own, from the terminal, and call
their REST APIs with the stored token.

```sh
sesame providers                             # where you stand with each provider
sesame setup google                          # first time: how to register the OAuth app
sesame client google --client-id <id>        # once: the OAuth app (secret is prompted)
sesame login drive                           # opens Google's OAuth page
sesame api drive /files                      # refreshed when it expires
sesame login github                          # no setup: built-in client, device flow
sesame api github /graphql -d '{"query":"{ viewer { login } }"}'
curl -H "Authorization: Bearer $(sesame token jira)" ...
sesame logout jira                           # forgets the local token only
```

The manual is the binary's help: `sesame --help` first, `sesame <command>
--help` for one command, `sesame help all` for all of it.

## What it keeps where

- **Providers** (one OAuth login and token each) and their **services** (one
  API each): the built-ins in `src/providers/built_in.rs`; every field a
  provider has, its flag and its help, in the field table,
  `src/providers/fields.rs`. Yours are stored with `sesame provider add`/`set`;
  there is no config file.
- **Clients, tokens and your provider fields**: in plaintext in
  `~/.config/sesame/sesame.db` (`$SESAME_CONFIG_DIR` when set), 0600 in a 0700
  directory, so keep it out of dotfiles and synced folders. Or, opted in by the
  environment, in a 1Password vault: `sesame help 1password-vault`. The
  decisions behind the vault store are ADRs 0001, 0002 and 0004 in
  `docs/adr/`.
- **The manual**: written where each fact lives, assembled by
  [agent-help](https://github.com/sunfmin/agent-cli): a command's doc comment
  on its clap variant in `src/main.rs`, a topic in `src/help/<topic>.md`
  registered in `src/help.rs`. `skills/sesame/SKILL.md` sends an agent to
  `sesame --help`.

## Development

`./gate.sh` runs fmt, docfit, clippy, the tests and the release dry run. The
tests reach 1Password only through a stand-in Core
(`src/store/vault/stand_in.rs`); `tests/e2e.rs` runs the whole flow against a
fake provider on 127.0.0.1.
