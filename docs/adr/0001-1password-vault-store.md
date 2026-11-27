# A 1Password vault as an opt-in store, selected by the environment

Status: the `op` part superseded by ADR 0004 (opcore).

sesame#1. With `SESAME_1PASSWORD_VAULT=<vault>` set, sesame keeps everything
`sesame.db` holds (clients, tokens, the person's provider fields) in a
1Password vault, read and written by `op` as a service account
(`OP_SERVICE_ACCOUNT_TOKEN`). Unset, `sesame.db` as before.

## Context

Felix, 2026-11-20 (control session): 「不想明文落在盘上，也想其他机器也能直接用」,
then 「存在 One Password，做成可选的」. `sesame.db` is plaintext on one disk.
1Password has SDKs for Go, JS and Python but not Rust, so the `op` CLI is the
way in. The account's budget is small: 1000 reads and 100 writes an hour per
token, 1000 requests a day for the whole account (shared with mytokens' vault
sync), ~2 s per `op` call (mytokens ADR 0022, measured).

## Decision

- **The switch is the environment**, not a config file or a flag. A machine
  opts in by what it is given, the same way it gets the service account
  token (a `mytokens` profile carries both); a config file would be a second
  home for the choice and would itself have to be on the disk this is meant to
  keep clean. Named but unusable (no token, no `op`, a vault the account cannot
  read) is an error naming what is missing; never a silent `sesame.db`.
- **One `Store`, two backends** (`src/store.rs`): `sqlite` unchanged, `vault`
  new. Callers do not know which.
- **Items.** `sesame.<provider>`: the provider's client and token, so two
  machines writing different providers never overwrite each other. Each value
  is a top-level field whose id is its label (`op read
  op://<vault>/sesame.<p>/refresh_token`); `client_secret`, `access_token`,
  `refresh_token` are concealed. `sesame-providers`: every provider's fields,
  one text field per provider holding JSON. All Secure Notes tagged `sesame`.
- **Why the definitions are one item**: resolving any name (a service shares a
  namespace with providers, and a person may add services to any provider)
  needs every provider's fields. One item makes that one read; an item per
  provider would make every `sesame api` cost a list plus a read per provider.
  Definitions change only by a person's command, so a lost update between two
  machines editing definitions at the same moment is accepted.
- **Budget.** An item is read at most once per process; taking the local lock
  forgets what was read, so a read-then-write sees the other process's write.
  A write happens only when what sesame keeps in the item changed, and a write
  is one `create`/`edit`/`delete` with the whole item. `sesame api` / `token`
  with no refresh: two reads, no write (tested, counted against the fake `op`).
  `sesame providers` lists the vault once and skips reading what is not there.
  (Superseded by ADR 0002: reads come from a local copy, 0 requests with no
  refresh.)
- **Talking to `op`.** Templates go on stdin through a pipe with no
  `--template`; an edit carries `tags` (sesame's own added to the item's) and
  keeps the fields, sections and tags someone else put on the item. (Written
  as "without them op wipes them"; sesame#22 found op 2.42.0 keeps an item's
  tags on an edit without `tags`: only that edit's printed answer shows none.
  Tags come back sorted.) An archived item still answers `op item get <id>`
  (`"state": "ARCHIVED"`, and an edit of it fails) though not its title or a
  list: sesame reads it as gone. The token is
  taken out of sesame's own environment at start and given only to `op`
  children. Item left with nothing: archived (`--archive`), recoverable.
- **Refresh.** A lock file in the config dir (`sesame.lock`, empty) serializes
  read–refresh–write on one machine. Across machines there is no lock: a
  provider whose refresh token rotates is refreshed by one machine, the others
  get handed tokens (`SESAME_TOKEN_<NAME>`), as before. The README says so.
- **Not a mytokens vault**: mytokens' two-way sync adopts and rewrites items
  it did not make; the README says to use a vault it does not sync.

## Considered options

- **A config file or a `sesame store` command.** Rejected: see above.
- **Encrypting `sesame.db`.** Rejected: does not share logins between machines.
- **Everything in one item.** Rejected: two machines refreshing different
  providers would overwrite each other.
- **Provider fields in each provider's item.** Rejected: every command would
  read every item (above).

## Consequences

- Tested against a fake `op` in `tests/e2e.rs`: every command, no secret under the
  config dir or in any `op` argv, call and write counts, the three errors.
- **Not checked against real 1Password** when this was written: the machine
  had no `op` and no scratch vault profile (`mytokens env sesame-scratch`).
  Checked in sesame#4 against `sesame-scratch` with op 2.42.0: `op item get
  <title>` found an item 1.15 s after `create`, `op item list` listed it at
  once (with its `version`), and an edit carrying the fields op printed was
  accepted (version 1 → 2, tags kept). Reads and writes of the store go
  through a local copy since (ADR 0002).
