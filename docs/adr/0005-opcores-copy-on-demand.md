# 5. The vault store is opcore's Copy, synced on demand

Supersedes ADR 0002's sync rules and its kept token, and ADR 0004's copy,
sync and writes; the layout of ADR 0001 and the lock stay.

## Context

Felix, 2026-11-29: sesame should use opcore whole, as optokens does. Its
own Copy (`sesame.db`'s tables, sealed) synced once an hour old. The
account's 1000 requests a day count every read and write (opcore's
decision record 7): a sync nobody asked for spends them. Two Copies, two
formats, two sync policies: two homes for one vault access.

## Decision

- **The Copy is opcore's**, `Syncs::OnDemand`, at `<config_dir>/vault-copy`.
  Reads answer from it with no network, at any age.
- **It syncs** only before a refresh (`latest_token`), for `sesame
  providers`, with no Copy, before a create (an item another machine made
  is edited, not made twice), and when a provider refuses the token it
  holds: one sync, one retry with the vault's if it holds another. That
  last replaces the hour's reason.
- **Each write is staged and pushed in the same process**: a provider that
  rotates its refresh token (Notion, Linear, HubSpot) stops honouring the
  vault's. One 1Password cannot take now waits in opcore's pending writes:
  a refresh still answers with a `warning:` line, this machine uses that
  token, and the next process that reaches 1Password pushes it first.
  `client`, `login`, `provider set` and `logout` fail saying it waits.
- **An edit refused outright is dropped**, as opcore drops it, with a
  warning; one refused because its item was archived elsewhere is made anew.
- **The lock** reopens the Copy when another process changed its files.
- **The old Copy is not opened**: a token it marked unwritten is written
  to the vault first, then the file goes.

## Considered

- `Syncs::Life(Duration::MAX)`, writing through: an edit then overwrites
  the fields with the Copy's, losing another machine's change; a push
  merges it on the item as 1Password holds it then.
- Keeping `unwritten_tokens` beside the pending writes: two homes.

## Consequences

- Another machine's change arrives at a refresh, `sesame providers` or a
  401, never because time passed. A write costs a list and a read too.
- What opcore lacks, so sesame does too: why a push waits is not reported;
  a failed push is retried on factum's backoff (1 s, doubling), so a
  process within it leaves the write waiting; every staged write warns
  that it is staged, even when pushed at once.
- Tested: `store::vault` (no Core call from a Copy synced in 1970; the old
  Copy's token, `tests/fixtures/1password-copy-55d7766`), and in
  tests/e2e.rs `a_refreshed_token_is_written_at_once_or_waits` and
  `a_refused_token_syncs_once_and_retries_with_the_vaults`.

Undo: give the Copy a Life again.
