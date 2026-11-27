# An encrypted local copy of the 1Password store

Status: reads before a write, and per item, superseded by ADR 0004.

sesame#4, on top of the vault store of ADR 0001. With the vault selected,
each machine keeps a copy of the whole store (clients, tokens, provider
fields) on its disk, sealed; reads come from it, and a call whose token is
still valid makes no `op` call at all.

## Context

With ADR 0001 alone every `sesame api` / `token` read two items, about a
second each against real 1Password (measured 2026-11-20: `op item get`
1.15 s, `item list` 0.9 s, `item create` 1.8 s, `item edit` 1.7 s), and the
account allows 1000 requests a day for everything. Agents calling in bursts
would wait seconds per call and spend the day's budget in an afternoon.

An access-token-only cache (the issue's first scope) cannot reach 0 calls:
resolving the provider reads the definitions from the vault too. Felix,
control session 2026-11-20: 「把整个 DB 缓存下来不就行了吗」, then
「就这样改 sesame#4」. He also wants no plaintext secret on disk
(「不想明文落在盘上」).

## Decision

- **The vault stays the truth; the copy is derived from it.** The copy is
  `sesame.db`'s schema (`clients`, `tokens`, `provider_fields`, the same
  migrations) plus `vault_items` (title → id, `version` at the last sync) and
  when it last synced. One vault item maps to its rows: `sesame.<provider>`
  to that provider's client and token rows, `sesame-providers` to the
  `provider_fields` rows. The vault layout is ADR 0001's, unchanged: the copy
  made the per-provider definitions item the issue sketches unnecessary, and
  keeping the layout keeps existing vaults working with no migration.
- **Reads** (`client`, `token`, `provider_fields`) come from the copy.
- **Writes** go through: under the machine's lock the item is read afresh
  (by id when the copy knows it), written (`create` / `edit` / archive, as in
  ADR 0001, only if what sesame keeps changed), then the copy is made what was
  written, version included, and saved.
- **A refreshed token is kept here first** (sesame#24): the provider's new
  token goes into the copy (sealed, saved) before the vault write. Should
  the write fail (network, the write budget, an expired service account
  token), the command still gets the token, a warning on stderr names the
  failed write, and the copy marks the provider in `unwritten_tokens`.
  While marked, the copy's token is what this machine uses and refreshes
  with: a sync does not replace it with the vault's, and the next write
  under the lock writes it, a sync's first step or any write of the
  provider's item (folded into it). For a provider that rotates its refresh
  token (Notion, Linear, HubSpot) the vault's old one is no longer honoured,
  so dropping the new one would lose the login. While unwritten it wins over
  the vault: a login or logout made meanwhile on another machine is
  overwritten by it at that write (a logout elsewhere is undone; the token
  is valid). Other writes (`client`, `login`, `provider set`) still fail as
  they did: the person sees the error and nothing issued is lost.
- **Sync**: one `op item list --tags sesame`, then a read of each item whose
  version is not the copy's; an item the copy holds that the list lacks is
  asked for by id before its rows go (1Password was said to list new items
  late; on real op 2.42 a new item was listed at once, but the check is one
  read in a rare case). It runs:
  - before a refresh (`valid_token`, under the lock, asks the store for
    `latest_token`), with the provider's item read whatever its version: a token another machine refreshed is
    used as is; for a token the provider refused (`Refresh::Now`), any other
    token the vault now holds is tried first. So A's refresh, `client` and
    `provider set` reach B at B's next refresh, at the cost of the list;
  - when the copy is older than `COPY_LIFE` (1 h), so a provider whose token
    never expires (GitHub's, a pasted one) still sees another machine's
    change within the hour;
  - for `sesame providers` (a status listing should be current: it opens
    the store with `Store::open_current`);
  - when there is no copy that opens: the first run, another token, damage.
- **Sealed at rest.** The copy lives in memory (`rusqlite` `serialize`) and
  reaches disk only as `<config_dir>/1password-copy`: XChaCha20-Poly1305 with
  a random nonce, the key HKDF-SHA256 of `OP_SERVICE_ACCOUNT_TOKEN` with the
  vault's name as context (opcore's `Sealer`). Whoever lacks the token
  reads nothing; whoever has it can read the vault anyway, so holding the
  long-lived secrets locally widens nothing. A copy that does not open
  (another token, another vault, a changed byte) is dropped silently and
  rebuilt by a sync. It is written to a file beside it and renamed over it,
  under the lock, so a reader never sees half of one.
- **The lock** (`sesame.lock`, ADR 0001) now also guards the copy: taking it
  reloads the copy from disk, so a write by another process here is not
  overwritten. Callers see neither the sync nor the copy: the store names what they
  want (`latest_token`, `open_current`) and syncs behind it (sesame#11).
- **`locked` serializes, nothing more** (sesame#11): writes go through to
  1Password, which has no transaction, so an error midway undoes none of
  them; `sesame.db` keeps the same rule (it commits what was written), so no
  caller comes to rely on a rollback only one store gives.

## Considered options

- **SQLCipher.** Rejected: `rusqlite`'s `bundled-sqlcipher` builds SQLCipher
  against a crypto library (OpenSSL or CommonCrypto), a second C dependency
  and build path for a database of a few kilobytes. The whole copy is
  rewritten on each change either way; serializing it in memory and sealing
  it with a pure-Rust AEAD keeps one build and makes the file atomic.
- **An access-token-only cache.** Rejected: still one read per call for the
  definitions (above).
- **Reading through to the vault on a miss, per item.** Rejected: a token
  the copy says is valid is used without asking; asking would cost the
  call the copy exists to save. The bound on staleness is the token's own
  life (and `COPY_LIFE`).
- **Syncing on every call** (only the list). Rejected: one request per call
  still burns the daily budget the copy is meant to keep.

## Consequences

- A change on another machine reaches this one at its next refresh (about
  an hour for Google, sooner for shorter tokens), at its next `sesame
  providers`, or within `COPY_LIFE`. Until then this machine uses what it
  has; a token revoked elsewhere is learned of from the provider's 401, which
  syncs and refreshes.
- Tested (`one_password_local_copy` in tests/e2e.rs): 0 calls for a valid
  token, provider resolution included; B picks up A's refreshed token without
  refreshing and A's `client` / `provider set` at its next refresh; no token,
  refresh token or client secret in plaintext under either config dir; a
  copy under another service account token, or damaged, is rebuilt.
  `a_refreshed_token_the_vault_refuses_is_kept`: with writes refused, a
  rotating provider's refreshed token is used, refreshed again from, and
  written once writes go through.
- Measured against real 1Password: see the README's budget and the comment on
  sesame#4.
