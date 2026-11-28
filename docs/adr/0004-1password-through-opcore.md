# 4. The vault store reaches 1Password through opcore, not `op`

Supersedes ADR 0001's "read and written by `op`" and ADR 0002's reads before
a write; the vault layout and the local copy stay.

Status: its copy, sync and writes superseded by ADR 0006.

## Context

Felix, 2026-11-27 (control session): one package for optokens and sesame, on
the 1Password SDK's core WebAssembly (github.com/sunfmin/opcore), spending
as few reads and writes as it can, items as the SDK's structs
(「应该直接用结构体，不应该用 Json」). Through `op`, a sync read each moved
item alone, and every write read its item first.

## Decision

- **`Op` is opcore's Client** (in `src/store/vault.rs` then), signed in on a
  process's first request only: a command the copy answers never signs in.
  No `op`, no child; the token is taken out of the environment.
- **Items are opcore's structs**, laid out as ADR 0001 says: in `op` a
  field's title is its `label`, `Text` / `Concealed` its `STRING` /
  `CONCEALED`. Either writer's item reads the same.
- **Sync**: one list, one `get_all` of every item whose `updatedAt` is not
  the copy's, the forced one, and the unlisted ones the copy has.
- **Writes**, under the lock: one list; a `get_all` only when the item's
  `updatedAt` is not the copy's, else the copy's item (kept whole) is
  written over. What the write answers is kept, never read back.
- **The seal is opcore's `Sealer`**, sesame's format byte for byte, same
  context: a copy sealed before opens after, `unwritten_tokens` intact
  (`tests/fixtures/1password-copy-55d7766`).
- **Tests** run the binary on a stand-in Core (`src/store/vault/stand_in.rs`,
  debug builds only); the store's own use `Memory`.

## Consequences

Measured 2026-11-27 on the vault `sesame`, release build, `op
service-account ratelimit` before and after (`op`-based sesame 0.1.28 beside):

| Command | opcore | `op` |
|---|---|---|
| a valid token (`sesame api figma /v1/me`) | 0.15 s, 0 requests | 0.38 s, 0 |
| a forced refresh (`token hubspot --min-life 99999`) | 6.7 s, 3 reads, 1 write | 4.1 s, 0 reads, 1 write |
| `sesame providers`, copy current | 4.3 s, 1 read | 0.9 s, 0 reads |
| `sesame providers`, no copy | 5.1 s, 1 read | 8.6 s, 7 reads |

The sign-in each syncing or writing process pays (3.2 s and one read, its
`VaultsList`) outweighs one batch read's savings on a small vault. The `op` stand-in's
truefit contract went with `op`; the stand-in Core has none yet.

Undo: put an `op` implementation back behind the `Op` seam.
