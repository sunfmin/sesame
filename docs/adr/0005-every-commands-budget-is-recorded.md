# 5. Every command's Budget is recorded, and measured on sesame-scratch

## Context

Felix, 2026-11-29: like optokens (its `docs/budget.md`, its decision record 18,
`scripts/e2e.sh`), sesame should record what each command spends of
1Password's budget and check it against the real vault. The account's
1000 requests a day count every read and write (opcore's decision record 7,
measured 2026-11-28). Until now the only numbers were ADR 0004's one-off
table.

## Decision

- Every command's scenario on the stand-in Core asserts its Core calls and the reads, writes and account requests they spend, and `docs/budget.md` is their table: `tests/budget.rs` generates it, fails when it is stale, and `UPDATE_BUDGET=1` rewrites it.
- Each method's cost is read from opcore's decision record 1, in the opcore source `Cargo.lock` pins, where opcore measured it on the real Core; sesame keeps no copy of the numbers, so an opcore bump that changes them changes the table.
- The stand-in logs a call it refuses with ` refused` after it in `calls.log`; a refused call spends nothing, as opcore's stand-in counts.
- `scripts/e2e.sh`, outside the gate, runs the table's commands on the vault `sesame-scratch` against a fake provider on 127.0.0.1, two config dirs for two machines, and sets each step's change in `op service-account ratelimit` (after 6 s to settle) beside its row; a step whose reads or writes differ fails it.

## Considered Options

- A cost table of sesame's own beside the stand-in: chosen against, a second
  home of opcore's numbers that drifts unseen.
- The live check as an ignored Rust test on the harness: chosen against, it
  would be compiled and counted by the gate it is kept out of; a script
  beside optokens' runs the release binary as a person does.
- Failing the live check on the account's requests too: the account is
  shared by every token of it, so another process's requests show in the
  delta; the script marks that difference and fails only on the token's own
  reads and writes.

## Consequences

The refused write and the write of a kept token have no live step: the
real rate limit cannot be reached on demand. Undo: remove `tests/budget.rs`,
`docs/budget.md` and `scripts/e2e.sh`; the stand-in's ` refused` is read
only by the tests.
