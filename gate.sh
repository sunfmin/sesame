#!/bin/sh
# The gate: what must pass before anything lands.
set -e
cd "$(dirname "$0")"
cargo fmt --all --check
cargo clippy --all-targets --quiet -- -D warnings
# The tests, measured against .slimfit/baseline.json.
slimfit check
# The op stand-in answers every case of its contract (truefit.toml); the
# real op's side runs outside the gate (`truefit contract --real op`).
cargo build --quiet --example fake-op
truefit contract >/dev/null || truefit contract
