#!/bin/sh
# The gate: what must pass before anything lands.
set -e
cd "$(dirname "$0")"
cargo fmt --all --check
# Each document in its home, within its budget (docfit.toml).
docfit check >/dev/null || docfit check
cargo clippy --all-targets --quiet -- -D warnings
# The tests, measured against .slimfit/baseline.json.
slimfit check
# The release build: both arches, universal, the formula (ADR 0003).
DIST=target/release-dry packaging/release.sh dry >/dev/null
# Each stand-in answers every case of its contract (truefit.toml).
truefit contract >/dev/null || truefit contract
