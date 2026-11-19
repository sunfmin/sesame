#!/bin/sh
# The gate: what must pass before anything lands.
set -e
cd "$(dirname "$0")"
cargo fmt --all --check
cargo clippy --all-targets --quiet -- -D warnings
# The tests, measured against .slimfit/baseline.json.
slimfit check
