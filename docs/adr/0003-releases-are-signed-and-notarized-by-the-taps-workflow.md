# 3. Releases are universal, signed and notarized by the tap's workflow

sesame#33, after slimfit's [ADR 0013](https://github.com/sunfmin/slimfit/blob/main/docs/adr/0013-releases-are-signed-and-notarized-by-the-taps-workflow.md),
which holds the reasons. The contract is sunfmin/homebrew-tap's
[`.github/workflows/README.md`](https://github.com/sunfmin/homebrew-tap/blob/main/.github/workflows/README.md).

## Context

Until sesame#33 a cut built both arches on the cutting host, packed two
per-arch archives, and published them and an `on_arm` / `on_intel` formula
from there. The binaries were only ad hoc signed, so Gatekeeper rejected a
copy downloaded in a browser. The owner, 2026-11-22: 「把所有的工具都变成
universal。」「把公开的工具全部在 GitHub CI 上签。」

## Decision

Invariant: **the Developer ID identity and the notary key live only in
sunfmin/homebrew-tap, and only its `release` workflow signs.** sesame holds no
signing secret and no release workflow.

- **sesame builds.** `packaging/release.sh build <vX.Y.Z> <outdir>` builds
  `aarch64-apple-darwin` and `x86_64-apple-darwin` with `SESAME_RELEASE` set,
  `lipo -create`s them, checks the binary says the version, and leaves the
  universal `sesame` and `sesame.rb` (no arch branch, `url "@URL@"`,
  `sha256 "@SHA256@"`) in `<outdir>`. `dry` (in gate.sh) and `cut` run the
  same `build`.
- **The tap signs and publishes** the release `sesame-v<X.Y.Z>` (one archive,
  `sesame-<X.Y.Z>-macos-universal.tar.gz`) and `Formula/sesame.rb`.
- **The cut waits.** `cut` builds here, pushes the tag, runs
  `gh workflow run release.yml -R sunfmin/homebrew-tap -f repo=sesame -f tag=<tag>`,
  waits for that run (`RELEASE_WAIT_LIMIT`, 2400 s from the cut's start), and
  takes away the tag it pushed, so factorium's own tag step still tags.

## Consequences

- The gate builds both release targets (`release.sh dry`); the tests fake
  the build and the tap (`tests/release.rs`).
- `[cut] limit` covers the host's build plus the tap's run.
- A cut needs no tap token on the host: only `gh` logged in as a user who may
  push sesame and dispatch the tap's workflow.
