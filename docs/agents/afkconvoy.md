# afkconvoy config

How the afkconvoy fleet works this repo's backlog: issues in sunfmin/control
labelled `ready-for-agent` and `repo:sunfmin/sesame`, one worker per issue,
landed on `main` behind `./gate.sh`, the same gate a person runs.

```yaml
base_branch: "main"
gate_command: ./gate.sh
gate_seconds: 1200
ready_label: ready-for-agent
```

## Cutting a version

The fleet cuts each version of sesame itself, once it goes idle with landed
work past the newest `v*` tag (`afkconvoy cut --help`). These are its steps,
and the one place they are written. Each is run by `sh -e` in the cut's
checkout, with the version in `$VERSION`: `set` on the base branch, `publish`
with the new tag checked out. The repo has no version tag yet: `initial`
makes the first cut 0.1.0.

```yaml cut
initial: 0.1.0
set: |
  set -ex
  packaging/release.sh set "$VERSION"
publish: |
  set -ex
  packaging/release.sh check "$(git describe --tags --exact-match)"
  afkconvoy exclusive -- packaging/release.sh build
  packaging/release.sh package
  packaging/release.sh publish
  brew update --quiet
  brew upgrade sunfmin/tap/sesame || brew install sunfmin/tap/sesame
  test "$("$(brew --prefix)/bin/sesame" --version)" = "sesame $VERSION"
```

- `set -ex` first: the cut's log (`convoy-cut.log`) shows each line as it
  runs, so a failed step shows the line it failed at.
- `build` makes both release binaries; it waits its turn in the host's
  exclusive queue, as a gate does.
- `publish` writes the archives to the tap's release `sesame-v<version>` and
  the formula to `Formula/sesame.rb` of `sunfmin/homebrew-tap`: the host's
  `gh` login must be able to write there.
- `brew update` comes first: `brew upgrade` alone fetches the tap at most once
  a day. `brew install` is for the first version, which nothing has installed
  yet. The last line fails the step unless the sesame Homebrew links is the
  version cut.

A host claims a cut only where `build` can run: rustup's stable toolchain with
both macOS targets, found even where the host runner's PATH lacks
`~/.cargo/bin`.

```yaml cut-needs
checks:
  - name: rustup-stable-macos-targets
    command: |
      PATH="$PATH:$HOME/.cargo/bin"
      installed=$(rustup target list --installed --toolchain stable)
      for t in aarch64-apple-darwin x86_64-apple-darwin; do
        echo "$installed" | grep -qx "$t" || {
          echo "cut builds with rustup's stable toolchain and the target $t, which this host lacks: rustup toolchain install stable --profile minimal --target aarch64-apple-darwin x86_64-apple-darwin" >&2
          exit 1
        }
      done
    seconds: 30
    install: |
      PATH="$PATH:$HOME/.cargo/bin"
      rustup toolchain install stable --profile minimal --target aarch64-apple-darwin x86_64-apple-darwin
    install_seconds: 900
```
