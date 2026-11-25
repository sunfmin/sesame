#!/bin/sh
# One version of sesame (ADR 0003): this repo builds it; sunfmin/homebrew-tap's
# release workflow signs, notarizes and publishes it. factorium.toml's cut step
# runs `packaging/release.sh cut $FACTORIUM_VERSION` in a worktree at the base's
# tip, then factorium tags what it left at HEAD and `brew upgrade`s the formula.
#
#   release.sh build <vX.Y.Z> <outdir>
#                             build aarch64 and x86_64 with the tag's version
#                             stamped (build.rs, SESAME_RELEASE; Cargo.toml is
#                             not edited), `lipo -create` them, check the
#                             universal binary says the version: <outdir> holds
#                             `sesame` and the formula `sesame.rb`, its url and
#                             sha256 left as @URL@ and @SHA256@ for the tap to
#                             fill in. Signs nothing, needs no secret.
#   release.sh cut <vX.Y.Z>   build, push the tag to origin, run the tap's
#                             release.yml on it and wait for that run, bounded
#                             (RELEASE_WAIT_LIMIT seconds from the cut's start,
#                             default 2400; RELEASE_POLL seconds between
#                             polls, default 5 for the run to appear, 15 for
#                             it to end); a `gh` poll that fails is logged and
#                             tried again on the next poll. A cut that ends
#                             early cancels the run it dispatched before it
#                             takes its tag away; publishes nothing from this
#                             host
#   release.sh check-tag <vX.Y.Z>  exit 0 if cut would take the version, 2 if not
#   release.sh dry            what the gate runs: build at the development form
#                             X.Y.Z+<commits>.g<commit>[.dirty], check the
#                             formula, publish nothing
#
# DIST names another directory than dist/.
set -eu
cd "$(dirname "$0")/.."

# A cut runs under factorium's daemon, whose PATH may lack rustup's
# ~/.cargo/bin. Put it last, so a cargo already on PATH still comes first;
# `build` puts the pinned toolchain's own bin first below.
PATH="$PATH:$HOME/.cargo/bin"
export PATH

REPO=https://github.com/sunfmin/sesame
TAP=sunfmin/homebrew-tap
TARGETS="aarch64-apple-darwin x86_64-apple-darwin"
DIST=${DIST:-dist}

usage() {
    echo "usage: release.sh build <vX.Y.Z> <outdir> | cut <vX.Y.Z> | dry | check-tag <vX.Y.Z>" >&2
    exit 2
}

# check_tag <tag>: a version tag vX.Y.Z, or usage.
check_tag() {
    case "$1" in
    v*[!0-9.]* | v*..* | v.* | v*.) usage ;;
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *) usage ;;
    esac
    case "$1" in v*.*.*.*) usage ;; esac
}

# toolchain: the toolchain rust-toolchain.toml pins (the one the gate passed)
# with both targets, its own bin first on PATH: a `cargo` ahead of rustup's
# there (Homebrew's) has no Intel target, and rustup's proxy is not enough, as
# the cargo it starts still finds the `rustc` that is first on PATH. Installs
# it and adds a missing target (into ~/.rustup): the tap's runner has neither.
toolchain() {
    command -v rustup >/dev/null || {
        echo "release: building both arches needs rustup (https://rustup.rs)" >&2
        exit 1
    }
    rustup toolchain install --no-self-update >/dev/null
    # shellcheck disable=SC2086 # the targets are words
    rustup target add $TARGETS >/dev/null
    PATH="$(dirname "$(rustup which cargo)"):$PATH"
    export PATH
}

# build <release or empty> <outdir>: the universal binary and the formula in
# <outdir>; answers (in $version) the version the binary says. An empty
# release builds the development form.
build() {
    toolchain
    # build.rs takes a set SESAME_RELEASE, even an empty one, as the version.
    if [ -n "$1" ]; then export SESAME_RELEASE="$1"; else unset SESAME_RELEASE; fi
    slices=
    for target in $TARGETS; do
        cargo build --release --locked --quiet -p sesame --target "$target"
        slices="$slices target/$target/release/sesame"
    done
    rm -rf "$2"
    mkdir -p "$2"
    # shellcheck disable=SC2086 # the slices are paths without spaces
    lipo -create -output "$2/sesame" $slices
    archs=$(lipo -archs "$2/sesame")
    [ "$archs" = "x86_64 arm64" ] || {
        echo "release: $2/sesame holds '$archs', not 'x86_64 arm64'" >&2
        exit 1
    }
    version=$("$2/sesame" --version | sed 's/^sesame //')
    [ -z "$1" ] || [ "$version" = "$1" ] || {
        echo "release: $2/sesame --version says 'sesame $version', not 'sesame $1'" >&2
        exit 1
    }
    cat >"$2/sesame.rb" <<FORMULA
class Sesame < Formula
  desc "Sign in to SaaS APIs from the terminal via OAuth and call their REST APIs"
  homepage "$REPO"
  url "@URL@"
  sha256 "@SHA256@"
  version "$version"

  depends_on :macos

  def install
    bin.install "sesame"
  end

  test do
    assert_equal "sesame #{version}", shell_output("#{bin}/sesame --version").strip
  end
end
FORMULA
    ruby -c "$2/sesame.rb" >/dev/null
}

# push_tag <tag>: origin has <tag> on HEAD. factorium's own tag step tags
# HEAD after the cut and fails on a tag origin already holds, so a tag this
# cut pushed is taken away again when the cut ends, however it ends (end_cut).
push_tag() {
    head=$(git rev-parse HEAD)
    # An annotated tag's peeled line (^{}) comes after it: the last line is the commit.
    there=$(git ls-remote origin "refs/tags/$1" "refs/tags/$1^{}" | tail -n1 | cut -f1)
    if [ -z "$there" ]; then
        git push --quiet origin "$head:refs/tags/$1"
        pushed=yes
    elif [ "$there" != "$head" ]; then
        echo "release: origin's $1 is on $there, not HEAD ($head)" >&2
        exit 1
    fi
}

# latest_run <tag>: the id of the newest run of the tap's release.yml on
# sesame <tag>, or nothing.
latest_run() {
    gh run list -R "$TAP" --workflow release.yml --event workflow_dispatch --limit 50 \
        --json databaseId,displayTitle \
        --jq "[.[] | select(.displayTitle == \"sesame $1\") | .databaseId] | max // empty"
}

# end_cut, on the cut's exit: a run it dispatched that has not completed is
# cancelled first, so no run is left building a tag that is gone; then the
# tag it pushed is taken away.
end_cut() {
    if [ "$dispatched" = yes ] && [ "$ended" != yes ]; then
        [ -n "$run" ] || run=$(latest_run "$tag") || run=
        if [ -n "$run" ] && [ "$run" != "$before" ]; then
            gh run cancel "$run" -R "$TAP" >/dev/null ||
                echo "release: could not cancel run $run: gh run cancel $run -R $TAP" >&2
        else
            echo "release: no release.yml run of sesame $tag in $TAP found to cancel" >&2
        fi
    fi
    [ "$pushed" != yes ] || git push --quiet origin ":refs/tags/$tag"
}

case "${1:-}" in
check-tag)
    [ $# -eq 2 ] || usage
    check_tag "$2"
    exit 0
    ;;
build)
    [ $# -eq 3 ] || usage
    check_tag "$2"
    build "${2#v}" "$3"
    echo "release: built sesame $version, universal, in $3"
    exit 0
    ;;
dry)
    [ $# -eq 1 ] || usage
    build "" "$DIST"
    case "$version" in
    *[!0-9a-z.+]* | *+*+*) dev=no ;;
    [0-9]*.[0-9]*.[0-9]*+[0-9]*.g[0-9a-f]*) dev=yes ;;
    *) dev=no ;;
    esac
    [ "$dev" = yes ] || {
        echo "release: $DIST/sesame --version says '$version', not X.Y.Z+<commits>.g<commit>[.dirty]" >&2
        exit 1
    }
    echo "release: dry ok (sesame $version, universal, $DIST)"
    exit 0
    ;;
cut) [ $# -eq 2 ] || usage ;;
*) usage ;;
esac
check_tag "$2"
tag=$2
started=$(date +%s)
limit=${RELEASE_WAIT_LIMIT:-2400}
pushed= dispatched= ended= run= before=
trap end_cut EXIT

# Built here first: a tag goes out only on a commit that builds at its version.
build "${tag#v}" "$DIST"
before=$(latest_run "$tag")
push_tag "$tag"
gh workflow run release.yml -R "$TAP" -f repo=sesame -f "tag=$tag"
dispatched=yes

while :; do
    found=$(latest_run "$tag") || {
        echo "release: gh run list failed; trying again" >&2
        found=
    }
    [ -n "$found" ] && [ "$found" != "$before" ] && run=$found && break
    [ $(($(date +%s) - started)) -lt "$limit" ] || {
        echo "release: no release.yml run of sesame $tag in $TAP after ${limit}s" >&2
        exit 1
    }
    sleep "${RELEASE_POLL:-5}"
done
echo "release: waiting for https://github.com/$TAP/actions/runs/$run"
while :; do
    state=$(gh run view "$run" -R "$TAP" --json status,conclusion --jq '.status + " " + .conclusion') || {
        echo "release: gh run view $run failed; trying again" >&2
        state=
    }
    case "$state" in
    "completed success")
        ended=yes
        break
        ;;
    completed*)
        ended=yes
        echo "release: run $run of sesame $tag ended '$state'" >&2
        gh run view "$run" -R "$TAP" --log-failed >&2 || true
        exit 1
        ;;
    esac
    [ $(($(date +%s) - started)) -lt "$limit" ] || {
        echo "release: run $run of sesame $tag still '$state' after ${limit}s: gh run view $run -R $TAP" >&2
        exit 1
    }
    sleep "${RELEASE_POLL:-15}"
done
echo "release: sesame $tag is published ($(($(date +%s) - started))s)"
