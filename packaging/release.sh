#!/bin/sh
# One version of sesame, cut on this Mac: factorium.toml's cut step runs
# `packaging/release.sh cut $FACTORIUM_VERSION` in a worktree at the base's
# tip, then factorium tags what it left at HEAD and `brew upgrade`s the
# formula.
#
#   release.sh cut <vX.Y.Z>   build for Apple Silicon and Intel with the tag's
#                             version stamped (build.rs, SESAME_RELEASE;
#                             Cargo.toml is not edited and nothing is
#                             committed), check each binary's arch and that
#                             `sesame --version` equals the tag, package, and
#                             publish: the archives to the tap's release
#                             sesame-v<X.Y.Z>, the formula to the tap's
#                             Formula/sesame.rb. Run again after a cut that
#                             failed half way, it publishes over what is there.
#   release.sh check-tag <vX.Y.Z>  exit 0 if cut would take the version, 2 if not
#   release.sh dry            what the tests run: check the binary this machine
#                             built ($BUILT, target/debug/sesame by default)
#                             says the development form
#                             X.Y.Z+<commits>.g<commit>[.dirty], package it at
#                             that version for both arches (the Intel archive
#                             holds the same binary, the arm64 archive
#                             copied: only cut builds both),
#                             check the formula, publish nothing
#
# The archives are downloaded from the tap (sunfmin/homebrew-tap), as every
# formula there is. DIST names another directory than dist/.
set -eu
cd "$(dirname "$0")/.."

# A cut runs under factorium's daemon, whose PATH may lack rustup's
# ~/.cargo/bin. Put it last, so a cargo already on PATH still comes first;
# `build` puts the stable toolchain's own bin first below.
PATH="$PATH:$HOME/.cargo/bin"
export PATH

REPO=https://github.com/sunfmin/sesame
TAP=sunfmin/homebrew-tap
ARCHES="arm64 x86_64"
DIST=${DIST:-dist}
# gzip's level for the archives: its default for cut; dry publishes nothing,
# so it packs fast.
LEVEL=6

usage() {
    echo "usage: release.sh cut <vX.Y.Z> | dry | check-tag <vX.Y.Z>" >&2
    exit 2
}

# The Rust target that builds for an arch.
target() {
    case "$1" in
    arm64) echo aarch64-apple-darwin ;;
    *) echo "$1-apple-darwin" ;;
    esac
}

archive() { # <version> <arch>
    echo "sesame-$1-macos-$2.tar.gz"
}

sha() {
    shasum -a 256 "$1" | cut -d' ' -f1
}

# check_binary <path> <arch> <version>: the binary is for the arch and, where
# this machine can run it (Intel needs Rosetta), says the version.
check_binary() {
    lipo -archs "$1" | grep -qx "$2" || {
        echo "release: $1 is not an $2 binary" >&2
        exit 1
    }
    if arch "-$2" /usr/bin/true 2>/dev/null; then
        said=$(arch "-$2" "$1" --version)
        [ "$said" = "sesame $3" ] || {
            echo "release: $1 --version says '$said', not 'sesame $3'" >&2
            exit 1
        }
    else
        echo "release: this machine cannot run $2: --version was not checked" >&2
    fi
}

# pack <binary> <arch> <version>: the binary to $DIST/<archive>.
pack() {
    mkdir -p "$DIST"
    staged=$(mktemp -d)
    cp "$1" "$staged/sesame"
    tar -czf "$DIST/$(archive "$3" "$2")" --options "gzip:compression-level=$LEVEL" \
        -C "$staged" sesame
    rm -rf "$staged"
    echo "$DIST/$(archive "$3" "$2")"
}

# formula <version>: the Homebrew formula for the archives in $DIST, checked,
# to $DIST/sesame.rb.
formula() {
    base=https://github.com/$TAP/releases/download/sesame-v$1
    out=$DIST/sesame.rb
    cat > "$out" <<FORMULA
class Sesame < Formula
  desc "Sign in to SaaS APIs from the terminal via OAuth and call their REST APIs"
  homepage "$REPO"
  version "$1"

  depends_on :macos

  on_arm do
    url "$base/$(archive "$1" arm64)"
    sha256 "$(sha "$DIST/$(archive "$1" arm64)")"
  end
  on_intel do
    url "$base/$(archive "$1" x86_64)"
    sha256 "$(sha "$DIST/$(archive "$1" x86_64)")"
  end

  def install
    bin.install "sesame"
  end

  test do
    assert_equal "sesame #{version}", shell_output("#{bin}/sesame --version").strip
  end
end
FORMULA
    ruby -c "$out" >/dev/null
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

# build <version>: both release binaries, the version stamped, with rustup's
# stable toolchain. Its own bin goes first on PATH: a `cargo` that is ahead
# of rustup's there (Homebrew's) has no Intel target, and `rustup run stable
# cargo` is not enough, as the cargo it starts still finds the `rustc` that
# is first on PATH.
build() {
    targets=$(for arch in $ARCHES; do target "$arch"; done)
    rustup=$(command -v rustup) || rustup=
    stable=$([ -n "$rustup" ] && "$rustup" which --toolchain stable cargo 2>/dev/null) || stable=
    installed=$([ -n "$stable" ] && "$rustup" target list --installed --toolchain stable) || installed=
    for target in $targets; do
        echo "$installed" | grep -qx "$target" && continue
        if [ -n "$rustup" ]; then
            why="that is not installed"
        else
            why="no rustup is installed (https://rustup.rs)"
        fi
        # shellcheck disable=SC2086
        cat >&2 <<MSG
release: cut needs rustup's stable toolchain with the target $target, and $why. With rustup, get it with:
    rustup toolchain install stable --profile minimal --target $(echo $targets)
MSG
        exit 1
    done
    PATH="$(dirname "$stable"):$PATH"
    export PATH
    for target in $targets; do
        SESAME_RELEASE=$1 cargo build --release --locked -p sesame --target "$target"
    done
}

case "${1:-}" in
check-tag)
    [ $# -eq 2 ] || usage
    check_tag "$2"
    exit 0
    ;;
dry)
    [ $# -eq 1 ] || usage
    built=${BUILT:-target/debug/sesame}
    [ -x "$built" ] || {
        echo "release: $built is missing: build it first" >&2
        exit 1
    }
    version=$("$built" --version | sed 's/^sesame //')
    case "$version" in
    *[!0-9a-z.+]* | *+*+*) dev=no ;;
    [0-9]*.[0-9]*.[0-9]*+[0-9]*.g[0-9a-f]*) dev=yes ;;
    *) dev=no ;;
    esac
    [ "$dev" = yes ] || {
        echo "release: $built --version says '$version', not X.Y.Z+<commits>.g<commit>[.dirty]" >&2
        exit 1
    }
    host=$(uname -m)
    check_binary "$built" "$host" "$version"
    LEVEL=1
    # One archive, copied for the other arches: they hold the same binary,
    # and compressing it again is most of what dry costs.
    first=
    for arch in $ARCHES; do
        if [ -z "$first" ]; then
            first=$(pack "$built" "$arch" "$version")
        else
            cp "$first" "$DIST/$(archive "$version" "$arch")"
        fi
    done
    formula "$version"
    echo "release: dry ok (sesame $version, $DIST/sesame.rb)"
    exit 0
    ;;
cut) [ $# -eq 2 ] || usage ;;
*) usage ;;
esac
check_tag "$2"
version=${2#v}
release=sesame-v$version

# The tag's version, stamped by build.rs: the tag goes on HEAD as it is.
build "$version"
archives=""
for arch in $ARCHES; do
    built=target/$(target "$arch")/release/sesame
    check_binary "$built" "$arch" "$version"
    archives="$archives $(pack "$built" "$arch" "$version")"
done
formula "$version"

# A release that is there already takes the archives again: a cut that
# failed half way is run a second time.
if gh release view "$release" -R "$TAP" >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    gh release upload "$release" -R "$TAP" --clobber $archives
else
    # shellcheck disable=SC2086
    gh release create "$release" -R "$TAP" --title "sesame $version" \
        --notes "The binaries the formula \`sesame\` installs." $archives
fi
tap=$(mktemp -d)
gh repo clone "$TAP" "$tap" -- --quiet --depth 1
cp "$DIST/sesame.rb" "$tap/Formula/sesame.rb"
git -C "$tap" add Formula/sesame.rb
if git -C "$tap" diff --cached --quiet; then
    echo "release: the tap's formula is sesame $version already"
else
    git -C "$tap" commit --quiet -m "sesame $version"
    git -C "$tap" push --quiet origin HEAD
fi
rm -rf "$tap"
