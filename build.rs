//! Stamps `SESAME_VERSION`: see src/version.rs.

#[path = "src/version.rs"]
mod version;

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    println!("cargo:rerun-if-env-changed=SESAME_RELEASE");
    // A new commit, tag or checkout, or an edit, changes the development form.
    for path in ["src", "build.rs", "Cargo.toml", "Cargo.lock"] {
        println!("cargo:rerun-if-changed={path}");
    }
    for dir in [
        git(&["rev-parse", "--git-dir"]),
        git(&["rev-parse", "--git-common-dir"]),
    ]
    .into_iter()
    .flatten()
    {
        for file in ["HEAD", "index", "packed-refs", "refs"] {
            println!("cargo:rerun-if-changed={dir}/{file}");
        }
    }
    let release = std::env::var("SESAME_RELEASE").ok();
    let describe = git(&[
        "describe", "--tags", "--long", "--dirty", "--match", "v[0-9]*",
    ]);
    // Without a version tag (a clone made with --no-tags): the commit count and hash.
    let commits = git(&["rev-list", "--count", "HEAD"]);
    let commit = git(&["describe", "--always", "--dirty", "--match", "v[0-9]*"]);
    let found = version::Git {
        describe: describe.as_deref(),
        commits: commits.as_deref(),
        commit: commit.as_deref(),
    };
    let cargo_version = std::env::var("CARGO_PKG_VERSION").unwrap();
    println!(
        "cargo:rustc-env=SESAME_VERSION={}",
        version::stamp(release.as_deref(), &found, &cargo_version)
    );
}
