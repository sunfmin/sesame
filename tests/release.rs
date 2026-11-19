//! `packaging/release.sh`'s steps that publish nothing: `check-tag` and `dry`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/packaging/release.sh");

fn release(args: &[&str], dir: &Path) -> Output {
    // A `gh` and a `git` ahead on PATH that leave a mark: neither may run.
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for tool in ["gh", "git"] {
        let stub = bin.join(tool);
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\ntouch '{}'\nexit 1\n",
                dir.join("published").display()
            ),
        )
        .unwrap();
        Command::new("chmod").arg("+x").arg(&stub).status().unwrap();
    }
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let out = Command::new("sh")
        .arg(SCRIPT)
        .args(args)
        .env("DIST", dir.join("dist"))
        .env("BUILT", env!("CARGO_BIN_EXE_sesame"))
        .env("PATH", path)
        .output()
        .expect("run release.sh");
    assert!(
        !dir.join("published").exists(),
        "release.sh {args:?} ran gh or git"
    );
    out
}

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sesame-release-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn check_tag_takes_only_a_version_tag() {
    let dir = tmp("check-tag");
    for good in ["v0.1.0", "v1.22.333"] {
        assert!(
            release(&["check-tag", good], &dir).status.success(),
            "{good}"
        );
    }
    for bad in [
        "", "v1", "v1.2", "1.2.3", "v1.2.3.4", "v1..3", "v1.2.x", "v1.2.3;x",
    ] {
        let out = release(&["check-tag", bad], &dir);
        assert_eq!(out.status.code(), Some(2), "{bad:?}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn dry_packages_the_development_build_for_both_arches_and_checks_the_formula() {
    let dir = tmp("dry");
    let out = release(&["dry"], &dir);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let said = Command::new(env!("CARGO_BIN_EXE_sesame"))
        .arg("--version")
        .output()
        .unwrap();
    let said = String::from_utf8(said.stdout).unwrap();
    let version = said.trim().strip_prefix("sesame ").unwrap();
    assert!(version.contains("+"), "a development build says {version}");

    let dist = dir.join("dist");
    let formula = std::fs::read_to_string(dist.join("sesame.rb")).unwrap();
    let base =
        format!("https://github.com/sunfmin/homebrew-tap/releases/download/sesame-v{version}");
    assert!(formula.contains("class Sesame < Formula"));
    assert!(formula.contains(&format!("version \"{version}\"")));
    for arch in ["arm64", "x86_64"] {
        let archive = format!("sesame-{version}-macos-{arch}.tar.gz");
        assert!(
            formula.contains(&format!("url \"{base}/{archive}\"")),
            "{arch}"
        );
        let listed = Command::new("tar")
            .arg("-tzf")
            .arg(dist.join(&archive))
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&listed.stdout).trim(), "sesame");
        let sum = Command::new("shasum")
            .args(["-a", "256"])
            .arg(dist.join(&archive))
            .output()
            .unwrap();
        let sum = String::from_utf8(sum.stdout).unwrap();
        let sum = sum.split_whitespace().next().unwrap();
        assert!(
            formula.contains(&format!("sha256 \"{sum}\"")),
            "{arch}: {sum}"
        );
    }
    assert!(formula.contains(
        "assert_equal \"sesame #{version}\", shell_output(\"#{bin}/sesame --version\").strip"
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}
