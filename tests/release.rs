//! `packaging/release.sh`'s steps that publish nothing: `check` and `formula`.

use std::path::Path;
use std::process::{Command, Output};

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/packaging/release.sh");
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn release(args: &[&str], dist: &Path) -> Output {
    Command::new("sh")
        .arg(SCRIPT)
        .args(args)
        .env("DIST", dist)
        .output()
        .expect("run release.sh")
}

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sesame-release-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn check_takes_only_the_tag_of_the_version() {
    let dist = tmp("check");
    assert!(
        release(&["check", &format!("v{VERSION}")], &dist)
            .status
            .success()
    );
    let wrong = release(&["check", "v9.9.9"], &dist);
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("is not v"));
}

#[test]
fn formula_points_at_the_tap_release_with_each_archive_sum() {
    let dist = tmp("formula");
    let missing = release(&["formula"], &dist);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("package it first"));

    for arch in ["arm64", "x86_64"] {
        std::fs::write(
            dist.join(format!("sesame-{VERSION}-macos-{arch}.tar.gz")),
            arch,
        )
        .unwrap();
    }
    let out = release(&["formula"], &dist);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let formula = String::from_utf8(out.stdout).unwrap();
    let base =
        format!("https://github.com/sunfmin/homebrew-tap/releases/download/sesame-v{VERSION}");
    assert!(formula.contains("class Sesame < Formula"));
    assert!(formula.contains(&format!("version \"{VERSION}\"")));
    assert!(formula.contains(&format!(
        "url \"{base}/sesame-{VERSION}-macos-arm64.tar.gz\""
    )));
    assert!(formula.contains(&format!(
        "url \"{base}/sesame-{VERSION}-macos-x86_64.tar.gz\""
    )));
    for arch in ["arm64", "x86_64"] {
        let sum = Command::new("shasum")
            .args(["-a", "256"])
            .arg(dist.join(format!("sesame-{VERSION}-macos-{arch}.tar.gz")))
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
    let rb = dist.join("sesame.rb");
    std::fs::write(&rb, &formula).unwrap();
    let ruby = Command::new("ruby").arg("-c").arg(&rb).output();
    if let Ok(ruby) = ruby {
        assert!(
            ruby.status.success(),
            "{}",
            String::from_utf8_lossy(&ruby.stderr)
        );
    }
    std::fs::remove_dir_all(&dist).unwrap();
}
