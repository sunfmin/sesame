//! `packaging/release.sh` without building or publishing: `check-tag`, and
//! `cut` with cargo, lipo, rustup and gh faked and origin a bare repo here.
//! The real two-arch build is `release.sh dry`, which gate.sh runs.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/packaging/release.sh");

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sesame-release-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn script(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    Command::new("chmod").arg("+x").arg(path).status().unwrap();
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn check_tag_takes_only_a_version_tag() {
    let run = |tag: &str| {
        Command::new("sh")
            .arg(SCRIPT)
            .args(["check-tag", tag])
            .output()
            .unwrap()
            .status
            .code()
    };
    for good in ["v0.1.0", "v1.22.333"] {
        assert_eq!(run(good), Some(0), "{good}");
    }
    for bad in [
        "", "v1", "v1.2", "1.2.3", "v1.2.3.4", "v1..3", "v1.2.x", "v1.2.3;x",
    ] {
        assert_eq!(run(bad), Some(2), "{bad:?}");
    }
}

/// A repo holding release.sh, with origin a bare repo, and fakes ahead on
/// PATH: `gh workflow run` makes run <n+1>, which `gh run view` reports as
/// the cut's RUN_ENDS.
struct Cut {
    dir: PathBuf,
    repo: PathBuf,
    origin: PathBuf,
}

impl Cut {
    fn new() -> Cut {
        let dir = tmp("cut");
        let (bin, repo, origin) = (dir.join("bin"), dir.join("repo"), dir.join("origin.git"));
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(repo.join("packaging")).unwrap();
        std::fs::copy(SCRIPT, repo.join("packaging/release.sh")).unwrap();
        script(
            &bin.join("cargo"),
            "#!/bin/sh\nfor a; do case \"$prev\" in --target) t=$a ;; esac; prev=$a; done\n\
             mkdir -p target/$t/release\n\
             printf '#!/bin/sh\\necho \"sesame %s\"\\n' \"$SESAME_RELEASE\" >target/$t/release/sesame\n\
             chmod +x target/$t/release/sesame\n",
        );
        script(
            &bin.join("lipo"),
            "#!/bin/sh\ncase \"$1\" in -archs) echo \"x86_64 arm64\" ;; -create) cp \"$4\" \"$3\" ;; esac\n",
        );
        script(
            &bin.join("rustup"),
            &format!(
                "#!/bin/sh\ncase \"$1\" in which) echo '{}/cargo' ;; esac\n",
                bin.display()
            ),
        );
        script(
            &bin.join("gh"),
            "#!/bin/sh\ns=$FAKE_GH\ncase \"$1 $2\" in\n\
             \"workflow run\") echo \"$*\" >>$s.calls; echo $(( $(cat $s.n) + 1 )) >$s.n ;;\n\
             \"run list\") n=$(cat $s.n); [ \"$n\" = 0 ] || echo \"$n\" ;;\n\
             \"run view\") case \"$*\" in *--log-failed*) echo \"the run's failed log\" ;; *) echo \"$RUN_ENDS\" ;; esac ;;\n\
             esac\n",
        );
        std::fs::write(dir.join("gh.n"), "0\n").unwrap();
        git(&dir, &["init", "-q", "--bare", "origin.git"]);
        git(&repo, &["init", "-q"]);
        git(&repo, &["add", "."]);
        git(
            &repo,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-qm",
                "one",
            ],
        );
        git(
            &repo,
            &["remote", "add", "origin", origin.to_str().unwrap()],
        );
        Cut { dir, repo, origin }
    }

    fn run(&self, ends: &str) -> Output {
        let path = format!(
            "{}:{}",
            self.dir.join("bin").display(),
            std::env::var("PATH").unwrap()
        );
        Command::new("sh")
            .current_dir(&self.repo)
            .args(["packaging/release.sh", "cut", "v1.2.3"])
            .env("PATH", path)
            .env("FAKE_GH", self.dir.join("gh"))
            .env("RELEASE_WAIT_LIMIT", "20")
            .env("RUN_ENDS", ends)
            .env_remove("DIST")
            .output()
            .unwrap()
    }

    fn tagged(&self) -> String {
        git(&self.origin, &["tag", "--list", "v1.2.3"])
    }
}

#[test]
fn cut_builds_one_universal_formula_runs_the_taps_workflow_and_leaves_tagging_to_factorium() {
    let cut = Cut::new();
    let out = cut.run("completed success");
    assert!(out.status.success(), "{out:?}");
    let calls = std::fs::read_to_string(cut.dir.join("gh.calls")).unwrap();
    assert_eq!(
        calls.trim(),
        "workflow run release.yml -R sunfmin/homebrew-tap -f repo=sesame -f tag=v1.2.3"
    );
    let formula = std::fs::read_to_string(cut.repo.join("dist/sesame.rb")).unwrap();
    for line in [
        "url \"@URL@\"",
        "sha256 \"@SHA256@\"",
        "version \"1.2.3\"",
        "assert_equal \"sesame #{version}\", shell_output(\"#{bin}/sesame --version\").strip",
    ] {
        assert!(formula.contains(line), "{line}: {formula}");
    }
    assert!(!formula.contains("on_arm") && !formula.contains("depends_on arch"));
    assert_eq!(
        cut.tagged(),
        "",
        "the tag the cut pushed is still on origin"
    );
    assert_eq!(
        git(&cut.repo, &["tag"]),
        "",
        "factorium's tag step would fail"
    );

    let out = cut.run("completed failure");
    assert!(!out.status.success(), "a run that fails passes the cut");
    assert!(String::from_utf8_lossy(&out.stderr).contains("the run's failed log"));
    assert_eq!(
        cut.tagged(),
        "",
        "the tag of a failed cut is still on origin"
    );

    // factorium's tag step, after a cut: a cut run again finds the tag on
    // HEAD and leaves it; on another commit, it fails.
    let head = git(&cut.repo, &["rev-parse", "HEAD"]);
    git(&cut.origin, &["tag", "v1.2.3", &head]);
    assert!(cut.run("completed success").status.success());
    assert_eq!(
        cut.tagged(),
        "v1.2.3",
        "the cut took away a tag it did not push"
    );
    git(
        &cut.repo,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "two",
        ],
    );
    let out = cut.run("completed success");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not HEAD"));
    std::fs::remove_dir_all(&cut.dir).unwrap();
}
