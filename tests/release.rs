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
/// the cut's RUN_ENDS. After the dispatch, the first LIST_FAILS `gh run list`
/// and the first VIEW_FAILS `gh run view` fail with HTTP 500; `gh run cancel`
/// is recorded with the tag origin holds when it is called.
struct Cut {
    dir: PathBuf,
    repo: PathBuf,
    origin: PathBuf,
}

impl Cut {
    fn new(name: &str) -> Cut {
        let dir = tmp(name);
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
            "#!/bin/sh\ns=$FAKE_GH\n\
             fail() { c=$(( $(cat $s.$1 2>/dev/null || echo 0) + 1 )); echo $c >$s.$1;\n\
             [ $c -gt \"$2\" ] || { echo 'failed: HTTP 500' >&2; exit 1; }; }\n\
             case \"$1 $2\" in\n\
             \"workflow run\") echo \"$*\" >>$s.calls; echo $(( $(cat $s.n) + 1 )) >$s.n ;;\n\
             \"run list\") n=$(cat $s.n); [ \"$n\" = 0 ] || { fail list \"${LIST_FAILS:-0}\"; echo \"$n\"; } ;;\n\
             \"run view\") case \"$*\" in *--log-failed*) echo \"the run's failed log\" ;; *) fail view \"${VIEW_FAILS:-0}\"; echo \"$RUN_ENDS\" ;; esac ;;\n\
             \"run cancel\") echo \"run cancel $3 tag=$(git --git-dir=\"${s%/gh}/origin.git\" tag --list v1.2.3)\" >>$s.calls ;;\n\
             esac\n",
        );
        // ADR 0003: only the tap signs. A cut that reached for a signing
        // tool would leave its call here.
        for tool in ["codesign", "notarytool", "security"] {
            script(
                &bin.join(tool),
                &format!("#!/bin/sh\necho \"{tool} $*\" >>\"$FAKE_GH.signing\"\nexit 1\n"),
            );
        }
        // xcrun also answers the system's own shims (--show-sdk-path).
        script(
            &bin.join("xcrun"),
            "#!/bin/sh\ncase \" $* \" in\n\
             *\\ codesign\\ * | *\\ notarytool\\ * | *\\ stapler\\ *) echo \"xcrun $*\" >>\"$FAKE_GH.signing\"; exit 1 ;;\n\
             esac\nexec /usr/bin/xcrun \"$@\"\n",
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

    fn run(&self, ends: &str, env: &[(&str, &str)]) -> Output {
        let path = format!(
            "{}:{}",
            self.dir.join("bin").display(),
            std::env::var("PATH").unwrap()
        );
        // ADR 0003: a cut needs no tap token on the host, only `gh` (here
        // the stand-in): nothing of the caller's environment reaches it but
        // PATH and HOME, so no GH_TOKEN, HOMEBREW_TAP_TOKEN or the like.
        Command::new("sh")
            .current_dir(&self.repo)
            .args(["packaging/release.sh", "cut", "v1.2.3"])
            .env_clear()
            .env("HOME", std::env::var("HOME").unwrap())
            .env("PATH", path)
            .env("FAKE_GH", self.dir.join("gh"))
            .env("RELEASE_WAIT_LIMIT", "20")
            .env("RUN_ENDS", ends)
            .envs(env.iter().copied())
            .output()
            .unwrap()
    }

    fn tagged(&self) -> String {
        git(&self.origin, &["tag", "--list", "v1.2.3"])
    }
}

#[test]
fn cut_builds_one_universal_formula_runs_the_taps_workflow_and_leaves_tagging_to_factorium() {
    let cut = Cut::new("cut");
    let out = cut.run("completed success", &[]);
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
    assert!(
        !cut.dir.join("gh.signing").exists(),
        "the cut signed: {}",
        std::fs::read_to_string(cut.dir.join("gh.signing")).unwrap_or_default()
    );
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

    let out = cut.run("completed failure", &[]);
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
    assert!(cut.run("completed success", &[]).status.success());
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
    let out = cut.run("completed success", &[]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not HEAD"));
    std::fs::remove_dir_all(&cut.dir).unwrap();
}

#[test]
fn a_cut_polls_again_after_gh_fails() {
    let cut = Cut::new("retry");
    let out = cut.run(
        "completed success",
        &[
            ("LIST_FAILS", "1"),
            ("VIEW_FAILS", "2"),
            ("RELEASE_POLL", "0"),
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("gh run list failed; trying again"),
        "{stderr}"
    );
    assert_eq!(
        stderr.matches("gh run view 1 failed; trying again").count(),
        2,
        "{stderr}"
    );
    let calls = std::fs::read_to_string(cut.dir.join("gh.calls")).unwrap();
    assert!(!calls.contains("run cancel"), "{calls}");
    assert_eq!(cut.tagged(), "");
    std::fs::remove_dir_all(&cut.dir).unwrap();
}

#[test]
fn a_cut_past_its_limit_cancels_its_run_then_takes_its_tag_away() {
    let cut = Cut::new("limit");
    let out = cut.run(
        "queued ",
        &[("RELEASE_WAIT_LIMIT", "1"), ("RELEASE_POLL", "1")],
    );
    assert!(!out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("still 'queued '"));
    let calls = std::fs::read_to_string(cut.dir.join("gh.calls")).unwrap();
    assert_eq!(
        calls.lines().last(),
        Some("run cancel 1 tag=v1.2.3"),
        "the run is cancelled while its tag is still on origin: {calls}"
    );
    assert_eq!(
        cut.tagged(),
        "",
        "the tag of a failed cut is still on origin"
    );
    std::fs::remove_dir_all(&cut.dir).unwrap();
}
