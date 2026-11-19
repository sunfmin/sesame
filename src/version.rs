//! The version `sesame --version` says. build.rs includes this file and
//! stamps its result into the binary as `SESAME_VERSION`.

/// What git says about the commit being built.
pub struct Git<'a> {
    /// `git describe --tags --long --dirty --match 'v[0-9]*'`
    /// (`v1.2.3-4-gabc1234-dirty`), if a version tag is reachable.
    pub describe: Option<&'a str>,
    /// `git rev-list --count HEAD`: every clone has it, tags or not.
    pub commits: Option<&'a str>,
    /// `git describe --always --dirty --match 'v[0-9]*'` without a version
    /// tag: the short hash (`abc1234[-dirty]`).
    pub commit: Option<&'a str>,
}

/// The version to stamp: the release the release script names
/// (`SESAME_RELEASE`), as is; otherwise the development form
/// `1.2.3+<commits>.g<commit>[.dirty]`, from the nearest version tag, or
/// without one from `cargo_version` (Cargo.toml's) and the commit count; only
/// outside a repository, `cargo_version` alone. A clone without tags still
/// stamps the development form, though its count (all commits) differs from
/// a tagged clone's (commits since the tag).
pub fn stamp(release: Option<&str>, git: &Git, cargo_version: &str) -> String {
    if let Some(release) = release {
        return release.to_string();
    }
    git.describe
        .and_then(tagged)
        .or_else(|| untagged(git.commits?, git.commit?, cargo_version))
        .unwrap_or_else(|| cargo_version.to_string())
}

fn split_dirty(s: &str) -> (&str, &str) {
    match s.strip_suffix("-dirty") {
        Some(rest) => (rest, ".dirty"),
        None => (s, ""),
    }
}

fn tagged(describe: &str) -> Option<String> {
    let (rest, dirty) = split_dirty(describe);
    let mut parts = rest.rsplitn(3, '-');
    let (commit, commits, tag) = (parts.next()?, parts.next()?, parts.next()?);
    Some(format!(
        "{}+{commits}.{commit}{dirty}",
        tag.strip_prefix('v')?
    ))
}

fn untagged(commits: &str, commit: &str, cargo_version: &str) -> Option<String> {
    let (hash, dirty) = split_dirty(commit);
    let digits = |s: &str, radix| !s.is_empty() && s.chars().all(|c: char| c.is_digit(radix));
    (digits(commits, 10) && digits(hash, 16))
        .then(|| format!("{cargo_version}+{commits}.g{hash}{dirty}"))
}

#[cfg(test)]
mod tests {
    use super::{Git, stamp};

    fn git<'a>(
        describe: Option<&'a str>,
        commits: Option<&'a str>,
        commit: Option<&'a str>,
    ) -> Git<'a> {
        Git {
            describe,
            commits,
            commit,
        }
    }

    #[test]
    fn a_release_says_its_version_and_anything_else_says_where_it_was_built() {
        let tagged = git(Some("v1.2.3-4-gabc1234"), Some("9"), Some("abc1234"));
        assert_eq!(stamp(Some("1.2.4"), &tagged, "0.1.0"), "1.2.4");
        assert_eq!(stamp(None, &tagged, "0.1.0"), "1.2.3+4.gabc1234");
        let dirty = git(Some("v1.2.3-0-gabc1234-dirty"), None, None);
        assert_eq!(stamp(None, &dirty, "0.1.0"), "1.2.3+0.gabc1234.dirty");
        assert_eq!(stamp(None, &git(None, None, None), "0.1.0"), "0.1.0");
        assert_eq!(
            stamp(None, &git(Some("gabc1234"), None, None), "0.1.0"),
            "0.1.0"
        );
        assert_eq!(
            stamp(None, &git(Some("x-4-gabc1234"), None, None), "0.1.0"),
            "0.1.0"
        );
    }

    #[test]
    fn a_clone_without_tags_stamps_the_development_form_from_cargo_version() {
        assert_eq!(
            stamp(None, &git(None, Some("42"), Some("abc1234")), "0.1.0"),
            "0.1.0+42.gabc1234"
        );
        assert_eq!(
            stamp(None, &git(None, Some("42"), Some("abc1234-dirty")), "0.1.0"),
            "0.1.0+42.gabc1234.dirty"
        );
        assert_eq!(
            stamp(
                Some("1.2.4"),
                &git(None, Some("42"), Some("abc1234")),
                "0.1.0"
            ),
            "1.2.4"
        );
        assert_eq!(stamp(None, &git(None, Some("42"), None), "0.1.0"), "0.1.0");
        assert_eq!(
            stamp(None, &git(None, None, Some("abc1234")), "0.1.0"),
            "0.1.0"
        );
        assert_eq!(
            stamp(None, &git(None, Some("x"), Some("abc1234")), "0.1.0"),
            "0.1.0"
        );
        assert_eq!(
            stamp(None, &git(None, Some("42"), Some("v1.0-dirty")), "0.1.0"),
            "0.1.0"
        );
    }
}
