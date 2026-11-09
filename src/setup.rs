//! `sesame setup <provider>`: the numbered steps from nothing to a working
//! `login`, written for an AI walking a person through them, and for the person.
use crate::providers::{Provider, Redirect};
use std::fmt::Write;

pub fn render(name: &str, p: &Provider) -> String {
    let callback = p.callback();
    let scopes = p.scopes.join(", ");
    let fill = |s: &str| {
        s.replace("{callback}", &callback)
            .replace("{scopes}", &scopes)
    };
    let mut out = String::new();
    let mut n = 0;
    let mut step = |out: &mut String, title: &str, page: Option<&str>, details: &str| {
        n += 1;
        let _ = writeln!(out, "{n}. {title}");
        if let Some(page) = page {
            let _ = writeln!(out, "   Open: {page}");
        }
        for line in details.lines() {
            let _ = writeln!(out, "   {line}");
        }
        out.push('\n');
    };

    let _ = writeln!(
        out,
        "Set up `{name}` ({}): register an OAuth app once, store it in sesame, log in.\n\n\
         If you are an AI walking a person through this:\n\
         - Go one step at a time; the person does each step in their browser and tells you when it is done.\n\
         - Never ask for the client secret in this conversation. The person runs `sesame client` in\n  \
           their own terminal; it asks for the secret with hidden input.\n\
         - `sesame login` needs the person to approve access in their browser themselves; do not click\n  \
           it for them.\n",
        if p.about.is_empty() { name } else { &p.about }
    );

    if p.setup.is_empty() {
        step(
            &mut out,
            "Register an OAuth app with the provider",
            None,
            &format!(
                "No setup steps are written for `{name}`. To print them here, add them with\n\
                 sesame provider set {name} --setup-step '{{\"title\": …, \"page\": …, \"details\": …}}'\n\
                 Register an authorization-code{} app with callback URL {callback}\n\
                 and the scopes: {scopes}",
                if p.pkce { " (PKCE)" } else { "" }
            ),
        );
    }
    for s in &p.setup {
        step(&mut out, &s.title, s.page.as_deref(), &fill(&s.details));
    }
    step(
        &mut out,
        "Store the client in sesame: the person runs this in their own terminal",
        None,
        &format!(
            "sesame client {name} --client-id <client id>\n\
             It prompts for the client secret without echoing it.\n\
             (An app without a secret: add --no-secret.)"
        ),
    );
    step(
        &mut out,
        "Log in: the person approves access in the browser",
        None,
        &match p.redirect {
            Redirect::Loopback => format!(
                "sesame login {name}\n\
                 On a remote machine (SSH): open the printed URL anywhere, then paste the address\n\
                 the browser ends on back into the terminal."
            ),
            Redirect::HttpsPaste => format!(
                "sesame login {name}\n\
                 After approving, the browser ends on {callback}?code=… and says it cannot open\n\
                 the page: that is expected. Copy the whole address from the address bar and paste\n\
                 it into the terminal."
            ),
        },
    );
    step(
        &mut out,
        "Check, then call the API",
        None,
        &format!(
            "sesame providers        # `{name}` shows logged in\n\
             sesame api {name} <path>\n\
             A token you got another way can be stored instead of logging in:\n\
             sesame login {name} --token   (hidden input; no refresh, paste a new one when it stops working)"
        ),
    );
    out.trim_end().to_string() + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::providers::built_in;

    #[test]
    fn google() {
        let out = render("google", &built_in("google"));
        for want in [
            "Desktop app",
            "Drive API",
            "Docs API",
            "YouTube Data API v3",
            "https://console.cloud.google.com/auth/branding",
            "External",
            "Test users",
            "7 days",
            "Publish app",
            "https://www.googleapis.com/auth/drive.readonly",
            "sesame client google --client-id <client id>",
            "sesame login google",
            "client secret in this conversation",
        ] {
            assert!(out.contains(want), "missing {want:?} in:\n{out}");
        }
        assert!(!out.contains("{callback}") && !out.contains("{scopes}"));
    }

    #[test]
    fn jira() {
        let out = render("jira", &built_in("jira"));
        for want in [
            "https://developer.atlassian.com/console/myapp/",
            "OAuth 2.0 integration",
            "Permissions",
            "Jira API",
            "read:jira-work, write:jira-work",
            "Authorization",
            "Callback URL: http://localhost:8749/callback",
            "Settings",
            "sesame client jira --client-id <client id>",
            "sesame login jira",
        ] {
            assert!(out.contains(want), "missing {want:?} in:\n{out}");
        }
    }

    #[test]
    fn slack() {
        let out = render("slack", &built_in("slack"));
        for want in [
            "https://api.slack.com/apps",
            "Create New App",
            "From scratch",
            "OAuth & Permissions",
            "User Token Scopes",
            "channels:read, groups:read",
            "chat:write",
            "Redirect URLs",
            "enter https://localhost:8751/callback",
            "Install to Workspace",
            "xoxp-",
            "sesame login slack --token",
            "Basic Information",
            "sesame client slack --client-id <client id>",
            "ends on https://localhost:8751/callback?code=",
        ] {
            assert!(out.contains(want), "missing {want:?} in:\n{out}");
        }
        assert!(!out.contains("http://localhost"), "{out}");
    }

    #[test]
    fn notion() {
        let out = render("notion", &built_in("notion"));
        for want in [
            "https://app.notion.com/developers/connections",
            "OAuth integration",
            "Redirect URI: http://localhost:8750/callback",
            "not 127.0.0.1",
            "Configuration tab",
            "sesame client notion --client-id <client id>",
            "sesame login notion",
        ] {
            assert!(out.contains(want), "missing {want:?} in:\n{out}");
        }
    }

    #[test]
    fn steps_are_numbered_in_order() {
        let out = render("jira", &built_in("jira"));
        let firsts: Vec<&str> = out
            .lines()
            .filter_map(|l| l.split_once(". ").map(|(n, _)| n))
            .filter(|n| n.parse::<u32>().is_ok())
            .collect();
        let want: Vec<String> = (1..=firsts.len()).map(|i| i.to_string()).collect();
        assert_eq!(firsts, want);
    }

    #[test]
    fn callback_follows_redirect_port() {
        let mut p = built_in("jira");
        p.redirect_port = Some(9123);
        let out = render("jira", &p);
        assert!(out.contains("http://localhost:9123/callback"), "{out}");
        assert!(!out.contains("8749"));
    }
}
