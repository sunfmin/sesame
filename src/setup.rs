//! `sesame setup <provider>`: the numbered steps from nothing to a working
//! `login`, written for an AI walking a person through them, and for the person.
use crate::providers::Provider;
use std::fmt::Write;

pub fn render(name: &str, p: &Provider) -> String {
    let callback = p.callback();
    let fill = |s: &str, scopes: &[String]| {
        s.replace("{callback}", &callback)
            .replace("{scopes}", &scopes.join(", "))
    };
    let scopes = p.scopes.join(", ");
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
                 Register an authorization-code (PKCE) app with callback URL {callback}\n\
                 and the scopes: {scopes}"
            ),
        );
    }
    for s in &p.setup {
        step(
            &mut out,
            &s.title,
            s.page.as_deref(),
            &fill(&s.details, &p.scopes),
        );
    }
    for (service, svc) in &p.services {
        for s in &svc.setup {
            let title = format!("{} (for `{service}`)", s.title);
            step(
                &mut out,
                &title,
                s.page.as_deref(),
                &fill(&s.details, &svc.scopes),
            );
        }
    }
    // Each service's login adds its scopes to those the token has.
    let services: String = p
        .services
        .iter()
        .map(|(s, svc)| {
            let about = if svc.about.is_empty() { s } else { &svc.about };
            format!("\nsesame login {s:<10} # adds {about} to the one `{name}` token")
        })
        .collect();
    let (client, login) = if p.device_url.is_some() {
        (
            format!(
                "sesame client {name} --client-id <client id> --no-secret\n\
                 The device flow needs no client secret. To also sign in with `--browser`, or to\n\
                 refresh expiring tokens, leave out --no-secret: it prompts for the secret without echoing it."
            ),
            format!(
                "sesame login {name}\n\
                 It prints a code and a page: the person opens the page (anywhere, also from a\n\
                 remote machine), enters the code and approves access.\n\
                 sesame login {name} --browser signs in through the redirect to {callback} instead.{services}"
            ),
        )
    } else {
        (
            format!(
                "sesame client {name} --client-id <client id>\n\
                 It prompts for the client secret without echoing it.\n\
                 (An app without a secret: add --no-secret.)"
            ),
            format!(
                "sesame login {name}{services}\n\
                 On a remote machine (SSH): open the printed URL anywhere, then paste the address\n\
                 the browser ends on back into the terminal."
            ),
        )
    };
    step(
        &mut out,
        "Store the client in sesame: the person runs this in their own terminal",
        None,
        &client,
    );
    step(
        &mut out,
        "Log in: the person approves access in the browser",
        None,
        &login,
    );
    let api = if p.services.is_empty() {
        format!("sesame api {name} <path>")
    } else {
        p.services
            .iter()
            .map(|(s, svc)| format!("sesame api {s:<10} <path>  # under {}", svc.api_base))
            .collect::<Vec<_>>()
            .join("\n")
    };
    step(
        &mut out,
        "Check, then call the API",
        None,
        &format!("sesame providers        # `{name}` shows logged in\n{api}"),
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
            "Gmail API (for `gmail`)",
            "https://console.cloud.google.com/apis/library/gmail.googleapis.com",
            "Google Calendar API (for `calendar`)",
            "https://www.googleapis.com/auth/gmail.readonly, https://www.googleapis.com/auth/gmail.send",
            "gmail.readonly is a restricted scope",
            "Calendar's scopes are sensitive",
            "security assessment",
            "sesame login gmail",
            "sesame api calendar   <path>  # under https://www.googleapis.com/calendar/v3",
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
    fn github() {
        let out = render("github", &built_in("github"));
        for want in [
            "https://github.com/settings/developers",
            "New OAuth App",
            "Authorization callback URL: http://127.0.0.1/callback",
            "http://127.0.0.1:<any port>/callback",
            "Enable Device Flow",
            "Expire user access tokens",
            "Client ID",
            "repo, read:org",
            "sesame client github --client-id <client id> --no-secret",
            "sesame login github --browser",
            "enters the code",
        ] {
            assert!(out.contains(want), "missing {want:?} in:\n{out}");
        }
        assert!(!out.contains("{callback}") && !out.contains("{scopes}"));
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
