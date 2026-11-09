//! The built-in providers. A provider is one OAuth realm: one login, one token.
//!
//! They live in code, not in `sesame.db`, so a new version's definitions reach
//! everyone; the database keeps only the fields a person changed with
//! `sesame provider set` (see `super::effective`).
//!
//! `setup` holds the steps `sesame setup <provider>` prints to register the
//! OAuth app: the `page` to open and the `details` of what to click, fill in
//! and pick. In `details`, `{callback}` is the redirect URL login uses and
//! `{scopes}` the provider's `scopes`, so neither is written twice. sesame adds
//! the closing steps itself (store the client, log in, call the API).
use super::{Provider, SetupStep, TokenBody};
use std::collections::BTreeMap;

fn strings(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| s.to_string()).collect()
}

fn params(xs: &[(&str, &str)]) -> BTreeMap<String, String> {
    xs.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn step(title: &str, page: Option<&str>, details: &str) -> SetupStep {
    SetupStep {
        title: title.into(),
        page: page.map(Into::into),
        details: details.into(),
    }
}

pub fn all() -> BTreeMap<String, Provider> {
    BTreeMap::from([("google".into(), google()), ("jira".into(), jira())])
}

fn google() -> Provider {
    Provider {
        about: "Google APIs: Drive, Docs, Sheets, YouTube, ...".into(),
        auth_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
        token_url: "https://oauth2.googleapis.com/token".into(),
        api_base: "https://www.googleapis.com".into(),
        hosts: strings(&["*.googleapis.com"]),
        scopes: strings(&[
            "openid",
            "email",
            "https://www.googleapis.com/auth/drive.readonly",
            "https://www.googleapis.com/auth/documents.readonly",
            "https://www.googleapis.com/auth/youtube.readonly",
        ]),
        auth_params: params(&[("access_type", "offline"), ("prompt", "consent")]),
        token_body: TokenBody::Form,
        resources_url: None,
        redirect_port: None,
        setup: vec![
            step(
                "Create or pick a Google Cloud project",
                Some("https://console.cloud.google.com/projectcreate"),
                "\
To reuse a project, pick it in the project picker at the top of the console instead.
For a new one: enter a Project name, click Create, and wait until the console opens its Dashboard.
Every later step happens in this project: check the project picker shows it.",
            ),
            step(
                "Enable the Google Drive API",
                Some("https://console.cloud.google.com/apis/library/drive.googleapis.com"),
                "Click Enable.",
            ),
            step(
                "Enable the Google Docs API",
                Some("https://console.cloud.google.com/apis/library/docs.googleapis.com"),
                "Click Enable.",
            ),
            step(
                "Enable the YouTube Data API v3",
                Some("https://console.cloud.google.com/apis/library/youtube.googleapis.com"),
                "Click Enable.",
            ),
            step(
                "Configure the consent screen (Google Auth Platform > Branding)",
                Some("https://console.cloud.google.com/auth/branding"),
                "\
If it says \"Google Auth platform not configured yet\", click Get Started, then:
- App Information: App name (anything, e.g. \"sesame\"), User support email (your own).
- Audience: External (Internal only if every user is in your Google Workspace organization).
- Contact Information: your email address.
- Finish: tick \"I agree to the Google API Services: User Data Policy\", click Continue, then Create.",
            ),
            step(
                "Add yourself as a test user (Google Auth Platform > Audience)",
                Some("https://console.cloud.google.com/auth/audience"),
                "\
Under Test users click Add users, enter the Google account email you will sign in with, click Save.
While the app's Publishing status is Testing, only test users can sign in, and Google lets
their refresh token expire 7 days after consent: then `sesame login google` must run again.
To stay signed in longer, click Publish app on this page (status becomes In production).
The app is unverified, so the sign-in page shows an \"unverified app\" warning, and Google
caps an unverified app at 100 users over its lifetime; for your own use that is fine.",
            ),
            step(
                "Create the OAuth client (Google Auth Platform > Clients)",
                Some("https://console.cloud.google.com/auth/clients"),
                "\
Click Create Client.
- Application type: Desktop app (not Web application).
- Name: anything, e.g. \"sesame\"; only the console shows it.
Click Create. No redirect URI is entered: a Desktop app client accepts {callback}.
The dialog that opens shows the Client ID and Client secret; keep it open for the next step.
The scopes sesame asks for at login: {scopes}",
            ),
        ],
    }
}

fn jira() -> Provider {
    Provider {
        about: "Jira Cloud (Atlassian OAuth 2.0 3LO)".into(),
        auth_url: "https://auth.atlassian.com/authorize".into(),
        token_url: "https://auth.atlassian.com/oauth/token".into(),
        api_base: "https://api.atlassian.com/ex/jira/{resource_id}".into(),
        hosts: strings(&["api.atlassian.com"]),
        scopes: strings(&[
            "read:jira-work",
            "write:jira-work",
            "read:jira-user",
            "offline_access",
        ]),
        auth_params: params(&[("audience", "api.atlassian.com"), ("prompt", "consent")]),
        token_body: TokenBody::Json,
        resources_url: Some("https://api.atlassian.com/oauth/token/accessible-resources".into()),
        redirect_port: Some(8749),
        setup: vec![
            step(
                "Create an OAuth 2.0 integration in the Atlassian developer console",
                Some("https://developer.atlassian.com/console/myapp/"),
                "\
Sign in with the Atlassian account that can see your Jira site.
Open the Create menu and choose OAuth 2.0 integration.
Enter a name (e.g. \"sesame\") and finish creating it; the app's page opens with a left menu.",
            ),
            step(
                "Add the Jira API and its scopes (left menu: Permissions)",
                None,
                "\
Next to Jira API, click Add. Then click Configure next to it, and in the list of scopes
click Add next to each one sesame asks for: {scopes}
(offline_access is not in that list: it is what gives sesame a refresh token, and sesame asks for it at login).",
            ),
            step(
                "Set the callback URL (left menu: Authorization)",
                None,
                "\
Next to OAuth 2.0 (3LO), click Configure.
Callback URL: {callback}
It must match exactly, so do not change localhost or the port. Click Save changes.",
            ),
            step(
                "Copy the client ID and secret (left menu: Settings)",
                None,
                "The authentication details show the Client ID and Secret. Keep the page open for the next step.",
            ),
        ],
    }
}
