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
use super::{ClientAuth, Provider, Redirect, RedirectHost, Service, SetupStep, TokenBody};
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
    BTreeMap::from([
        ("figma".into(), figma()),
        ("github".into(), github()),
        ("google".into(), google()),
        ("jira".into(), jira()),
        ("linear".into(), linear()),
        ("notion".into(), notion()),
        ("slack".into(), slack()),
    ])
}

/// A GitHub OAuth App (not a GitHub App). Login is the device flow, which
/// needs no client secret; `--browser` uses the loopback redirect on
/// 127.0.0.1, whose port GitHub does not match against the registered one.
/// https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
fn github() -> Provider {
    Provider {
        about: "GitHub REST and GraphQL APIs (OAuth App)".into(),
        auth_url: "https://github.com/login/oauth/authorize".into(),
        token_url: "https://github.com/login/oauth/access_token".into(),
        refresh_url: None,
        api_base: "https://api.github.com".into(),
        hosts: strings(&["api.github.com", "uploads.github.com"]),
        scope_separator: " ".into(),
        scopes: strings(&["repo", "read:org"]),
        scope_param: "scope".into(),
        auth_params: BTreeMap::new(),
        pkce: true,
        token_body: TokenBody::Form,
        token_path: String::new(),
        client_auth: ClientAuth::Body,
        api_headers: params(&[
            ("Accept", "application/vnd.github+json"),
            ("X-GitHub-Api-Version", "2026-03-10"),
        ]),
        resources_url: None,
        site_name_field: None,
        redirect: Redirect::Loopback,
        redirect_port: None,
        code_seconds: None,
        redirect_host: RedirectHost::Loopback,
        device_url: Some("https://github.com/login/device/code".into()),
        identity_url: Some("https://api.github.com/user".into()),
        identity_field: Some("login".into()),
        identity_body: None,
        error_fields: vec![],
        setup: vec![
            step(
                "Register an OAuth App (Settings > Developer settings > OAuth Apps)",
                Some("https://github.com/settings/developers"),
                "\
Click New OAuth App (Register a new application if you have none yet). To have an
organization own it, use that organization's Settings > Developer settings > OAuth Apps instead.
- Application name: anything, e.g. \"sesame\"; people see it when they approve access.
- Homepage URL: any page of yours, e.g. https://github.com/<you>.
- Authorization callback URL: http://127.0.0.1/callback
  (GitHub takes any port at login, so sesame listens on {callback}).
- Tick Enable Device Flow: `sesame login github` uses it, and it needs no client secret.
- Expire user access tokens: refreshing an expiring token needs the client secret. Without a
  secret stored in sesame, untick it, or run `sesame login github` again when the token expires (8 hours).
Click Register application.",
            ),
            step(
                "Copy the Client ID",
                None,
                "\
The app's page shows the Client ID. The device flow needs nothing else.
Only for `sesame login github --browser`, or to refresh expiring tokens: click
Generate a new client secret and keep it for the next step.
The scopes sesame asks for at login: {scopes}",
            ),
        ],
        services: BTreeMap::new(),
        sources: strings(&["https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps"]),
    }
}

/// Google's one OAuth client and token reach many APIs, each a service: login
/// to a service adds its scopes to those granted (`include_granted_scopes`).
/// Scope tiers: https://developers.google.com/workspace/gmail/api/auth/scopes,
/// https://developers.google.com/workspace/drive/api/guides/api-specific-auth,
/// https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification
fn google() -> Provider {
    let scopes = |xs: &[&str]| -> Vec<String> {
        xs.iter()
            .map(|s| format!("https://www.googleapis.com/auth/{s}"))
            .collect()
    };
    let enable = |api: &str, page: &str, about: &str| {
        vec![step(
            &format!("Enable the {api}"),
            Some(&format!(
                "https://console.cloud.google.com/apis/library/{page}"
            )),
            &format!("Click Enable. Its scopes: {{scopes}}\n{about}"),
        )]
    };
    let service = |about: &str, api_base: &str, s: &[&str], setup: Vec<SetupStep>| Service {
        about: about.into(),
        api_base: api_base.into(),
        scopes: scopes(s),
        setup,
    };
    Provider {
        about: "Google APIs: one sign-in for Drive, Docs, YouTube, Calendar, Gmail".into(),
        auth_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
        token_url: "https://oauth2.googleapis.com/token".into(),
        refresh_url: None,
        api_base: "https://www.googleapis.com".into(),
        hosts: strings(&["*.googleapis.com"]),
        scope_separator: " ".into(),
        scopes: strings(&["openid", "email"]),
        scope_param: "scope".into(),
        auth_params: params(&[
            ("access_type", "offline"),
            ("prompt", "consent"),
            ("include_granted_scopes", "true"),
        ]),
        pkce: true,
        token_body: TokenBody::Form,
        token_path: String::new(),
        client_auth: ClientAuth::Body,
        api_headers: BTreeMap::new(),
        resources_url: None,
        site_name_field: None,
        redirect: Redirect::Loopback,
        redirect_port: None,
        code_seconds: None,
        redirect_host: RedirectHost::Localhost,
        device_url: None,
        identity_url: None,
        identity_field: None,
        identity_body: None,
        error_fields: vec![],
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
That is fine for your own use. To stay signed in longer, click Publish app on this page
(status becomes In production); the sign-in page then shows an \"unverified app\" warning,
and Google caps an unverified app's users.
Each service's scopes are sensitive or restricted, as its step below says. For yourself, in
Testing or unverified, that needs no review. To let other people's accounts in, Google must
verify the app; restricted scopes (Gmail read, Drive) also need a security assessment when
their data is stored on or sent through servers:
https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification",
            ),
            step(
                "Create the OAuth client (Google Auth Platform > Clients)",
                Some("https://console.cloud.google.com/auth/clients"),
                "\
Click Create Client.
- Application type: Desktop app (not Web application).
- Name: anything, e.g. \"sesame\"; only the console shows it.
Click Create. No redirect URI is entered: a Desktop app client accepts {callback}.
The dialog that opens shows the Client ID and Client secret; keep them for storing the client below.
`sesame login google` asks only for: {scopes}; each service's login adds its own.",
            ),
        ],
        services: BTreeMap::from([
            (
                "calendar".into(),
                service(
                    "Google Calendar",
                    "https://www.googleapis.com/calendar/v3",
                    &["calendar.readonly", "calendar.events"],
                    enable(
                        "Google Calendar API",
                        "calendar-json.googleapis.com",
                        "Calendar's scopes are sensitive.",
                    ),
                ),
            ),
            (
                "docs".into(),
                service(
                    "Google Docs",
                    "https://docs.googleapis.com/v1",
                    &["documents.readonly"],
                    enable("Google Docs API", "docs.googleapis.com", ""),
                ),
            ),
            (
                "drive".into(),
                service(
                    "Google Drive",
                    "https://www.googleapis.com/drive/v3",
                    &["drive.readonly"],
                    enable(
                        "Google Drive API",
                        "drive.googleapis.com",
                        "drive.readonly is a restricted scope.",
                    ),
                ),
            ),
            (
                "gmail".into(),
                service(
                    "Gmail",
                    "https://gmail.googleapis.com/gmail/v1",
                    &["gmail.readonly", "gmail.send"],
                    enable(
                        "Gmail API",
                        "gmail.googleapis.com",
                        "gmail.readonly is a restricted scope, gmail.send a sensitive one.",
                    ),
                ),
            ),
            (
                "youtube".into(),
                service(
                    "YouTube Data API",
                    "https://www.googleapis.com/youtube/v3",
                    &["youtube.readonly"],
                    enable("YouTube Data API v3", "youtube.googleapis.com", ""),
                ),
            ),
        ]),
        sources: strings(&["https://developers.google.com/identity/protocols/oauth2/native-app", "https://developers.google.com/workspace/gmail/api/auth/scopes"]),
    }
}

fn jira() -> Provider {
    Provider {
        about: "Jira Cloud (Atlassian OAuth 2.0 3LO)".into(),
        auth_url: "https://auth.atlassian.com/authorize".into(),
        token_url: "https://auth.atlassian.com/oauth/token".into(),
        refresh_url: None,
        api_base: "https://api.atlassian.com/ex/jira/{resource_id}".into(),
        hosts: strings(&["api.atlassian.com"]),
        scope_separator: " ".into(),
        scopes: strings(&[
            "read:jira-work",
            "write:jira-work",
            "read:jira-user",
            "offline_access",
        ]),
        scope_param: "scope".into(),
        auth_params: params(&[("audience", "api.atlassian.com"), ("prompt", "consent")]),
        pkce: true,
        token_body: TokenBody::Json,
        token_path: String::new(),
        client_auth: ClientAuth::Body,
        api_headers: BTreeMap::new(),
        resources_url: Some("https://api.atlassian.com/oauth/token/accessible-resources".into()),
        site_name_field: None,
        redirect: Redirect::Loopback,
        redirect_port: Some(8749),
        code_seconds: None,
        redirect_host: RedirectHost::Localhost,
        device_url: None,
        identity_url: None,
        identity_field: None,
        identity_body: None,
        error_fields: vec![],
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
        services: BTreeMap::new(),
        sources: strings(&["https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/"]),
    }
}

/// Slack Web API with a user token: sesame acts as the person, not as a bot.
/// Slack's OAuth (https://docs.slack.dev/authentication/installing-with-oauth):
/// user scopes go in `user_scope`, the user token comes back under
/// `authed_user`, the redirect URL must be https, and a failed call is often
/// HTTP 200 with `"ok": false`. PKCE is off: Slack accepts it only once the
/// app opts in, which only Slack support can undo
/// (https://docs.slack.dev/authentication/using-pkce).
fn slack() -> Provider {
    Provider {
        about: "Slack Web API, as yourself (user token)".into(),
        auth_url: "https://slack.com/oauth/v2/authorize".into(),
        token_url: "https://slack.com/api/oauth.v2.access".into(),
        refresh_url: None,
        api_base: "https://slack.com/api".into(),
        hosts: strings(&["slack.com"]),
        scopes: strings(&[
            "channels:read",
            "groups:read",
            "im:read",
            "mpim:read",
            "channels:history",
            "groups:history",
            "im:history",
            "mpim:history",
            "chat:write",
            "users:read",
        ]),
        scope_param: "user_scope".into(),
        scope_separator: ",".into(),
        auth_params: BTreeMap::new(),
        pkce: false,
        token_body: TokenBody::Form,
        token_path: "/authed_user".into(),
        client_auth: ClientAuth::Body,
        api_headers: BTreeMap::new(),
        resources_url: None,
        site_name_field: Some("/team/name".into()),
        redirect: Redirect::HttpsPaste,
        redirect_port: Some(8751),
        code_seconds: None,
        redirect_host: RedirectHost::Localhost,
        device_url: None,
        // https://docs.slack.dev/reference/methods/auth.test: who the token is,
        // also for a pasted one.
        identity_url: Some("https://slack.com/api/auth.test".into()),
        identity_field: Some("user".into()),
        identity_body: None,
        // A failed call is HTTP 200 with `"ok": false` and an `error` code.
        error_fields: strings(&["error"]),
        setup: vec![
            step(
                "Create a Slack app",
                Some("https://api.slack.com/apps"),
                "\
Click Create New App, choose From scratch, enter an App Name (e.g. \"sesame\") and pick the
workspace you will sign in to, then click Create App. The app's page opens with a left menu.",
            ),
            step(
                "Add the User Token Scopes (left menu: OAuth & Permissions)",
                None,
                "\
Under Scopes > User Token Scopes (not Bot Token Scopes: sesame acts as you), click
Add an OAuth Scope for each one sesame asks for: {scopes}",
            ),
            step(
                "Add the redirect URL (left menu: OAuth & Permissions)",
                None,
                "\
Under Redirect URLs click Add New Redirect URL, enter {callback}, click Add, then Save URLs.
Slack takes only https redirect URLs, so nothing listens there: at login the browser ends on a
page it cannot open, and you paste that page's address into the terminal.
If the console refuses this URL, sign in with a pasted token instead, then go to the last step:
on the same page click Install to Workspace and Allow, copy the User OAuth Token (it starts
with xoxp-), and run `sesame login slack --token` in your own terminal; it asks for the token
with hidden input.",
            ),
            step(
                "Copy the client ID and secret (left menu: Basic Information)",
                None,
                "Under App Credentials: the Client ID, and the Client Secret (click Show). Keep the page open for the next step.",
            ),
        ],
        services: BTreeMap::new(),
        sources: strings(&[
            "https://docs.slack.dev/authentication/installing-with-oauth",
            "https://docs.slack.dev/authentication/using-pkce",
        ]),
    }
}

/// Notion's public integration: no scopes (the person picks the pages on the
/// consent page), HTTP Basic at the token endpoint, and a `Notion-Version` on
/// every API request. Steps from https://developers.notion.com/docs/authorization.
fn notion() -> Provider {
    Provider {
        about: "Notion (public integration OAuth)".into(),
        auth_url: "https://api.notion.com/v1/oauth/authorize".into(),
        token_url: "https://api.notion.com/v1/oauth/token".into(),
        refresh_url: None,
        api_base: "https://api.notion.com/v1".into(),
        hosts: strings(&["api.notion.com"]),
        scopes: Vec::new(),
        scope_param: "scope".into(),
        scope_separator: " ".into(),
        auth_params: params(&[("owner", "user")]),
        pkce: true,
        token_body: TokenBody::Json,
        token_path: String::new(),
        client_auth: ClientAuth::Basic,
        api_headers: params(&[("Notion-Version", "2026-03-11")]),
        resources_url: None,
        site_name_field: Some("workspace_name".into()),
        redirect: Redirect::Loopback,
        // Notion allows http only for localhost, and matches the port and path exactly.
        redirect_port: Some(8750),
        code_seconds: None,
        redirect_host: RedirectHost::Localhost,
        device_url: None,
        identity_url: None,
        identity_field: None,
        identity_body: None,
        error_fields: vec![],
        setup: vec![
            step(
                "Create an OAuth (public) integration in Notion's developer portal",
                Some("https://app.notion.com/developers/connections"),
                "\
Sign in with your Notion account and create a new OAuth integration (a public one, not internal).
Fill in the form with a name (e.g. \"sesame\"); for the installation scope, pick Any workspace,
or the workspaces you will use: it cannot be changed after creation.",
            ),
            step(
                "Set the redirect URI (the form's OAuth configuration section)",
                None,
                "\
Redirect URI: {callback}
It must match exactly: keep http, localhost (not 127.0.0.1) and the port. Save the integration.",
            ),
            step(
                "Copy the client ID and secret (the integration's Configuration tab)",
                None,
                "\
The Configuration tab shows the OAuth client ID and client secret. Keep it open for the next step.
Notion has no scopes: at login, the consent page asks which pages and databases sesame may reach.
To change them later, log in again, or share a page with the integration from Notion.",
            ),
        ],
        services: BTreeMap::new(),
        sources: strings(&["https://developers.notion.com/docs/authorization"]),
    }
}

/// A Figma OAuth app: HTTP Basic at the token endpoint, refresh at its own
/// endpoint (whose answer has no new refresh token), and an authorization code
/// that lasts 30 seconds. Steps and endpoints from
/// https://developers.figma.com/docs/rest-api/oauth-apps/ and scopes from
/// https://developers.figma.com/docs/rest-api/scopes/.
fn figma() -> Provider {
    Provider {
        about: "Figma REST API (OAuth app)".into(),
        auth_url: "https://www.figma.com/oauth".into(),
        token_url: "https://api.figma.com/v1/oauth/token".into(),
        refresh_url: Some("https://api.figma.com/v1/oauth/refresh".into()),
        api_base: "https://api.figma.com/v1".into(),
        hosts: strings(&["api.figma.com"]),
        scopes: strings(&[
            "current_user:read",
            "file_content:read",
            "file_comments:read",
        ]),
        scope_param: "scope".into(),
        scope_separator: " ".into(),
        auth_params: BTreeMap::new(),
        pkce: true,
        token_body: TokenBody::Form,
        token_path: String::new(),
        client_auth: ClientAuth::Basic,
        api_headers: BTreeMap::new(),
        resources_url: None,
        site_name_field: None,
        redirect: Redirect::Loopback,
        // Figma accepts only registered redirect URLs, so the port is fixed.
        redirect_port: Some(8753),
        code_seconds: Some(30),
        redirect_host: RedirectHost::Localhost,
        device_url: None,
        identity_url: Some("https://api.figma.com/v1/me".into()),
        identity_field: Some("email".into()),
        identity_body: None,
        error_fields: vec![],
        setup: vec![
            step(
                "Create an OAuth app (My Apps on Figma's developer site)",
                Some("https://www.figma.com/developers/apps"),
                "\
Sign in to Figma, then click Create a new app in the upper-right corner.
Give it a name (e.g. \"sesame\") and pick the team or organization that owns it.",
            ),
            step(
                "Add the redirect URL (the app's OAuth credentials page)",
                None,
                "\
Redirect URL: {callback}
Figma exchanges a code only for a registered redirect URL: keep http, localhost and the port.",
            ),
            step(
                "Pick the scopes",
                None,
                "\
Select the scopes sesame asks for at login: {scopes}
(Add others, e.g. file_comments:write, if you will ask for them with `sesame login figma --scope`.)",
            ),
            step(
                "Copy the client ID and secret, and decide who may sign in",
                None,
                "\
The OAuth credentials page shows the Client ID and Client secret; keep it open for the next step.
A new app is a Draft: only you and the plan's admins can authorize it. For your team or
organization to use it, publish it as Private (no review by Figma); Public needs Figma's review.",
            ),
        ],
        services: BTreeMap::new(),
        sources: strings(&["https://developers.figma.com/docs/rest-api/oauth-apps/", "https://developers.figma.com/docs/rest-api/scopes/"]),
    }
}

/// Linear: GraphQL only, at `/graphql`. Scopes are comma-separated; the access
/// token lasts 24 hours and each refresh hands out a new refresh token.
/// https://linear.app/developers/oauth-2-0-authentication
fn linear() -> Provider {
    Provider {
        about: "Linear (GraphQL API)".into(),
        auth_url: "https://linear.app/oauth/authorize".into(),
        token_url: "https://api.linear.app/oauth/token".into(),
        refresh_url: None,
        api_base: "https://api.linear.app".into(),
        hosts: strings(&["api.linear.app"]),
        scopes: strings(&["read", "write"]),
        scope_param: "scope".into(),
        scope_separator: ",".into(),
        auth_params: BTreeMap::new(),
        pkce: true,
        token_body: TokenBody::Form,
        token_path: String::new(),
        client_auth: ClientAuth::Body,
        api_headers: BTreeMap::new(),
        resources_url: None,
        site_name_field: None,
        redirect: Redirect::Loopback,
        // Linear documents no rule for the callback, so it is matched as registered.
        redirect_port: Some(8752),
        code_seconds: None,
        redirect_host: RedirectHost::Localhost,
        device_url: None,
        identity_url: Some("https://api.linear.app/graphql".into()),
        identity_field: Some("/data/viewer/name".into()),
        identity_body: Some(serde_json::json!({"query": "{ viewer { name } }"})),
        // A GraphQL error comes back as 200 with `errors`.
        error_fields: strings(&["errors"]),
        setup: vec![
            step(
                "Create an OAuth application in Linear (Settings > API > OAuth applications)",
                Some("https://linear.app/settings/api/applications/new"),
                "\
Sign in to the Linear workspace sesame should reach; every admin of that workspace can see the app.
- Application name: anything, e.g. \"sesame\"; people see it when they approve access.
- Callback URLs: {callback}
  It must match exactly, so do not change localhost or the port.
Click Create.",
            ),
            step(
                "Copy the client ID and secret",
                None,
                "\
The application's page shows the Client ID and the Client secret. Keep it open for the next step.
The scopes sesame asks for at login: {scopes} (they are asked for at login, not set on this page).",
            ),
        ],
        services: BTreeMap::new(),
        sources: strings(&["https://linear.app/developers/oauth-2-0-authentication"]),
    }
}
