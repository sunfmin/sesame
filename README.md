# sesame

Sign in to SaaS APIs that have no CLI of their own, from the terminal, and call
their REST APIs with the stored token.

```sh
sesame client google --client-id <id>        # once: the OAuth app to sign in with (secret is prompted)
sesame login google                          # opens the provider's OAuth page; token goes to the keychain
sesame api google /drive/v3/files            # GET, token attached, refreshed when it expires
sesame api google https://docs.googleapis.com/v1/documents/<id>
sesame api google '/youtube/v3/channels?part=snippet&mine=true'
sesame api jira /rest/api/3/myself
sesame api jira /rest/api/3/issue -d @issue.json      # -d implies POST; -X, -H, -i as in curl
curl -H "Authorization: Bearer $(sesame token jira)" ...
sesame providers                              # who you are signed in to
sesame logout jira
```

## How it works

- **Provider** = one OAuth realm: one login, one token. Built-ins are in
  [`src/providers.toml`](src/providers.toml); `~/.config/sesame/providers.toml`
  adds providers or replaces one by name, same format.
- **Login** is the authorization-code flow with PKCE and a loopback redirect
  (`http://localhost:<port>/callback`). On a remote machine (SSH), open the
  printed URL anywhere and paste the address the browser ends on back into the
  terminal.
- **Secrets** (client and token) live in the OS keychain, service `sesame`. With
  `SESAME_STORE_DIR` set they go to 0600 files there instead.
- **`api`** sends the token only to the provider's `hosts`; a 401 triggers one
  refresh and retry.

## Registering the OAuth apps

Each user (or you, once, for everyone) needs an OAuth client per provider:

- **Google**: Cloud Console → Credentials → OAuth client ID → *Desktop app*.
  Enable the Drive / Docs / YouTube Data APIs on the project.
- **Jira**: developer.atlassian.com → OAuth 2.0 integration, callback
  `http://localhost:8749/callback`, add the Jira API scopes.

## Development

`./gate.sh` — fmt, clippy, tests. `tests/e2e.rs` runs the whole flow against a
fake provider on 127.0.0.1.
