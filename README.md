# sesame

Sign in to SaaS APIs that have no CLI of their own, from the terminal, and call
their REST APIs with the stored token.

```sh
sesame setup google                          # first time: how to register the OAuth app
sesame client google --client-id <id>        # once: the OAuth app to sign in with (secret is prompted)
sesame login google                          # opens the provider's OAuth page; token goes to ~/.config/sesame/sesame.db
sesame api google /drive/v3/files            # GET, token attached, refreshed when it expires
sesame api google https://docs.googleapis.com/v1/documents/<id>
sesame api google '/youtube/v3/channels?part=snippet&mine=true'
sesame api jira /rest/api/3/myself
sesame api jira /rest/api/3/issue -d @issue.json      # -d implies POST; -X, -H, -i as in curl
sesame api slack /conversations.list                  # as yourself, with a Slack user token
sesame api slack /chat.postMessage -d '{"channel":"C…","text":"hi"}'
sesame login slack --token                            # or store a token you copied (hidden input)
curl -H "Authorization: Bearer $(sesame token jira)" ...
sesame providers                              # who you are signed in to
sesame logout jira                            # forgets the local token only
```

## How it works

- **Provider** = one OAuth realm: one login, one token. The built-ins (google,
  jira, slack) are defined in the code, [`src/providers/built_in.rs`](src/providers/built_in.rs).
  Your own providers, and your changes to a built-in one, are stored in
  `sesame.db` and managed with commands; there is no config file to edit:

  ```sh
  sesame provider add acme --auth-url https://acme.example/authorize \
      --token-url https://acme.example/token --api-base https://api.acme.example \
      --host api.acme.example --scope read --scope write
  sesame provider set google --scope openid --scope email   # only the changed fields are stored
  sesame provider show google        # the definition in force, as JSON, each field `built-in` or `user`
  sesame provider rm google          # back to the built-in definition (or removes one you added)
  ```

  A built-in provider's fields you did not `set` follow each new version of
  sesame. `sesame provider add --help` lists every field; `add` and `set`
  refuse an invalid value before writing anything.
- **Login** is the authorization-code flow with PKCE and a loopback redirect
  (`http://localhost:<port>/callback`). On a remote machine (SSH), open the
  printed URL anywhere and paste the address the browser ends on back into the
  terminal. A provider that takes only https callbacks (`--redirect https-paste`,
  as slack) uses `https://localhost:<redirect-port>/callback`: nothing listens
  there, the browser says it cannot open the page, and you paste its address.
  The fields `scope_param`, `pkce`, `token_path`, `account_path` and `ok_field`
  describe the rest of a provider's OAuth dialect (`sesame provider add --help`).
- **`login --token`** (or `--token-stdin`) stores a token you got another way,
  such as a Slack app's User OAuth Token; it has no refresh, and `sesame
  providers` marks it `pasted token`.
- **Secrets** (clients and tokens) and provider definitions are stored **in plaintext** in one SQLite
  database, `~/.config/sesame/sesame.db` (`$SESAME_CONFIG_DIR/sesame.db` when
  set), protected only by file permissions, as gcloud does: the file is 0600,
  the directory 0700. Do not put `~/.config/sesame` in a dotfiles repo or a
  synced folder.
- **`logout`** deletes the local token only; to revoke it, remove the app's
  access on the provider's side (Google account permissions, Atlassian
  connected apps, the Slack app's page).
- **`api`** sends the token only to the provider's `hosts`; a 401 triggers one
  refresh and retry. With an `ok_field` (slack: `ok`), a JSON answer whose field
  is `false` exits non-zero even on HTTP 200.

## Registering the OAuth apps

Each user (or you, once, for everyone) needs an OAuth client per provider.
`sesame setup <provider>` prints the steps, from creating the app on the
provider's console to the first `sesame api` call; `sesame providers` says
which providers still need one. The steps are part of each provider's
definition, so a provider you add can carry its own:
`sesame provider set acme --setup-step '{"title": "Register the app", "page": "https://acme.example/apps", "details": "Callback URL: {callback}; scopes: {scopes}"}'`
(repeatable, in order; `{callback}` and `{scopes}` are filled in).

## Development

`./gate.sh` — fmt, clippy, tests. `tests/e2e.rs` runs the whole flow against a
fake provider on 127.0.0.1.
