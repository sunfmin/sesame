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
sesame login github                          # device flow: prints a code to enter on github.com/login/device
sesame api github /user
sesame api github /graphql -d '{"query":"{ viewer { login } }"}'
sesame api jira /rest/api/3/issue -d @issue.json      # -d implies POST; -X, -H, -i as in curl
sesame api notion /search -d '{}'             # Notion-Version is sent for you; -H replaces it
sesame api figma /me
sesame api figma /files/<key>
sesame api linear /graphql -d '{"query":"{ viewer { id name } }"}'   # GraphQL `errors` exit non-zero
curl -H "Authorization: Bearer $(sesame token jira)" ...
sesame providers                              # who you are signed in to
sesame logout jira                            # forgets the local token only
```

## How it works

- **Provider** = one OAuth realm: one login, one token. The built-ins (figma, github, google,
  jira, linear, notion) are defined in the code, [`src/providers/built_in.rs`](src/providers/built_in.rs).
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

  Fields cover how providers differ, so none needs code of its own: no
  `--scope` means the authorization URL has no `scope`; `--client-auth basic`
  sends the client as HTTP Basic instead of in the body; `--api-header
  'Name: value'` goes on every `sesame api` request (a `-H` of that name
  replaces it); `--site-name-field` names the token response's field that
  `sesame providers` shows as the site (Notion's `workspace_name`);
  `--refresh-url` sends refreshes to their own endpoint (Figma's
  `/v1/oauth/refresh`; without it, the token endpoint); `--code-seconds`
  says how long the authorization code lasts (Figma: 30), so login asks for
  the pasted address within that time and a refused exchange says the code
  most likely expired.

  A built-in provider's fields you did not `set` follow each new version of
  sesame. Among the fields: how the scopes are joined in the authorization
  URL (`--scope-separator ,` for Linear), and which fields of a 2xx JSON answer
  still mean failure (`--error-field errors` for GraphQL).
  `sesame provider add --help` lists every field; `add` and `set`
  refuse an invalid value before writing anything.
- **Login** is the authorization-code flow with PKCE and a loopback redirect
  (`http://localhost:<port>/callback`, or `127.0.0.1` for a provider whose
  `redirect_host` says so). On a remote machine (SSH), open the printed URL
  anywhere and paste the address the browser ends on back into the terminal.
  A provider with a `device_url` (github) uses the device flow instead: login
  prints a code to enter on the provider's page, from any machine, and needs no
  client secret; `sesame login <provider> --browser` takes the loopback redirect.
  A provider with an `identity_url` records who signed in, shown by `sesame providers`.
- **Secrets** (clients and tokens) and provider definitions are stored **in plaintext** in one SQLite
  database, `~/.config/sesame/sesame.db` (`$SESAME_CONFIG_DIR/sesame.db` when
  set), protected only by file permissions, as gcloud does: the file is 0600,
  the directory 0700. Do not put `~/.config/sesame` in a dotfiles repo or a
  synced folder.
- **`logout`** deletes the local token only; to revoke it, remove the app's
  access on the provider's side (Google account permissions, Atlassian
  connected apps, Notion's Settings > Connections, GitHub's Settings > Applications).
- **`api`** sends the token only to the provider's `hosts`; a 401 triggers one
  refresh and retry. It exits non-zero on a non-2xx status, and on a 2xx whose
  JSON carries one of the provider's `error_fields` not empty.

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
