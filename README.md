# sesame

Sign in to SaaS APIs that have no CLI of their own, from the terminal, and call
their REST APIs with the stored token.

```sh
sesame setup google                          # first time: how to register the OAuth app
sesame client google --client-id <id>        # once: the OAuth app to sign in with (secret is prompted)
sesame login drive                           # opens Google's OAuth page; token goes to ~/.config/sesame/sesame.db
sesame api drive /files                      # GET https://www.googleapis.com/drive/v3/files, refreshed when it expires
sesame login gmail                           # adds Gmail's scopes to the same Google token
sesame api gmail /users/me/messages          # https://gmail.googleapis.com/gmail/v1/users/me/messages
sesame login calendar
sesame api calendar /calendars/primary/events
sesame api docs /documents/<id>
sesame api youtube '/channels?part=snippet&mine=true'
sesame api google https://www.googleapis.com/drive/v3/about?fields=user   # a full URL on the provider's hosts
sesame api jira /rest/api/3/myself
sesame login github                          # device flow: prints a code to enter on github.com/login/device
sesame api github /user
sesame api github /graphql -d '{"query":"{ viewer { login } }"}'
sesame api jira /rest/api/3/issue -d @issue.json      # -d implies POST; -X, -H, -i as in curl
sesame api slack /conversations.list                  # as yourself, with a Slack user token
sesame api slack /chat.postMessage -d '{"channel":"C…","text":"hi"}'
sesame login slack --token                            # or store a token you copied (hidden input)
sesame api notion /search -d '{}'             # Notion-Version is sent for you; -H replaces it
sesame api figma /me
sesame api figma /files/<key>
sesame api linear /graphql -d '{"query":"{ viewer { id name } }"}'   # GraphQL `errors` exit non-zero
sesame api hubspot /crm/v3/objects/contacts?limit=1
curl -H "Authorization: Bearer $(sesame token jira)" ...
sesame providers                              # who you are signed in to, and each service's access
sesame logout jira                            # forgets the local token only
```

## How it works

- **Provider** = one OAuth realm: one login, one token. The built-ins (figma, github, google,
  hubspot, jira, linear, notion, slack) are defined in the code, [`src/providers/built_in.rs`](src/providers/built_in.rs).
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
  refuse an invalid value before writing anything, and a fixed
  `--redirect-port` another provider already uses. Every field is one row of
  the field table in [`src/providers/fields.rs`](src/providers/fields.rs):
  its flag, type, check, and the question to answer about a platform to fill
  it in.
- **A platform sesame does not know**: `sesame provider guide` prints, for the
  AI doing it, the steps and one question per field to answer from the
  platform's docs. `sesame provider discover <domain or issuer>` reads its
  RFC 8414 or OpenID Connect metadata, if any, and prints a draft `sesame
  provider add`. Store each doc page with `--source`; `sesame provider export
  <name>` prints the `add` command that makes the definition again, to share
  it or turn it into a built-in. Once a provider you added is built in, only
  the fields where yours differ from the built-in count as your changes;
  your client and token stay.
- **Service** = one API of a provider, reached with the provider's client and
  token: Google's are `drive`, `docs`, `youtube`, `calendar` and `gmail`. A
  service has its own `api_base` and scopes, and its name is used like a
  provider's (the two share one namespace). `sesame login <service>` signs in
  to the provider asking for the scopes already granted plus the service's
  (Google adds `include_granted_scopes=true`), and the new token replaces the
  old one; `sesame login google` alone asks only for `openid email`. A call
  refused with a 403 for a missing scope says which `sesame login <service>`
  adds it. Add or change one with `--service`:

  ```sh
  sesame provider set acme --service 'name=billing,api-base=https://api.acme.example/billing,scope=billing.read'
  sesame provider set google --service 'name=gmail,scope=https://www.googleapis.com/auth/gmail.readonly'  # only the keys given change
  sesame provider set acme --drop-service billing
  ```

  `sesame provider show` lists each as `services.<name>`. A service with steps
  of its own (enabling its API in Google Cloud) adds them to `sesame setup`.
- **Login** is the authorization-code flow with PKCE and a loopback redirect
  (`http://localhost:<port>/callback`, or `127.0.0.1` for a provider whose
  `redirect_host` says so). On a remote machine (SSH), open the printed URL
  anywhere and paste the address the browser ends on back into the terminal.
  A provider with a `device_url` (github) uses the device flow instead: login
  prints a code to enter on the provider's page, from any machine, and needs no
  client secret; `sesame login <provider> --browser` takes the loopback redirect.
  A provider with an `identity_url` records who signed in, shown by `sesame providers`.
  A provider that takes only https callbacks (`--redirect https-paste`,
  as slack) uses `https://localhost:<redirect-port>/callback`: nothing listens
  there, the browser says it cannot open the page, and you paste its address.
  The fields `scope_param`, `pkce`, `token_path`, `site_name_field` and `error_fields`
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
  connected apps, Notion's Settings > Connections, GitHub's Settings > Applications,
  the Slack app's page).
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
