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
sesame login github                          # no setup: sesame's built-in client, device flow (a code to enter on github.com/login/device)
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
sesame token jira --json                      # {"access_token": "…", "expires_at": <unix seconds or null>}
sesame token jira --json --min-life 1200      # refreshed first unless it lasts 20 more minutes
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
- **Built-in client**: a provider can ship a public client, a client id with no
  secret (`public_client_id`; github's is sesame's own OAuth App). Login uses it
  while you have stored no client of your own, so `sesame login github` works
  with no setup. Your client, once stored with `sesame client`, is used instead;
  `sesame client <provider> --reset` forgets it and goes back to the built-in one.
  `sesame providers` says which is used (`built-in client` or `your client`), and
  `sesame provider show` marks `public_client_id` with `in_use`. With a
  `device_url`, the built-in client signs in only through the device flow:
  GitHub's code exchange on the loopback redirect needs the secret, so `--browser`
  needs your own client. GitHub's built-in tokens do not expire (refreshing would
  need the secret).
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
  To keep them out of the disk and share them between machines instead, use
  a 1Password vault: see [Keeping logins in 1Password](#keeping-logins-in-1password-optional).
- **`logout`** deletes the local token only; to revoke it, remove the app's
  access on the provider's side (Google account permissions, Atlassian
  connected apps, Notion's Settings > Connections, GitHub's Settings > Applications,
  the Slack app's page).
- **`api`** sends the token only to the provider's `hosts`; a 401 triggers one
  refresh and retry. It exits non-zero on a non-2xx status, and on a 2xx whose
  JSON carries one of the provider's `error_fields` not empty.

- **`token`** prints a valid access token alone, refreshed if it expires within
  a minute. `--json` prints one JSON line instead,
  `{"access_token": "…", "expires_at": <unix seconds>}`, so whoever hands the
  token on knows when it expires; `expires_at` is `null` when sesame knows no
  expiry (a pasted token, a handed one, or a provider that gave none).

- **Handed token**: on a machine that should not hold the login, hand
  `sesame api` and `sesame token` an access token in the environment, one per
  provider or service: `SESAME_TOKEN_<NAME>`, the name in upper case with `-`
  as `_` (`SESAME_TOKEN_GMAIL`, `SESAME_TOKEN_GOOGLE`; a service's variable is
  used before its provider's). Nothing is read from or written to `sesame.db`,
  no client is needed and nothing is refreshed; a 401 exits non-zero saying the
  handed token was refused or has expired, and its holder must hand a new one.
  The rest is as with a stored token: it goes only to the provider's hosts, and
  the provider's `api_header`s and `error_fields` apply. A provider that is not
  built in is defined by `SESAME_PROVIDERS`, a JSON object of `sesame provider
  show` outputs by provider name. One machine holds the login and refreshes it,
  so no two rotate each other's refresh token away:

  ```sh
  # on the machine with the login
  token=$(sesame token gmail --min-life 1200)     # refreshed if it expires within 20 minutes
  # on the other, with no sesame.db
  SESAME_TOKEN_GMAIL=$token sesame api gmail /users/me/profile
  SESAME_PROVIDERS="{\"acme\": $(sesame provider show acme)}" SESAME_TOKEN_ACME=… sesame api acme /me
  ```

## Keeping logins in 1Password (optional)

With `SESAME_1PASSWORD_VAULT=<vault>` in the environment, sesame keeps
everything `sesame.db` would hold (clients, tokens, your provider fields) in
that 1Password vault instead, read and written by the 1Password CLI `op` as a
**service account**, whose token is `OP_SERVICE_ACCOUNT_TOKEN`. Every machine
with the same two variables uses the same logins; on disk there is only an
encrypted copy of the vault's sesame items (below) and an empty lock file,
`sesame.lock`. Unset, sesame uses
`sesame.db` as before. There is no config file: a machine opts in by its
environment, for example a `mytokens` profile carrying both.

Switching it on, end to end:

1. **A vault of its own** (see below why): in 1Password, create a vault, say
   `sesame` (`op vault create sesame`, signed in as yourself).
2. **A service account with read and write on that vault only**: in
   1Password's Developer > Service Accounts (or `op service-account create
   sesame --vault sesame:read_items,write_items`), give it no other vault, and
   copy its token, shown once.
3. **Both variables in mytokens**, never in a shell rc or a file:

   ```sh
   mytokens put sesame --set "SESAME_1PASSWORD_VAULT=sesame"
   mytokens put sesame --fields "OP_SERVICE_ACCOUNT_TOKEN"     # prompted: paste the service account's token
   ```

4. **Move what `sesame.db` holds into the vault**, so you keep your logins
   instead of signing in to every provider again:

   ```sh
   (eval "$(mytokens env sesame)"; sesame store migrate)
   (eval "$(mytokens env sesame)"; sesame providers)    # every login, now from the vault
   ```

   `store migrate` copies every client, token and provider field, one write per
   provider (and one for all provider fields), within the service account's
   write budget. It overwrites nothing: where the vault already holds something
   else for a provider, that is reported as a conflict, left as it is, and the
   command says how to settle it. A run cut short (the budget, an error) goes on
   where it stopped when run again; once all is copied it writes nothing. Only
   then is `sesame.db` renamed to `sesame.db.migrated-<date>`, not deleted: it
   prints how to go back (unset `SESAME_1PASSWORD_VAULT`, rename it back) and,
   since it still holds the secrets in plaintext, how to delete it once sesame
   works from the vault. Without `SESAME_1PASSWORD_VAULT` it refuses, saying
   what to set.

- The vault named but the token missing, `op` not on PATH, or a vault the
  service account cannot read: sesame stops with an error saying which. It
  never falls back to `sesame.db`.
- **The items.** `sesame.<provider>` holds that provider's client and token, one
  field each (`client_id`, `client_secret`, `access_token`, `refresh_token`,
  `expires_at`, `scope`, `resource_id`, `resource_name`, `account`, `pasted`),
  the secrets concealed: `op read op://<vault>/sesame.google/refresh_token`.
  `sesame-providers` holds your provider fields, one JSON field per provider.
  All are Secure Notes tagged `sesame`. Fields you add to an item yourself are
  kept. An item left with nothing (`logout` and `client --reset` of a provider)
  is archived, so it can be restored in 1Password.
- **Use a vault of its own**, one that is not in `mytokens onepassword list`:
  mytokens' two-way sync adopts and rewrites items it did not make.
- **The local copy.** Each machine keeps a copy of the whole store (clients,
  tokens with their refresh tokens, provider fields: the tables of
  `sesame.db`, plus each item's version) in `<config dir>/1password-copy`,
  encrypted (XChaCha20-Poly1305, the key derived from
  `OP_SERVICE_ACCOUNT_TOKEN`): without the token it reads as nothing, and with
  it the vault could be read anyway. sesame reads from the copy, so a call
  whose token is still valid makes **no** `op` call and takes milliseconds.
  Writes (`login`, `client`, `provider add/set/rm`, `logout`, a refresh) go
  to the vault first, then the copy. A copy that does not open (the token
  changed, the file damaged) is dropped and rebuilt from the vault.
- **How fresh the copy is.** Before refreshing a token sesame syncs: it lists
  the vault once and reads only the items whose version moved, so a token
  another machine already refreshed is used without refreshing again, and
  another machine's `client`, `provider set` or `logout` arrives too. It also
  syncs when the copy is an hour old (for tokens that never expire), on
  `sesame providers`, and when there is no copy. So a change made elsewhere
  reaches a machine within its token's life (an hour for Google), at most an
  hour.
- **The budget.** A service account may read 1000 times and write 100 times an
  hour, and the account makes 1000 requests a day in all (shared with
  mytokens' vault sync, `op service-account ratelimit`); each `op` call takes
  about a second. Measured against a real vault (sesame#4): a call with a
  valid token, 0.03 s and no request; a refreshing call, 3.6 s (a list, a
  read, a write) and 2 requests on the account's daily count. **Per day**, a
  machine spends about 2 requests per refresh: a provider with hour-long
  tokens used all day long is ~24 refreshes, ~50 requests; one whose token
  does not expire, at most 24 hourly syncs. Calls in between are free, however
  many. (Before the copy, every `sesame api` cost two reads: 500 calls a day
  would have spent the account's whole budget.) Secrets reach `op` only on
  its stdin and the token only in its environment, never on its command line.
- **One machine refreshes each provider.** Two processes on one machine take
  turns (the lock file), but 1Password has no lock across machines: where a
  provider's refresh hands out a new refresh token, two machines refreshing
  at once can leave one of them with a
  refresh token the provider has already replaced. Let one machine refresh it
  (`sesame token <name> --min-life …`) and hand the token to the others
  (`SESAME_TOKEN_<NAME>`, above), as without the vault.

## Registering the OAuth apps

github needs none: it has a built-in client. Elsewhere each user (or you, once,
for everyone) needs an OAuth client per provider; on github your own is optional.
`sesame setup <provider>` prints the steps, from creating the app on the
provider's console to the first `sesame api` call; `sesame providers` says
which providers still need one. The steps are part of each provider's
definition, so a provider you add can carry its own:
`sesame provider set acme --setup-step '{"title": "Register the app", "page": "https://acme.example/apps", "details": "Callback URL: {callback}; scopes: {scopes}"}'`
(repeatable, in order; `{callback}` and `{scopes}` are filled in).

## Development

`./gate.sh` — fmt, clippy, tests, and the `op` stand-in's truefit contract
(`truefit.toml`). `tests/e2e.rs` runs the whole flow against a fake provider on
127.0.0.1.
