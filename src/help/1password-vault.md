With `{const:VAULT_VAR}=<vault>` in the environment, sesame keeps everything `sesame.db` would hold (clients, tokens, your provider fields) in that 1Password vault instead, signed in as a service account whose token is `OP_SERVICE_ACCOUNT_TOKEN`. Every machine given the same two variables uses the same logins. Unset, sesame uses `sesame.db`. Named but unusable (no token, a vault the account cannot read), sesame stops naming what is missing; it never falls back to `sesame.db`.

## Switching it on

1. Create a vault of its own, say `sesame`, not one another tool syncs two ways (such a sync adopts and rewrites items it did not make).
2. Create a service account with read and write on that vault only (1Password's Developer > Service Accounts, or `op service-account create sesame --vault sesame:read_items,write_items`), and copy its token, shown once.
3. Give a machine both variables from a secrets manager's profile, never a shell rc or a file.
4. Run `sesame store migrate` with both set, so the logins in `sesame.db` move to the vault instead of signing in again, then `sesame providers` to see them.

## What it holds

`sesame.<provider>` holds a provider's client and token, one field each, the secrets concealed (`op read op://<vault>/sesame.google/refresh_token`); `sesame-providers` holds your provider fields, one JSON field per provider. All are Secure Notes tagged `sesame`. Fields you add to an item yourself are kept; an item left with nothing (`logout` and `client --reset`) is archived, so it can be restored.

Each machine keeps an encrypted copy of the vault's sesame items in its config directory and answers from it however old it is: a call whose token is still valid makes no 1Password request. sesame reaches 1Password only before a refresh, for `sesame providers`, when there is no copy, and when a provider refuses the token the copy holds (it then retries once with the vault's, if that is another). So another machine's refresh, `client`, `provider set` or `logout` arrives at this machine's next refresh, `sesame providers` or refused call, never because time passed.

Every write reaches the vault in the command that makes it. One 1Password cannot take now (its rate limit, the network) waits on this machine, beside the copy: a refresh still answers its new token, with a warning, this machine uses that token meanwhile, and the next command that reaches 1Password writes it first; `client`, `login`, `provider set` and `logout` fail, saying it waits. `sesame providers` pushes what waits.

## Its budget, and one machine per provider

A service account may read 1000 times and write 100 times an hour, and the account makes 1000 requests a day in all. A refresh spends about 4 requests (a sync, then the write); calls in between spend none. 1Password has no lock across machines: where a provider's refresh hands out a new refresh token, two machines refreshing at once can leave one with a refresh token the provider already replaced. Let one machine refresh it (`sesame token <name> --min-life …`) and hand the token to the others (see [handed tokens](help:handed-token)).
