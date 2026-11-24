A token can be handed to `sesame api` and `sesame token` in the environment instead of read from the store, by whoever holds the login (another machine's `sesame token <service>`).

With `{const:TOKEN_PREFIX}<NAME>` set, where `<NAME>` is the service's or provider's name in upper case with `-` as `_` (`{const:TOKEN_PREFIX}GMAIL`, `{const:TOKEN_PREFIX}GOOGLE`), `sesame api` and `sesame token` use that access token instead of the store: nothing is read from or written to the store, and nothing is refreshed. The service's variable is used before its provider's.

When the provider refuses a handed token, sesame says so on stderr: its holder must hand a new one.

A provider that is not built in is defined by `{const:PROVIDERS_VAR}`, a JSON object of `sesame provider show` outputs by provider name (`{"acme": <sesame provider show acme>}`).
