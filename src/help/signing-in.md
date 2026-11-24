A provider is signed in to by the person, in their own terminal; each of its services shares its one client and token.

## The client

Signing in takes an OAuth client (app) of the provider's. A provider with a `built-in client` (github) needs none. For one showing `no client`, `sesame setup <provider>` prints the steps to register one on the provider's site; walk the person through them. The person then stores it with `sesame client <provider> --client-id <id>`, which prompts for the client secret with hidden input.

## Logging in

The person runs `sesame login <service>` (or `<provider>`) and approves access in the browser themselves; a provider with a device endpoint (github) prints a code to enter on its page instead. A service (gmail, calendar, ...) shares its provider's client and token: logging in to it adds its scopes to the provider's token. Where the provider hands out tokens on its own app page, `sesame login <provider> --token` stores one the person pastes, with hidden input.

## Secrets stay out of the chat

Never ask for a client secret or a token in the chat. The person types it at sesame's own prompt in their terminal (`sesame client`, `sesame login --token`), which hides it.
