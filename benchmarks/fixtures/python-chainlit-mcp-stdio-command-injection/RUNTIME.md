# Runtime witness

The bounded witness is run with Python 3.12.3 against the exact package pins in
the paired requirements files:

- Chainlit 2.11.1: the pure validator parses a fixed `npx` command into an
  executable and inert argument vector. Nothing is launched.
- Chainlit 2.12.0: the legacy validator is absent and the request model rejects
  the removed client-selected stdio command fields.

This is package-behavior evidence, not proof that an application is deployed,
network-reachable, anonymous, or able to produce a particular process effect.
