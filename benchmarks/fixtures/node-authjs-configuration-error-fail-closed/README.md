# Repaired Auth.js configuration-error fail-closed

This source-identical control upgrades only `next-auth` to 5.0.0-beta.32. Its
session-response parser converts every non-successful Auth.js core response to
`null`, so the same bare `request.auth` check denies the request when server
configuration is invalid.

Install the locked dependencies and run `node examples/witness.mjs`. The synthetic
witness opens no listener and reports a null auth value with a denied response.
