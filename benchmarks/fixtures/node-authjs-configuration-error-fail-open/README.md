# Vulnerable Auth.js configuration-error fail-open

This fixture pins `next-auth` 5.0.0-beta.31 and uses an official Auth.js
middleware wrapper to protect a private route with a bare `request.auth`
truthiness check. The deliberately incomplete OIDC provider represents a
deployment configuration failure. On this release, the middleware callback
receives the server's JSON error body as a truthy auth object and permits the
unauthenticated request.

Install the locked dependencies and run `node examples/witness.mjs`. The witness uses a
synthetic request, opens no listener, performs no outbound request, and reports
the observed auth shape and allow/deny status.
