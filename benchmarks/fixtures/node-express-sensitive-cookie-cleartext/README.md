# Cleartext-capable Express session cookie

The production source registers a literal Express 5 session route, creates a
short-lived authentication token with the official jsonwebtoken package, and
places it in a `session` response cookie. The cookie keeps `httpOnly` and
SameSite protection but explicitly disables `secure`, so its attributes permit
the browser to attach it to an unencrypted HTTP request.

`examples/witness.mjs` is an offline, in-memory serialization boundary witness.
It starts no Express server or listener, sends no network request, and reads no
credential or signing key. It demonstrates only that the modeled attributes do
not restrict the inert cookie to HTTPS; deployment reachability, interception,
and use of a disclosed value remain separate proof obligations.
