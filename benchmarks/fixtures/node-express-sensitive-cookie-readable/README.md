# Browser-readable Express session cookie

The production source registers a literal Express 5 session route, creates a
short-lived authentication token with the official jsonwebtoken package, and
places it in a `__Host-session` response cookie. The cookie explicitly disables
`httpOnly`, so browser JavaScript can read the session value if script execution
occurs in the cookie's origin.

`examples/witness.mjs` is an offline, in-memory boundary witness. It starts no
Express server, sends no network request, reads no credential or signing key,
and creates no executable token. It demonstrates only whether the modeled
cookie would be included in the browser's `document.cookie` view.
