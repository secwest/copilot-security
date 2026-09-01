# Credentialed CORS origin reflection

This fixture models an Express account route protected by `express-session`.
The official `cors` middleware enables credentials and reflects every request
origin, so browser JavaScript from an attacker-selected origin can read the
session-derived response when the victim's cookie policy permits credentials.

The witness invokes the real `cors` middleware with in-memory request and
response objects. It starts no server or listener, sends no request, and uses
no real session, cookie, credential, or account data.
