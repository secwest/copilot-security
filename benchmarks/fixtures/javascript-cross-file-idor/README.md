# Cross-file invoice object authorization

Every request has an authenticated customer identity, but the repository
wrapper ignores it and loads the invoice using only the request-controlled
invoice identifier. An authenticated customer can therefore retrieve another
customer's invoice when its identifier is known.

This fixture is intentionally vulnerable. The paired
`javascript-cross-file-safe-authorization` fixture binds the same object
identifier to the authenticated customer in the repository query.
