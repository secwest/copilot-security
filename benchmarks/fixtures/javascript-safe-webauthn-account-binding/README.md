# Transaction-bound WebAuthn account login

Login initiation creates a short-lived server transaction that binds one
challenge to the intended user and that user's allowed credential IDs. Login
completion loads only that transaction, requires the credential to be in the
allowlist and owned by the transaction user, verifies the exact RP ID, origin,
challenge, and P-256 signature, consumes the transaction once, and derives the
session identity from the bound credential owner.

Substituting another user's valid credential, changing the relying-party
context, using an expired transaction, or replaying a successful assertion
fails closed.
