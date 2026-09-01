# Unverified JWT authorization fixture

This intentionally vulnerable Express 5 fixture reads a Bearer token, decodes
it with `jsonwebtoken.decode()`, and trusts the decoded `role` claim for an
admin authorization decision. Decoding parses attacker-authored bytes but does
not verify their signature, algorithm, issuer, or audience.

The bounded witness uses an inert unsigned fixture token and starts no server,
opens no listener, sends no request, and reads no real key, token, credential,
or protected data.
