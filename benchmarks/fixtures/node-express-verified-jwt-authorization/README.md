# Verified JWT authorization control

This source-matched Express 5 control verifies the Bearer token with an
explicit key, algorithm, issuer, and audience before using its `role` claim for
the same admin authorization decision.

The bounded witness demonstrates that the unsigned fixture token is rejected.
It starts no server, opens no listener, sends no request, and reads no real key,
token, credential, or protected data.
