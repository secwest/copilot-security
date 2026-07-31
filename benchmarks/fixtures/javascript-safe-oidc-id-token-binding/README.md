# OIDC ID-token client and nonce binding fixture

This paired control verifies an EdDSA ID token and binds its trusted issuer,
target-client audience, authorized party, lifetime, and nonce to a one-time
login transaction owned by the initiating browser session. A signed token for
a sibling client, a multi-audience token naming another authorized party, a
cross-session nonce, and replay are rejected before installing a principal.
