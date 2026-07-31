# OIDC ID-token client and nonce misbinding fixture

This fixture models an OpenID Connect relying party that verifies an EdDSA ID
token signature, the trusted issuer, expiration, and a one-time callback state.
It then installs the token subject without checking that the token was issued
to this client or that its nonce belongs to the initiating browser session.

An attacker can start a login in their own target-app session and submit a
still-valid victim ID token captured through a sibling client registered at the
same trusted issuer. The target accepts the wrong `aud`, conflicting `azp`, or
unbound nonce and authenticates the attacker-controlled session as the victim.
