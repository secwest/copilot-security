# WebAuthn credential-to-account misbinding

The server verifies a fresh challenge, the exact RP ID and origin, and a valid
P-256 assertion signature. It nevertheless accepts any registered credential
and creates the session for the attacker-supplied username. An attacker starts
a login for a victim, substitutes the attacker's own credential, signs the
victim challenge legitimately, and receives a victim session.

The defect is the missing binding between the requested account, the challenge
transaction, the allowed credential set, the credential owner, and the final
session identity. It is not a missing-signature or missing-origin-check case.
