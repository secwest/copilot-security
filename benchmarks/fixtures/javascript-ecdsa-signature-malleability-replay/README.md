# ECDSA signature-malleability replay fixture

This fixture models a settlement webhook that verifies an ECDSA P-256
signature over the exact raw event, enforces timestamp freshness, validates the
event, and atomically rejects a previously consumed replay key.

The replay key is nevertheless the SHA-256 digest of the DER signature bytes.
For every valid ECDSA `(r, s)` signature, `(r, n - s)` is a distinct valid
signature for the same message. An attacker can transform one captured fresh
settlement signature into its valid twin, obtain a different replay key, and
credit the same signed event twice without the private key or a signature
forgery.
