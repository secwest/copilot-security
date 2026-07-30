# Pinned JWT key-origin control

The verifier rejects token-supplied remote key URLs, fetches keys only from the
configured issuer JWKS endpoint, requires one signing key with the expected
algorithm, type, curve, and use, and binds verified claims to issuer, audience,
lifetime, nonce, and session identity.
