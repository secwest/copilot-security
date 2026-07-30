# JWT remote-key origin injection fixture

The verifier constrains `jku` to a trusted shared JWKS-service origin but accepts
any token-controlled tenant path on that service. An attacker can publish a key
under their own tenant, sign an otherwise policy-conformant administrative ID
token with it, and have the application treat the forged identity as trusted.
