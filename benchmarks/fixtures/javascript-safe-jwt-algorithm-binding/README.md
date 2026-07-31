# Pinned JWT algorithm and key-type control

The verifier pins `RS256` before key selection, converts only a configured
trusted key into a public-key object, requires the key type to be RSA, and uses
only asymmetric signature verification. It also binds issuer, audience,
subject, role, and expiry before the administrative export consumes claims.
