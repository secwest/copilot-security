# JWT algorithm and key-type confusion fixture

The access-token verifier lets the protected `alg` header select either RSA
signature verification or HMAC verification while reusing the same configured
RSA public-key bytes for both operations. Because the public key is available
to clients, an attacker can choose `HS256`, use those public bytes as the HMAC
secret, forge an administrative token, and export the signing audit.
