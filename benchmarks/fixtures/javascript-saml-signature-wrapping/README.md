# SAML signed-assertion identity misbinding

The service provider validates a one-time authentication request, the exact
destination, a pinned identity-provider issuer, the assertion audience and
recipient, and an RSA-SHA256 signature over the assertion selected by the
signature reference. It then creates the application session from the first
assertion in the response rather than the assertion whose signature it
verified.

An attacker obtains a valid assertion for their own account, inserts an
unsigned administrator assertion before it, and leaves the valid signature and
reference untouched. Cryptographic verification succeeds over the attacker's
legitimate assertion, but the application installs the unsigned administrator
identity. The defect is signed-node-to-consumed-node misbinding, not an absent
signature check.
