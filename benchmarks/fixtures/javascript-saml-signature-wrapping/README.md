# SAML signature-wrapping fixture

The response validator finds and verifies the assertion named by the signature
reference. It then returns the first assertion in the attacker-controlled
response rather than the assertion whose payload was verified. An unsigned
administrative assertion can therefore be placed before a correctly signed
ordinary-user assertion and become the session identity.
