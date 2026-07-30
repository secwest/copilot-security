# Bound SAML assertion control

The validator requires one assertion matching the signature reference, verifies
that assertion's exact serialized payload, derives the session claims only by
parsing those verified bytes, and binds identifier, issuer, audience, recipient,
lifetime, and replay state before returning the identity.
