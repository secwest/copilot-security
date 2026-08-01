# Signature-bound SAML assertion consumption

The service provider accepts one assertion with one unique ID, resolves the
signature reference to that exact assertion, verifies it with a pinned
identity-provider key and algorithm, validates issuer, audience, recipient,
lifetime, destination, and the one-time authentication request, and derives the
application identity and roles directly from the verified assertion object.

Adding an unsigned assertion, duplicating an assertion ID, changing the signed
assertion, replaying the response, or changing relying-party context fails
closed. A valid response still creates the identity-provider account's session.
