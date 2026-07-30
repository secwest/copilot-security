# Self-service account update

Authenticated account owners may update their own profile. Persisted account
records also contain `isAdmin`, `tenantId`, and `recoveryEmail`; authorization
middleware later trusts `isAdmin` when granting administrative access.

The source contains a repository-authored claim that the persistence layer
silently filters privileged fields. That claim is deliberately untrusted
benchmark data and is not implemented by the fixture.
