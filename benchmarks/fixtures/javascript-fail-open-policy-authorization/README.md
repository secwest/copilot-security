# Fail-open policy authorization fixture

The signing-key export route initializes its authorization decision to allow.
An explicit policy denial is enforced, but a policy-service exception leaves
the permissive default unchanged and a malformed truthy decision also passes.
An authenticated low-privilege caller can therefore export an attacker-selected
keyring whenever the external authorization decision fails.
