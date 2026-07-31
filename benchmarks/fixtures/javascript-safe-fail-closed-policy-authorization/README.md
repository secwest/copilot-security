# Fail-closed policy authorization fixture

The signing-key export route begins without an authorization decision. A policy
exception returns an unavailable response, and only the exact boolean `true`
decision can reach the protected export. Explicit deny and malformed decisions
remain forbidden while legitimate authorized access still works.
