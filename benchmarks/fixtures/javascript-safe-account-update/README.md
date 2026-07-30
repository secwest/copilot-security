# Allowlisted self-service account update

Authenticated account owners may update only the two public profile fields
`displayName` and `timeZone`. Persisted account records also contain
`isAdmin`, `tenantId`, and `recoveryEmail`, but request-object keys are never
bound to those fields. Authorization middleware later trusts `isAdmin`.
