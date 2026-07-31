# GraphQL recovery-operation limits fixture

The gateway validates the parsed GraphQL execution plan before running any
resolver. Documents are bounded, aliases must be unique, and at most one
security-sensitive recovery mutation is accepted per request. Client budgets
are charged by planned resolver cost rather than HTTP request count. The
recovery service separately reserves a synchronous account-scoped failure slot
at the resolver boundary, so distributing attempts among clients cannot exceed
the three-guess budget. Benign batched public queries remain supported.
