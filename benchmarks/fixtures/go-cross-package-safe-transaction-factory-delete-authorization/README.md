# Go authorized cross-package transaction-factory deletion

This control preserves the route, wrapper, SQL transaction, two imported and
aliased factory packages, leaf `BeginTx`, execution, commit, response, and
attacker-selected invoice ID. It adds only an account predicate derived from
request context. The offline driver proves that the victim survives while an
invoice owned by the authenticated account is still durably deleted.
