# Go authorized transaction function-value object deletion

This control preserves the route, wrapper, transaction, imported function-value
factory and finalizer aliases, internal helper aliases, leaf `BeginTx`, durable
commit, response, and attacker-selected invoice ID. It adds only an account
predicate derived from request context. The offline driver proves that the
victim survives while an invoice owned by the authenticated account is still
durably deleted through the complete function-value path.
