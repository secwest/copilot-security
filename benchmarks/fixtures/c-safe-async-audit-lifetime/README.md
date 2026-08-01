# Lifetime-safe asynchronous audit

This control uses the same asynchronous administrator export and fixed-size
session pool. Closing a session first cancels any pending operation that owns a
pointer to that exact object and only then releases the slot. Reuse by an
unprivileged client therefore cannot redirect the old privileged operation.

Production systems could instead transfer ownership to a ref-counted operation
or copy an independently owned delivery capability. The essential invariant is
the same: no deferred work may dereference an object after its lifetime ends.
