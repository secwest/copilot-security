# Lifetime-safe asynchronous audit

This control uses the same asynchronous administrator export and fixed-size
session pool. A C11 lock serializes slot, pending-operation, and lifetime state.
Starting an audit gives the operation its own reference. Closing a session marks
it closed, cancels pending work while holding the lock, releases both operation
and owner references, and reuses the slot only after the final reference ends.

If completion claims the operation first, its retained reference prevents slot
reuse until delivery returns. If close wins, completion observes no pending
operation. An unprivileged client therefore cannot redirect the old privileged
operation under either sequential or concurrent scheduling.
