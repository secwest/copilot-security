# Safe ECDSA event-idempotency fixture

This fixture intentionally accepts either mathematically valid ECDSA signature
encoding for a settlement. It verifies the signature over the exact raw event,
enforces freshness, and validates the signed event before changing state.

Replay protection is bound to the signed semantic event ID rather than the
malleable signature bytes. The ledger atomically consumes that event ID with
the credit, so `(r, s)`, `(r, n - s)`, retransmission, and alternative valid
signatures for the same event all resolve to one protected operation.
