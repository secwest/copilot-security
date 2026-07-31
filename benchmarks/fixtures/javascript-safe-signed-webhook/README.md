# Replay-safe signed payment-webhook fixture

This fixture verifies the HMAC-SHA-256 signature over the exact raw body and
provider timestamp, rejects callbacks outside a five-minute freshness window,
strictly validates the settlement event, and atomically consumes its signed
event ID while applying the account credit.

A legitimate target event is applied once. Duplicate delivery returns the
existing balance without repeating the financial effect, while stale, future,
tampered, malformed, and incorrectly signed callbacks are rejected.
