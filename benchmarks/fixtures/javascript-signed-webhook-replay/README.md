# Signed payment-webhook replay fixture

This fixture models a payment webhook that correctly verifies an HMAC-SHA-256
signature over the provider timestamp and exact raw body. It validates the
event shape before crediting the referenced merchant account.

The signed timestamp is never checked for freshness and the signed event ID is
never consumed. An attacker who captures one legitimate settlement callback
can replay the unchanged body and signature, causing the same financial event
to credit the account repeatedly even though forgery and body tampering fail.
