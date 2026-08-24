# Vulnerable nanoid non-secure negative-size boundary

This fixture carries a request-controlled numeric ID size through three
repository wrappers into `nanoid/non-secure` 5.1.15. Its decrement loop never
terminates for a negative size, so one request can occupy the Node.js event
loop indefinitely.

Run `npm ci --ignore-scripts && npm test`. The witness confines the call to a
child process, requires it to remain CPU-bound for the bounded timeout, and
kills it before returning success.
