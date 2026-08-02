# Cross-file server-side request forgery

The unauthenticated preview route passes a caller-controlled absolute URL to a
separate HTTP client wrapper. The wrapper follows redirects, fetches the
attacker-selected destination from the application network, and returns a
strictly time- and size-bounded response body to the caller.
