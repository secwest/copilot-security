# Cross-file fixed-destination preview

The route passes an untrusted asset label across the same wrapper boundary.
The HTTP client accepts only labels present in a server-owned map of complete
fixed URLs and disables redirects, so the caller cannot select a host, scheme,
port, or redirect destination. Response time and decoded body size are bounded.
