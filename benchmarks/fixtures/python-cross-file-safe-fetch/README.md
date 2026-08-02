# Python cross-file fixed-destination preview

The Flask route passes an untrusted asset label across the same relative-import
boundary. The HTTP client accepts only labels in a server-owned map of complete
fixed URLs and disables redirects, so the caller cannot select a host, scheme,
port, or redirect destination. Response time and decoded body size are bounded.
