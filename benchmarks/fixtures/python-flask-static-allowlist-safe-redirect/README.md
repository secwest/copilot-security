# Flask static-allowlist safe redirect

This topology-matched control redirects a request value only when it is a
literal member of an immutable, server-owned tuple. The hostile absolute URL
fails membership and reaches the fixed local fallback. The witness uses Flask's
in-process test client, disables redirect following, and performs no external
request.
