# Vulnerable Echo encoded-separator fixture

This operational Echo 4.15.2 application places a wildcard GET route beneath
the middleware-protected `/admin` group, then mounts a broader static file
handler at `/` on the same server. The real-package witness writes one inert
marker beneath a test-owned temporary `admin` directory. A direct request is
denied, while an otherwise identical request containing `%2F` bypasses the
protected route and discloses the marker through the static handler.

The witness uses `httptest`, opens no listener, contacts no external service,
and removes its temporary directory automatically.
