# Flask inverted static-allowlist open redirect

This fixture uses an immutable, server-owned tuple but reverses the membership
test. An attacker-selected absolute URL is redirected precisely when it is not
in the allowlist. The witness uses Flask's in-process test client, disables
redirect following, and performs no external request.
