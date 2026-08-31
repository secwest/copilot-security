# Flask built-in `str` allowlist control

This topology-matched control passes the same Flask query value through the
live Python built-in `str(object)` conversion, but redirects it only when it is
an exact member of an immutable server-owned tuple. An attacker-selected URL
therefore reaches the fixed `/account` fallback. The witness disables redirect
following and performs no external request.
