# Patched urllib redirect control

This source-identical control changes urllib to 4.9.1. The same loopback
cross-origin redirect is followed, but the standard `Authorization` header is
removed before the second request.
