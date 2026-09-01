# HTTPS-only Express session cookie

This topology-matched control is source-identical to the cleartext-capable
fixture except that its signed `session` cookie sets `secure: true`. A
conforming browser therefore restricts the cookie to encrypted HTTPS requests.

`examples/witness.mjs` is an offline, in-memory serialization boundary witness.
It starts no Express server or listener, sends no network request, and reads no
credential or signing key. It checks only that the `Secure` attribute is present
and excludes the modeled cookie from an HTTP request.
