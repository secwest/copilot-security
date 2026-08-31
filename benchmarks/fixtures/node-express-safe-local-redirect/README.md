# Express fixed-local redirect control

This topology-matched control registers the same literal Express 5 route and
reads the same query field. It percent-encodes the untrusted value beneath a
non-root, application-owned local prefix before calling `res.redirect`.

Run `npm run witness` to prove that the fixed synthetic input remains on the
application origin. The witness starts no server and makes no network request.
