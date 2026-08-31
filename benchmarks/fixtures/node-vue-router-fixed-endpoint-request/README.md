# Vue Router fixed-endpoint request control

This topology-matched control reads the same browser-controlled Vue Router
query value but percent-encodes it as one query parameter beneath a fixed API
endpoint. The value cannot alter the request origin or pathname.

Run `npm run witness` to check URL resolution without starting an application
or making a network request. The witness uses only fixed synthetic values.
