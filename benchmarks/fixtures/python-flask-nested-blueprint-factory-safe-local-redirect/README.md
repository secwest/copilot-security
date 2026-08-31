# Flask nested-Blueprint application-factory fixed-local redirect

This topology-matched control retains the same application factory, child and
parent Blueprints, registration sequence, route, request value, and redirect
sink. It percent-encodes the untrusted value beneath the fixed non-root local
`/continue?next=` target, so the selected authority remains local.

The witness constructs the application through the factory, disables redirect
following, inspects only the emitted `Location`, and makes no external request.
