# Browser postMessage fixed-origin control

This topology-matched control reads the same bounded access-token value and
sends the same payload to the same parent-window relationship. It changes only
the target origin from wildcard to the complete trusted portal origin.

Run `npm run witness` to prove in memory that the attacker-origin parent does
not receive the payload while the intended exact origin does. The witness
starts no browser and performs no network request.
