# Repaired nanoid non-secure negative-size boundary

This source-identical control upgrades only nanoid to 5.1.16. Its non-secure
generator terminates immediately for a negative size instead of occupying the
Node.js event loop indefinitely.

Run `npm ci --ignore-scripts && npm test`; the bounded child must exit normally
and return the empty string.
