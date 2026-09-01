# Browser postMessage wildcard sensitive-data disclosure

This fixture reads a bounded access-token value from browser `localStorage`
and sends it to the embedding parent window with the modern `postMessage`
options overload and wildcard `targetOrigin`.

Run `npm run witness` to execute the exact source with an in-memory browser
boundary. The synthetic parent is at an attacker origin and receives the
payload. The witness starts no browser, performs no network request, and does
not claim that a deployed receiver is attacker controlled.
