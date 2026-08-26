# Undici SOCKS5 cross-origin pool reuse

This fixture places a request-controlled preview URL before a credentialed
billing request on one shared official `Socks5ProxyAgent`. Undici 7.27.2 reuses
the pool created for the first origin, so the later request can reach the wrong
origin with its standard authorization header.

`witness.mjs` uses two ephemeral loopback HTTP origins, one loopback-only
SOCKS5 proxy, and one inert authorization marker. It contacts no external
endpoint and closes the agent and all three listeners in `finally`.
