# Vulnerable node-opcua server nonce cache

The server uses `node-opcua` 2.165.0 and reaches `OPCUAServer.start()`, exposing
the unauthenticated session path that records client nonces in a process-global
cache without eviction. The bounded witness inserts 50,001 nonempty unique
nonces and then replays the first; the vulnerable cache still retains it.

Install the fixture dependencies and run `node witness.mjs`. The witness does
not start a listener or attempt memory exhaustion.
