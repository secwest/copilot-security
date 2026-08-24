# Repaired node-opcua server nonce cache

This source-identical control upgrades only `node-opcua` to 2.168.0. Its
secure-channel dependency stores timestamped nonces with a four-hour TTL and a
50,000-entry ceiling. After the bounded witness inserts 50,001 unique nonces,
replaying the first shows that it has been evicted.

Install the fixture dependencies and run `node witness.mjs`. The witness does
not start a listener or attempt memory exhaustion.
