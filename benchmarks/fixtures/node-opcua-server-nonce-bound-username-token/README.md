# Repaired node-opcua username token nonce binding

This source-identical control upgrades only `node-opcua` to 2.166.0. That
release validates the decrypted `UserNameIdentityToken` length and compares its
trailing nonce with the active session nonce before calling the application
`userManager`.

Install the locked dependencies and run `node witness.mjs`. The correct token
is accepted under nonce A, while replay under nonce B and the four-byte forged
blob are rejected before the manager is called. The witness uses an ephemeral
RSA key and does not open a listener.
