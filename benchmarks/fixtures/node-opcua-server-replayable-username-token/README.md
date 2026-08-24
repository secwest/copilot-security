# Vulnerable node-opcua username token nonce binding

The server uses `node-opcua` 2.165.2, configures an application `userManager`,
and reaches `OPCUAServer.start()`. Affected password extraction decrypts the
`UserNameIdentityToken` but does not compare its trailing nonce with the active
session nonce.

Install the locked dependencies and run `node witness.mjs`. The bounded witness
uses the real package authentication method and an ephemeral RSA key. It shows
that ciphertext created with nonce A is accepted again under nonce B and that a
four-byte forged blob reaches a deliberately empty-password-compatible manager.
It does not open a listener.
