# Vulnerable Socket.IO parser zero-attachment boundary

This fixture carries a request-controlled Socket.IO packet through three
wrappers into a module-scope `socket.io-parser` 4.2.6 `Decoder`. A binary event
declaring zero attachments is emitted but leaves its reconstructor alive. Every
later binary frame on that persistent decoder is retained because a positive
buffer count can never equal the declared zero count.

Run `npm install --ignore-scripts && npm test` to retain a bounded 8 MiB of
distinct binary frames and verify the affected state invariant without
exhausting the process.
