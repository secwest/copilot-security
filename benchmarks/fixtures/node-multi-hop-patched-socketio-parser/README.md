# Patched Socket.IO parser zero-attachment boundary

This source-identical control upgrades only `socket.io-parser` from 4.2.6 to
4.2.7. The repaired decoder rejects binary events and acknowledgements that
declare fewer than one attachment, before emitting the packet or retaining a
reconstructor.

Run `npm install --ignore-scripts && npm test` to confirm that the same crafted
packet raises `Illegal attachments` and retains no binary frames.
