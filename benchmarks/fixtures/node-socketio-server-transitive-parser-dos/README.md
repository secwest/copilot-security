# Socket.IO server with vulnerable transitive parser

This fixture exposes a Socket.IO 4.8.3 Server on a listening HTTP server. Its npm lock resolves the parent's `socket.io-parser: ~4.2.4` dependency to affected 4.2.6. A remote Engine.IO client can send the zero-attachment binary-event packet and cause the per-connection decoder to retain every later binary frame until teardown.
