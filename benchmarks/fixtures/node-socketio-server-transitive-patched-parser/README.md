# Socket.IO server with repaired transitive parser

This source- and parent-identical control exposes the same Socket.IO 4.8.3 Server. Its npm lock resolves the unchanged `socket.io-parser: ~4.2.4` dependency to repaired 4.2.7, which rejects the impossible zero-attachment binary-event packet before retaining parser state.
