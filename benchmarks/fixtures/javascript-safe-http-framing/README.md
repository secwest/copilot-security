# Strict HTTP framing control

The gateway rejects ambiguous or unsupported HTTP message framing, requires one
canonical `Content-Length`, consumes exactly one complete request, and forwards
a structured request rather than the original connection bytes. Authorization
is applied to that same request object before the backend can act.
