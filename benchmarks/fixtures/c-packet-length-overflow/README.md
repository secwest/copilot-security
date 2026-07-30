# Attacker-length packet copy

The network service passes an unauthenticated login packet to
`handle_login_packet`. The first two packet bytes declare the username length.
The parser checks that the packet contains that many bytes, but it never checks
the declared length against the fixed 32-byte destination.

An attacker can therefore overwrite the adjacent `is_admin` byte before the
handler makes its authorization decision.
