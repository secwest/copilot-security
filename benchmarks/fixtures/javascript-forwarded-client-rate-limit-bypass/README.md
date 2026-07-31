# Forwarded-client rate-limit bypass fixture

This recovery endpoint runs behind a trusted ingress that appends the actual
client address to any incoming `X-Forwarded-For` value. The application instead
uses the leftmost, attacker-controlled value as its rate-limit identity. One
remote client can rotate a spoofed first address across requests and submit the
correct recovery code after the intended three-attempt limit, replacing the
victim's password without controlling another network source.
