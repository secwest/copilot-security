# DNS-rebinding SSRF fixture

The preview route validates every address returned by an initial DNS lookup,
but then passes the hostname to an HTTP client that resolves it again. An
attacker-controlled hostname can return a public address during validation and
the link-local cloud-metadata address during connection, exposing temporary
cloud credentials even though direct private addresses and redirects are
blocked.
