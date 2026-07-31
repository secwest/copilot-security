# DNS-pinned preview fixture

The preview route resolves an HTTPS hostname once, rejects the request unless
every returned address is an allowed public IPv4 address, and gives one approved
address to a transport that connects directly to it while preserving the
logical Host header and TLS server name. Redirects are disabled, so DNS cannot
change between validation and connection. Direct private, mixed, malformed,
IPv6, and empty answer sets fail closed while legitimate public previews still
work.
