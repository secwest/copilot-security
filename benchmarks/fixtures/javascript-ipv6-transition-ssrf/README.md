# IPv6-transition SSRF guard bypass

An HTTP query value crosses a local module boundary into `fetch`. The wrapper parses the URL but rejects only dotted-quad private IPv4 addresses. IPv4-mapped IPv6, NAT64, and 6to4 literals can therefore encode a private IPv4 destination without matching the guard.
