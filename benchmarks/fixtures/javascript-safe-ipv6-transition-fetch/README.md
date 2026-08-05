# Complete IPv6-transition address handling

The outbound wrapper canonicalizes all three modeled IPv6 transition families—IPv4-mapped IPv6, NAT64, and 6to4—before applying the private IPv4 deny guard. The same request value still reaches `fetch`, providing a strict negative control for the specialized incomplete-guard model.
