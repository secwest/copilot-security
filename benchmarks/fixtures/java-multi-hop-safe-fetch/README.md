# Java multi-hop safe fetch

The request value crosses the same two Spring service boundaries but is used
only as an exact key into fixed server-owned complete URIs. The transport also
requires a JDK client configured not to follow redirects before sending.
