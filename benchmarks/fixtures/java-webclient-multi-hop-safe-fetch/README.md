# Java WebClient multi-hop safe fetch

The request value crosses the same Spring controller and service boundaries but
is used only as an exact key into server-owned complete destinations. The
underlying JDK connector rejects redirects, and the reactive response is
released under a short timeout.
