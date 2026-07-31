# Cross-site WebSocket hijacking fixture

This fixture models a cookie-authenticated WebSocket endpoint that accepts an
upgrade without authorizing the browser-supplied `Origin`. An attacker page can
therefore open the socket with the victim's `SameSite=None` session cookie,
request account API keys, read them through the bidirectional channel, and use
the disclosed control-plane credential.
