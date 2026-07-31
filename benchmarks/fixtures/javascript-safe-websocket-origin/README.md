# Exact WebSocket Origin authorization fixture

This control accepts cookie-authenticated WebSocket upgrades only from one exact
trusted portal origin. It rejects sibling, suffix-lookalike, opaque, scheme, and
port variants before reading the session or registering a message handler, while
the legitimate portal can still request its account API keys.
