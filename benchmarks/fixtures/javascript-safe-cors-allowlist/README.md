# Exact credentialed CORS origin allowlist

The API permits credentialed reads only from an exact deployment-configured
portal origin. Attacker-controlled sibling, suffix-lookalike, opaque `null`, and
missing origins are rejected before authentication or secret retrieval, while
the legitimate portal retains access.
