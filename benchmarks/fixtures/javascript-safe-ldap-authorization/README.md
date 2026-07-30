# Safe LDAP group authorization fixture

This service resolves a canonical directory principal from a server-issued user
identifier, escapes every LDAP filter assertion special character using
RFC 4515 syntax, and checks membership in a fixed administrators group. The
attacker-controlled federated subject is never used as a directory principal.
The controls also preserve legitimate directory names containing a literal
asterisk rather than confusing them with LDAP's presence operator.
