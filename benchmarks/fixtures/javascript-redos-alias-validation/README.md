# Catastrophic-backtracking alias validation fixture

An unauthenticated registration handler applies a nested-quantifier regular
expression directly to an attacker-controlled alias. A near-matching string of
`a` characters followed by one rejected character forces exponentially many
backtracking paths on the single JavaScript event-loop thread before the
request can be rejected.
