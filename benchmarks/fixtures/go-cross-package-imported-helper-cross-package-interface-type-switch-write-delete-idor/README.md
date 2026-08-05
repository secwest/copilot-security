# Go imported helper cross-package interface type-switch deletion

The imported parent helper creates a value layer containing a pointer holder,
copies the value three times, and converts its repository to an interface
declared in a separate package. The source uses named parameters, a named
result, and explicit import aliases; the target uses unnamed parameters and
its imports' package names. Canonical type identities prove the interfaces are
assignable despite those spelling differences. Every type-switch arm writes
the selected primary repository through a different copy. The deterministic
witness proves that the attacker-selected object reaches the unscoped primary
deletion. The archive store is an exact dispatch decoy.
