# Go imported helper value-copy pointer deletion

The imported parent helper creates a value layer containing a pointer holder,
copies the layer, injects the selected primary repository through the copied
value's shared holder, and returns the original value. The deterministic
witness proves that the attacker-selected object reaches the unscoped primary
deletion through exact shallow-copy identity. The unused archive store is a
dispatch decoy.
