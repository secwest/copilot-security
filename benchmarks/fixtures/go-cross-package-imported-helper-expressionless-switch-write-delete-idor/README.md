# Go imported helper expressionless-switch deletion

The imported parent helper creates a value layer containing a pointer holder,
copies the value three times, and writes the selected primary repository through
a different copy in each arm of an expressionless `switch` with a final
`default`. Every arm ends in an explicit unlabelled `break`, which is equivalent
to Go's implicit case termination. Every path therefore establishes the same
shared holder before the original value is returned. The deterministic witness
proves that the attacker-selected object reaches the unscoped primary deletion.
The archive store is an exact dispatch decoy.
