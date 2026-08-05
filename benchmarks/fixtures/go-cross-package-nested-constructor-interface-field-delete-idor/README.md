# Go nested constructor-interface object deletion

The handler injects one of two repository implementations into an imported
service. Its constructor nests the selected implementation under a pointer layer
and initializes unrelated scalar fields. The deterministic witness proves that
the attacker-selected object reaches only the selected repository deletion.
