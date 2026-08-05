# Go constructor-field-write object deletion

The handler injects one of two repository implementations into an imported
service. Its constructor creates an empty service, aliases its pointer, and
writes a nested layer containing the selected interface implementation. The
deterministic witness proves that the attacker-selected object reaches only the
selected repository deletion.
