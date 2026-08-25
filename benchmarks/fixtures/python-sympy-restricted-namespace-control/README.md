# Restricted SymPy namespace control

This topology-matched control retains the same Flask route, JSON expression,
relative wrapper, SymPy release, Python runtime, and witness. The parser call
adds a global dictionary whose `__builtins__` value is empty and a local
dictionary containing only the SymPy constructors required for ordinary
arithmetic and symbols.

The bounded witness confirms that `6 * 7` still evaluates to 42 while the
`__import__` capability probe is rejected before any external effect.
