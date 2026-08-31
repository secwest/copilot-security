# Flask nested-Blueprint open redirect

This fixture models Flask's documented one-level Blueprint nesting shape. A
child Blueprint route reads `next`, receives only a root slash prefix, and is
made reachable through `parent.register_blueprint(child)` followed by
`app.register_blueprint(parent)`.

The witness uses Flask's in-process test client with redirect following
disabled. It inspects the emitted `Location` header and makes no request to the
attacker-selected origin.
