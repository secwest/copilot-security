# Flask nested-Blueprint application-factory open redirect

This fixture models Flask's documented application-factory and one-level
Blueprint nesting shapes together. A child Blueprint route reads `next`,
receives only a root slash prefix, and becomes reachable through
`parent.register_blueprint(child)` followed by a direct-suite
`app.register_blueprint(parent)` and `return app` inside `create_app`.

The witness constructs the application through the factory, uses Flask's
in-process test client with redirect following disabled, inspects the emitted
`Location` header, and makes no request to the attacker-selected origin.
