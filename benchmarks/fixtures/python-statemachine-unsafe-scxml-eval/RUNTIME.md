# Runtime

The benchmark and bounded witness use CPython 3.12.3 with
`python-statemachine==3.1.2`. `SCXMLProcessor()` is intentionally constructed
with the affected evaluator default, and `start()` enters the initial state
that runs the datamodel callback.
