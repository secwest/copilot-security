# Runtime

The benchmark and bounded witness use CPython 3.12.3 with
`python-statemachine==3.2.0`. `SCXMLProcessor()` retains its repaired
`trusted=False` default. The restricted evaluator preserves `6 * 7` but rejects
the builtin capability probe with `InvalidDefinition`.
