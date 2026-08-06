# Node Mongoose multi-hop aggregate append lookup injection

A request-controlled stage array crosses three exact relative imports and reaches `Aggregate.append()` after a fixed initial pipeline. Later `exec()` consumes the mutated Aggregate, allowing attacker-selected `$lookup` and projection stages to expose a secret collection.
