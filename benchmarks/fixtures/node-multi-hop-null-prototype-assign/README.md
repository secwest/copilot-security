# Multi-hop null-prototype assignment target

The matched Express and relay topology copies the untrusted source only into an `Object.create(null)` target. An own `__proto__` key remains ordinary data because the target inherits no prototype setter.
