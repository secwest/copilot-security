# Multi-hop vulnerable just-extend merge

An Express JSON object crosses three relative-import wrappers into a source operand of `extend(true, target, ...sources)`. The nearest runtime manifest pins `just-extend` 4.0.0, whose recursive destination lookup can reuse the inherited `__proto__` object and modify `Object.prototype`. The route then demonstrates the cross-object effect through a fresh policy object.

The dependency-free witness reproduces the official 4.0.0 and 4.0.1 lookup distinction. The fixture never installs the vulnerable dependency; scanner acceptance separately requires the exact package binding, package-specific version evidence, literal deep flag, source position, and request-to-sink flow.
