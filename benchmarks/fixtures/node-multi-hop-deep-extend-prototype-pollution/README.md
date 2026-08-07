# Multi-hop vulnerable deep-extend merge

An Express JSON object crosses three relative-import wrappers into a source operand of `deepExtend(target, ...sources)`. The nearest runtime manifest pins vulnerable `deep-extend` 0.5.0, before the 0.5.1 prototype-pollution fix.

The dependency-free witness isolates the historical `__proto__` traversal. The fixture never installs the vulnerable dependency; scanner acceptance separately requires the exact package binding, package-specific version evidence, source position, and request-to-sink flow.
