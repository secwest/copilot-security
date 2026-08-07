# Multi-hop vulnerable merge-options merge

An Express JSON object crosses three relative-import wrappers into one source argument of `mergeOptions(option1, ...options)`. The nearest runtime manifest pins vulnerable `merge-options` 1.0.0, whose recursive `key in merged` lookup and ordinary assignment can select and modify `Object.prototype` for a parser-produced own `__proto__` key.

The dependency-free witness isolates the official 1.0.0 behavior without installing the vulnerable package. Scanner acceptance separately requires the exact package binding, package-specific version evidence, any real source argument, and request-to-sink flow.
