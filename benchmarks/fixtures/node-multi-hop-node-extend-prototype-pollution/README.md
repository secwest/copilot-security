# Multi-hop vulnerable node.extend merge

An Express JSON object crosses three relative-import wrappers into a source operand of `extend(true, target, ...sources)`. The nearest runtime manifest pins vulnerable `node.extend` 2.0.0, whose recursive destination lookup reuses the inherited `__proto__` object and modifies `Object.prototype`. The route demonstrates the resulting cross-object authorization effect through a fresh policy object.
