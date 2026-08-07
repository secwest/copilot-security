# Multi-hop patched node.extend merge

This control preserves the Express source, three relative-import wrappers, and exact `extend(true, target, ...sources)` call. Its nearest runtime manifest pins patched `node.extend` 2.0.1, whose own-property-aware read avoids selecting inherited `Object.prototype` and whose own-data-property write avoids the legacy `__proto__` setter.
