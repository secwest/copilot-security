# Multi-hop patched merge-options merge

This control preserves the Express source, three relative-import wrappers, and exact `mergeOptions(option1, ...options)` call. Its nearest runtime manifest pins patched `merge-options` 1.0.1, which refuses to recurse into the destination prototype and defines dangerous keys as own data properties rather than invoking the legacy `__proto__` setter.

The dependency-free witness reproduces the upstream repair and proves that the returned object retains an own `__proto__` value without changing its real prototype or global `Object.prototype`. The fixture never installs the package.
