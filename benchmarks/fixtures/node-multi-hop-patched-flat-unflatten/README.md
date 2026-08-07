# Patched flat.unflatten flow

This matched negative preserves the Express source, three wrappers, and
official `unflatten` call while pinning flat 4.1.1. The repaired implementation
rejects `__proto__` at each delimited path-expansion step, so hostile keys remain
unable to reach `Object.prototype`.
