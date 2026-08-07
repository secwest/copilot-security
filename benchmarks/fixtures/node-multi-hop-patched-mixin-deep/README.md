# Multi-hop patched mixin-deep merge

This control preserves the Express source, three relative-import wrappers, and exact `mixinDeep(target, ...sources)` call. Its nearest runtime manifest pins patched `mixin-deep` 2.0.1, whose completed key validation rejects `__proto__`, `constructor`, and `prototype` before recursive destination access.
