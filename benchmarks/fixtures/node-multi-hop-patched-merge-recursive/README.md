# Multi-hop patched merge.recursive call

This control preserves the Express source, three relative-import wrappers, pre-existing nested destination object, and exact `merge.recursive(target, ...sources)` call. Its nearest runtime manifest pins `merge` 2.1.1, whose completed repair rejects `__proto__`, `constructor`, and `prototype` inside the recursive helper as well as the outer merge loop.
