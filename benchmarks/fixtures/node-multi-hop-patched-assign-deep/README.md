# Multi-hop patched assign-deep merge

This control preserves the Express source, application error boundary, three relative-import wrappers, and exact `assignDeep(target, ...sources)` call. Its nearest runtime manifest pins `assign-deep` 0.4.8, whose completed repair rejects `__proto__`, `constructor`, and `prototype` keys before recursive destination access, so no exception or inherited authorization state is produced.
