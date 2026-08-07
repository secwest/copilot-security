# Patched Immutable.js control

This fixture preserves the Express source, three relative-import wrappers,
profile target, and `mergeDeep` source position while pinning Immutable.js
5.1.5. The repair ignores `__proto__` in every plain-object copy, merge, set,
update, and conversion path.
