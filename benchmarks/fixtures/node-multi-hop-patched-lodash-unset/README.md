# Patched Lodash unset control

This fixture preserves the Express source, all three relative-import wrappers,
the core Lodash subpath, target, and `unset` path position while pinning current
Lodash 4.18.1. The completed `baseUnset` repair coerces each segment before
checking it and refuses non-terminal prototype traversal.
