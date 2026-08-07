# Multi-hop patched deep-extend merge

This control preserves the Express source, three relative-import wrappers, and exact `deepExtend(target, ...sources)` call. Its nearest runtime manifest pins patched `deep-extend` 0.5.1, whose property-read boundary prevents the historical `__proto__` traversal.

The dependency-free witness models that patched boundary. The scanner must not emit a vulnerable-package merge row from this fixture.
