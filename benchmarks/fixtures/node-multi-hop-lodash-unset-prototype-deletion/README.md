# Lodash array-path prototype deletion fixture

An Express JSON path crosses three relative-import boundaries into the core
Lodash 4.17.23 `unset` subpath. The first Lodash repair checks only literal
string segments, so an array-wrapped `__proto__` segment is coerced only during
property access and reaches `Object.prototype`. Deleting `toString` then breaks
later ordinary-object string coercion until the process restores the method.

The matched control pins Lodash 4.18.1, whose completed repair normalizes every
segment and rejects non-terminal magic-property traversal before deletion.
