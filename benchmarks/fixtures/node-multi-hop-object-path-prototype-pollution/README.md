# Vulnerable object-path inherited deletion flow

An Express JSON path crosses three relative-import wrapper boundaries into the
official inherited-properties `objectPath.del(target, path)` API under an exact
vulnerable 0.11.7 runtime pin. A path such as `__proto__.toString` deletes the
built-in method from `Object.prototype`, breaking later object string coercion.
