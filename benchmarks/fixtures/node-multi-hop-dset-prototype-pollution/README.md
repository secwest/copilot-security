# Vulnerable dset path flow

An Express JSON path crosses three relative-import wrapper boundaries into the
official `dset(target, path, value)` API under an exact vulnerable 3.1.3 runtime
pin. A parser-produced nested-array segment bypasses the string-only dangerous
key comparison through implicit property-key coercion and reaches
`Object.prototype`.
