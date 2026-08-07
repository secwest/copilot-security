# Vulnerable js-toml parser flow

An Express TOML body crosses three relative-import wrapper boundaries into the
official `js-toml.load` parser under an exact vulnerable 1.0.1 runtime pin. A
`[__proto__]` table makes the parser reuse `Object.prototype`, so the following
property assignment becomes inherited authorization state on fresh objects.
