# Multi-hop vulnerable mixin-deep merge

An Express JSON object crosses three relative-import wrappers into a source operand of `mixinDeep(target, ...sources)`. The nearest runtime manifest pins dependency-free `mixin-deep` 2.0.0, whose incomplete `__proto__`-only repair still follows a parser-produced `constructor.prototype` path into `Object.prototype`. The route demonstrates the resulting cross-object authorization effect through a fresh policy object.
