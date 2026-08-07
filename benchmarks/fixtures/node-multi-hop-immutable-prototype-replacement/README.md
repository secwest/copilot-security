# Immutable.js returned-object prototype replacement fixture

An Express JSON profile update crosses three relative-import boundaries into
Immutable.js 5.1.4 `mergeDeep`. Copying the parser-produced own `__proto__` key
changes only the returned profile's prototype, making `profile.admin` inherited
and truthy without changing global `Object.prototype`.

The matched control pins Immutable.js 5.1.5, whose repaired plain-object paths
reject the magic key before copying or recursion.
