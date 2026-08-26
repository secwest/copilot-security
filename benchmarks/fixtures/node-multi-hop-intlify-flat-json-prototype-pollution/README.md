# Vulnerable Vue I18n flat-JSON fixture

An Express-style request field crosses three relative-module wrappers into the
`messages` option of `createI18n()` with `flatJson: true`. Vue I18n 9.14.2
traverses an own dotted `__proto__` key and can modify `Object.prototype`.

The witness runs only in its disposable Node process, uses one inert unique
property, opens no listener or socket, and deletes the property in `finally`.
