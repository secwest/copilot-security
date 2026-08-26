# Repaired Vue I18n flat-JSON control

This source-identical control changes only Vue I18n from 9.14.2 to 9.14.3.
The repaired transformer rejects an exact `__proto__` path segment before it
can traverse the prototype chain.

The witness runs only in its disposable Node process, uses one inert unique
property, opens no listener or socket, and confirms cleanup in `finally`.
