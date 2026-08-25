# Patched Prompty Nunjucks template fixture

This source-identical control changes only `@prompty/core` from
`2.0.0-beta.4` to `2.0.0-beta.5`. The patched renderer permits only own data
properties, rejects `constructor`, `prototype`, and `__proto__` traversal, and
disallows template function calls.

Run `npm install --ignore-scripts` and `npm run witness` to validate the pinned
package behavior.
