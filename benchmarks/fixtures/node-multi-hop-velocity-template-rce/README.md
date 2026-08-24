# Vulnerable Velocity.js template fixture

An Express query parameter crosses three relative-import wrappers into the
official Velocity.js renderer under the exact vulnerable `velocityjs` 2.1.6
runtime. `witness.mjs` uses a bounded, non-shell sentinel that exercises the
inherited `constructor.constructor` property-read chain and returns only
`process.version`.

Run `npm install --ignore-scripts` and `npm run witness` to validate the pinned
package behavior.
