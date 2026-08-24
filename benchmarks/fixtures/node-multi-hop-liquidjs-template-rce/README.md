# Vulnerable LiquidJS template fixture

An Express query parameter crosses three relative-import wrappers into an
official LiquidJS engine under the exact vulnerable `liquidjs` 10.25.7
runtime. `witness.mjs` uses a bounded, non-shell sentinel that follows the
inherited `valueOf` filter path and returns only `process.version`.

Run `npm install --ignore-scripts` and `npm run witness` to validate the pinned
package behavior.
