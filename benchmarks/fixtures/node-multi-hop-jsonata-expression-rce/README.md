# Vulnerable JSONata expression fixture

An Express query parameter crosses three relative-import wrappers into the
official JSONata compiler and the compiled expression is evaluated under the
exact vulnerable `jsonata` 2.2.0 runtime. `witness.mjs` uses a bounded,
non-shell sentinel that recovers the host `Function` constructor and returns
only `process.version`.

Run `npm install --ignore-scripts` and `npm run witness` to validate the pinned
package behavior.
