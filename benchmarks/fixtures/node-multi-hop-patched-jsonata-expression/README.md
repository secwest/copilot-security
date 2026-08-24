# Patched JSONata expression control

This source-identical control changes only the JSONata runtime to 2.2.1. The
same bounded witness is rejected with JSONata error `T1006` before the recovered
constructor can run.

Run `npm install --ignore-scripts` and `npm run witness` to validate the pinned
package behavior.
