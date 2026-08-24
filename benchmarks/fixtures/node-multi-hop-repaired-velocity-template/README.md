# Repaired Velocity.js template fixture

This source-identical control upgrades only `velocityjs` to 2.1.7. That release
applies one shared prototype guard to reference, index, and method property
reads, so the inherited `constructor.constructor` chain no longer resolves.

Run `npm install --ignore-scripts` and `npm run witness` to validate the pinned
package behavior.
