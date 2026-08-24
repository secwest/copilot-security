# Repaired LiquidJS template fixture

This source-identical control changes only the runtime dependency from
LiquidJS 10.25.7 to 10.26.0. The repaired release stores filters and tags in
null-prototype registries, so inherited `valueOf` no longer becomes a callable
template filter.

Run `npm install --ignore-scripts` and `npm run witness` to validate the pinned
package behavior.
