# Multi-hop vulnerable Lodash recursive merge

An Express JSON object crosses three relative-import wrappers into a source operand of `lodash.merge()`. The nearest runtime manifest pins vulnerable Lodash 4.17.10, before the 4.17.11 `_.merge` prototype-pollution fix, so a `constructor.prototype` path can modify `Object.prototype` and supply inherited authorization state.

The dependency-free witness isolates the historical recursive-traversal primitive so the benchmark suite does not install a vulnerable package. Scanner acceptance separately requires the exact official import, nearest manifest, pinned vulnerable version, source position, and request-to-sink flow.
