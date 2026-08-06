# Multi-hop lock-resolved vulnerable Lodash recursive merge

An Express JSON object crosses three relative-import wrappers into a source operand of `lodash.merge()`. The nearest runtime manifest uses the ordinary `^4.17.0` registry range, while its npm v3 lockfile repeats that declaration and resolves Lodash to vulnerable 4.17.11. A `constructor.prototype` path can therefore modify `Object.prototype` and supply inherited authorization state.

The dependency-free witness isolates the historical recursive-traversal primitive. The fixture never installs the vulnerable package; scanner acceptance separately requires the official binding, matching nearest manifest and lockfile declarations, exact resolved version, source position, and request-to-sink flow.
