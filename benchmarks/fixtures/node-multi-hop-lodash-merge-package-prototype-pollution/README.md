# Multi-hop vulnerable standalone lodash.merge package

An Express JSON object crosses three relative-import wrappers into a source operand of the direct callable exported by `lodash.merge`. The nearest runtime manifest pins the separately versioned package to vulnerable 4.6.1, before its 4.6.2 prototype-pollution fix.

The dependency-free witness isolates historical `constructor.prototype` traversal. The fixture never installs the vulnerable dependency; scanner acceptance separately requires the exact package binding, matching package-specific version evidence, source position, and request-to-sink flow.
