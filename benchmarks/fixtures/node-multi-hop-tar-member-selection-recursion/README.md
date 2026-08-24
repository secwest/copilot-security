# Vulnerable node-tar member-selection recursion

An upload path crosses three application wrappers before asynchronous `tar.t` 7.5.20 lists one selected member. A GNU `L` or PAX `x` header can supply enough slash-separated path segments to exhaust the recursive `filesFilter/mapHas` parent walk before entry-depth controls run, terminating the Node process with an uncaught `RangeError`.

`witness.mjs` reproduces the vulnerable recursive walk in an isolated child process without installing the affected package.
