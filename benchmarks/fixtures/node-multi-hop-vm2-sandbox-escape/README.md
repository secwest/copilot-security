# Vulnerable vm2 sandbox fixture

An Express request body field crosses three relative-import wrappers into the
official `VM.run` method under the exact vulnerable `vm2` 3.11.5 runtime.
`witness.mjs` uses the advisory's dangerous host-prototype-mutator chain only
to recover `process.version`; it does not spawn a process, touch the filesystem,
change process state, open a listener, or make a network request.
The same witness reads only `os.hostname()` through the documented wildcard
`NodeVM` builtin configuration and never calls a host-mutating API.

Run `npm install --ignore-scripts` and `npm run witness` to validate the pinned
package behavior.
