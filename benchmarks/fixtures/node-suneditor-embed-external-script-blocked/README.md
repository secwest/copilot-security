# SunEditor Embed external-script XSS fixture

This fixture creates the official SunEditor editor with the official Embed
plugin and toolbar button enabled. An exported application entry point places
remote request-body HTML at the editor-content boundary. The companion witness
inspects only the installed upstream Embed implementation and prints the exact
version plus a boolean for the 3.1.4 default-deny script gate; it does not load
or execute a script.

The paired control uses identical application, witness, and documentation
bytes. Only the `suneditor` dependency changes from affected 3.1.3 to repaired
3.1.4. `runtime-server.mjs` binds only a random `127.0.0.1` port and serves one
inert script that increments an in-memory sentinel. `runtime-witness.html`
submits identical iframe-plus-script bytes through the initialized official
Embed plugin and reports only submission, request-count, and sentinel facts.
The affected package submits, requests once, and increments once; the repaired
package rejects the submission, makes no script request, and leaves the
sentinel unset.
