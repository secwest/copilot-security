# Repaired shell-quote object-token control

This control is source-identical to the vulnerable fixture except for its exact `shell-quote` 1.8.4 dependency. The repaired `quote()` implementation accepts only parser-generated operators and rejects an `op` containing a line terminator before the result can reach the shell.

`npm run witness` uses the same fixed `;\npwd` token, changes no files, and makes no network request. It must receive the package's `invalid op value` error and must not invoke `/bin/sh`.
