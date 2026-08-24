# Reachable shell-quote object-token command injection

An Express query value crosses three relative-import wrappers before it becomes the `op` field of a public `shell-quote` object token. Version 1.8.3 leaves line terminators in that field unescaped, and the resulting command is handed to `/bin/sh -c` through the official Node child-process API.

`npm run witness` uses only the fixed `;\npwd` payload. It changes no files and makes no network request. The affected build retains the command-separating newline and, on POSIX hosts, executes only side-effect-free `pwd`; the repaired twin rejects the identical token before shell dispatch.
