# Go manual Cmd shell-command injection fixture

An indexed HTTP query value crosses one wrapper, is formatted into command
grammar, and reaches a manually constructed `exec.Cmd` through an `Args` field
assignment and `CombinedOutput`. The test executes a copy of itself as a
deterministic shell witness on Windows and Linux without invoking the host
shell.
