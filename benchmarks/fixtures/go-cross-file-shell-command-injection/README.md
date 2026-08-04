# Go shell-command injection fixture

An indexed HTTP query value crosses one wrapper, is formatted into the command
string supplied to `sh -c`, and reaches `CombinedOutput`. The test installs a
copy of its own test executable as a deterministic shell witness, so the
exploit runs on Windows and Linux without invoking the host shell.
