# Python cross-file list `+=` command injection

The Flask route passes an attacker-controlled report name through a relative
Python import. The wrapper adds a formatted shell command to an initially empty
list with `+=`, selects that exact element, and executes it with `shell=True`.
The witness proves that POSIX shell metacharacters reach shell grammar.
