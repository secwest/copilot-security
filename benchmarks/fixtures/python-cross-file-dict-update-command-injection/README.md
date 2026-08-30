# Python cross-file dictionary update command injection

The Flask route passes an attacker-controlled report name through a relative
Python import. The wrapper overwrites the `preview` command through an exact
`dict.update` literal, selects that same constant key through `get`, and sends
the resulting string to `subprocess.run` with `shell=True`. The witness proves
only that POSIX shell metacharacters reach shell grammar and create a temporary
marker.
