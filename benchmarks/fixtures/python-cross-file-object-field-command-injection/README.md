# Python cross-file object-field command injection

The Flask route passes an attacker-controlled report name through a relative
Python import. The wrapper stores the resulting command in the exact `value`
field of a fresh standard-library `SimpleNamespace`, reads that same field,
and sends the string to `subprocess.run` with `shell=True`. The witness proves
only that POSIX shell metacharacters reach shell grammar and create a temporary
marker.
