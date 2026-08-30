# Python cross-file dataclass-field command injection

The Flask route passes an attacker-controlled report name through a relative
Python import. The wrapper writes the resulting command to the declared `value`
field of an exact standard-library generated dataclass, reads that same receiver
and field, and passes the string to `subprocess.run` with `shell=True`. The
witness proves only that POSIX shell metacharacters reach shell grammar and
create one disposable temporary marker.
