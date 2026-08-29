# asyncpg Unicode source-retention bound-parameter control

This Python 3.12 control retains the vulnerable fixture's PEP 695 syntax and
variation-selector, percent, zero-width-joiner, combining-mark, and soft-hyphen
source text. It keeps SQL grammar fixed and sends the hostile FastAPI value only
as a `$1` protocol-bound argument.

The pair detects both silent source loss and false positives caused merely by
unusual valid source text.

Run the bounded witness with `python examples/witness.py` on Python 3.12 or
newer. It substitutes a recording connection and opens no network socket.
