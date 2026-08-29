# asyncpg Unicode source-retention SQL injection

This Python 3.12 fixture combines PEP 695 syntax with variation-selector,
percent, zero-width-joiner, combining-mark, and soft-hyphen source text. A
FastAPI query parameter still becomes SQL grammar in the first argument of an
awaited official `asyncpg.Connection.fetch()` call.

The paired control retains exactly the same unusual source shapes but uses a
`$1` protocol-bound value. The pair detects scanners that silently lose an
otherwise valid source file while decoding, parsing, logging, or enumerating it.

Run the bounded witness with `python examples/witness.py` on Python 3.12 or
newer. It substitutes a recording connection and opens no network socket.
