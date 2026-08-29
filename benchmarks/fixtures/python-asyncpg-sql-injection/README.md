# asyncpg SQL grammar injection

This Python fixture demonstrates a FastAPI query parameter crossing a typed wrapper and becoming SQL grammar in the first argument of an awaited official `asyncpg.Connection.fetch()` call.

The bounded witness substitutes only a recording connection. It proves the grammar/value boundary without opening a socket or claiming PostgreSQL impact. A reported finding still needs driver, server, statement-policy, role, reachability, and concrete database-impact evidence.

Run the witness with `python examples/witness.py`.
