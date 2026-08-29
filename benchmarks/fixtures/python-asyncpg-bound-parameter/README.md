# asyncpg bound-parameter control

This topology-matched Python control keeps SQL grammar fixed and sends the same hostile FastAPI query value only as asyncpg's later bound-value argument to `Connection.fetch()`.

Its bounded recording witness opens no socket. It verifies that the SQL text retains `$1` and that the payload remains a separate protocol value. Run it with `python examples/witness.py`.
