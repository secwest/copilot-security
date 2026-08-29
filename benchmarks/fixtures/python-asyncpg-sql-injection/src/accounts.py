import asyncpg


async def lookup(connection: asyncpg.Connection, username: str):
    query = (
        "SELECT username, role FROM accounts WHERE username = '"
        + username
        + "'"
    )
    query_copy = query
    return await connection.fetch(query_copy)
