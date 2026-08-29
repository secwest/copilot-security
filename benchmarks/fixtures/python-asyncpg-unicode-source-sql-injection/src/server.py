from typing import Annotated

import asyncpg
from fastapi import FastAPI, Query

from .accounts import lookup

app = FastAPI()


@app.get("/accounts")
async def account(
    username: Annotated[str, Query()], connection: asyncpg.Connection
):
    return await lookup(connection, username)
