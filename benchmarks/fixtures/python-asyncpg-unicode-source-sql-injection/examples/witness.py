import asyncio
from pathlib import Path
import sys
import types


class RecordingConnection:
    def __init__(self):
        self.calls = []

    async def fetch(self, *arguments):
        self.calls.append(arguments)
        return arguments


asyncpg = types.ModuleType("asyncpg")
asyncpg.Connection = RecordingConnection
sys.modules["asyncpg"] = asyncpg
sys.path.insert(0, str(Path(__file__).parents[1]))

from src.accounts import lookup


async def main():
    payload = "guest' OR role = 'administrator' --"
    connection = RecordingConnection()
    await lookup(connection, payload)
    arguments = connection.calls[0]
    is_control = Path(__file__).parents[1].name.endswith("bound-parameter")
    if is_control:
        assert arguments == (
            "SELECT username, role FROM accounts WHERE username = $1",
            payload,
        )
    else:
        assert len(arguments) == 1
        assert "OR role = 'administrator'" in arguments[0]
        assert "$1" not in arguments[0]
    print({"control": is_control, "arguments": arguments})


asyncio.run(main())
