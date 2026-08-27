from pathlib import Path

import asyncssh

DOWNLOAD_ROOT = Path("downloads")


async def fetch_release(conn):
    return await asyncssh.scp((conn, "release.tar"), DOWNLOAD_ROOT)
