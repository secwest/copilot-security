"""Bounded Chainlit MCP command-schema witness; never launches a process."""

from __future__ import annotations

import importlib.metadata
import json


FIXED_COMMAND = "npx --yes copilot-security-bounded-marker"


def main() -> None:
    version = importlib.metadata.version("chainlit")
    if version == "2.11.1":
        from chainlit.config import config
        from chainlit.mcp import validate_mcp_command

        config.features.mcp.stdio.allowed_executables = ["npx", "uvx"]
        environment, executable, arguments = validate_mcp_command(FIXED_COMMAND)
        assert environment == {}
        assert executable == "npx"
        assert arguments == ["--yes", "copilot-security-bounded-marker"]
        result = {
            "arguments": arguments,
            "executed": False,
            "executable": executable,
            "version": version,
        }
    elif version == "2.12.0":
        import chainlit.mcp as mcp
        from chainlit.types import ConnectMCPRequest
        from pydantic import ValidationError

        try:
            ConnectMCPRequest.model_validate(
                {"clientType": "stdio", "fullCommand": FIXED_COMMAND}
            )
        except ValidationError as error:
            rejected = True
            rejection = error.__class__.__name__
        else:
            rejected = False
            rejection = "none"
        assert not hasattr(mcp, "validate_mcp_command")
        assert rejected
        result = {
            "client_command_rejected": rejected,
            "executed": False,
            "rejection": rejection,
            "validator_present": False,
            "version": version,
        }
    else:
        raise RuntimeError(f"unexpected Chainlit version: {version}")

    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
