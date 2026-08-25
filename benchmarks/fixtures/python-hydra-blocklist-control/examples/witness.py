from __future__ import annotations

from importlib.metadata import version
import json
from pathlib import Path
import sys

FIXTURE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FIXTURE))

from src.factory import build_component

SENTINEL = 42


def main() -> None:
    value: int | None = None
    error: str | None = None
    try:
        value = build_component(
            {
                "_target_": "builtins.eval",
                "_args_": ["6 * 7"],
            }
        )
    except Exception as caught:
        error = type(caught).__name__
    print(
        json.dumps(
            {
                "evaluated": value == SENTINEL,
                "error": error,
                "hydra_core": version("hydra-core"),
                "python": ".".join(map(str, sys.version_info[:3])),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
