from __future__ import annotations

from importlib.metadata import version
import json
from pathlib import Path
import sys

FIXTURE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FIXTURE))

from src.parser import parse_expression

SENTINEL = 42
PAYLOAD = "__import__('builtins').eval('6 * 7')"


def main() -> None:
    value: int | None = None
    error: str | None = None
    try:
        value = int(parse_expression(PAYLOAD))
    except Exception as caught:
        error = type(caught).__name__
    ordinary_math = int(parse_expression("6 * 7"))
    print(
        json.dumps(
            {
                "builtin_capability": value == SENTINEL,
                "error": error,
                "ordinary_math": ordinary_math,
                "python": ".".join(map(str, sys.version_info[:3])),
                "sympy": version("sympy"),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
