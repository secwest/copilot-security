from __future__ import annotations

from importlib.metadata import version
import json
from pathlib import Path
import sys

FIXTURE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FIXTURE))

from src.loader import run_statechart

SENTINEL = 42


def document(expression: str) -> str:
    return f"""\
<scxml xmlns="http://www.w3.org/2005/07/scxml" version="1.0" initial="ready">
  <datamodel><data id="result" expr="{expression}"/></datamodel>
  <state id="ready"/>
</scxml>
"""


def main() -> None:
    capability: int | None = None
    capability_error: str | None = None
    try:
        capability = int(
            run_statechart(document("__import__('builtins').eval('6 * 7')"))
        )
    except Exception as caught:
        capability_error = type(caught).__name__

    ordinary_error: str | None = None
    ordinary_math: int | None = None
    try:
        ordinary_math = int(run_statechart(document("6 * 7")))
    except Exception as caught:
        ordinary_error = type(caught).__name__

    print(
        json.dumps(
            {
                "capability": capability,
                "capability_error": capability_error,
                "ordinary_error": ordinary_error,
                "ordinary_math": ordinary_math,
                "python": ".".join(map(str, sys.version_info[:3])),
                "python_statemachine": version("python-statemachine"),
                "sentinel_reached": capability == SENTINEL,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
