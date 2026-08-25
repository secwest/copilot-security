from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import runpy
import sys
import tempfile
from pathlib import Path

from datamodel_code_generator import InputFileType, generate, get_version


SCHEMA = {
    "type": "object",
    "title": "Root",
    "required": ["field"],
    "properties": {"field": {"$ref": "#/$defs/GeneratedField"}},
    "$defs": {
        "GeneratedField": {
            "type": "object",
            "x-python-import": {
                "module": "os",
                "name": "getcwd\nprint(6 * 7)",
            },
        }
    },
}


def main() -> None:
    result: dict[str, object] = {
        "python": ".".join(map(str, sys.version_info[:3])),
        "datamodel_code_generator": get_version(),
        "generated": False,
        "capability": None,
        "capability_output": None,
        "error": None,
    }
    with tempfile.TemporaryDirectory(prefix="dmcg-witness-") as directory:
        output = Path(directory, "model.py")
        try:
            generate(
                SCHEMA,
                input_file_type=InputFileType.JsonSchema,
                output=output,
            )
            result["generated"] = True
            result["generated_contains_capability"] = "print(6 * 7)" in output.read_text(
                encoding="utf-8"
            )
            captured = io.StringIO()
            try:
                with redirect_stdout(captured):
                    namespace = runpy.run_path(str(output))
                result["capability"] = namespace.get("CAPABILITY")
            finally:
                result["capability_output"] = captured.getvalue().strip() or None
        except Exception as error:
            result["error"] = type(error).__name__

    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
