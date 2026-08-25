from __future__ import annotations

import runpy
from pathlib import Path

from datamodel_code_generator import InputFileType, generate


def compile_and_load(schema: dict[str, object]) -> dict[str, object]:
    output_path = Path("/tmp/generated_model.py")
    generate(schema, input_file_type=InputFileType.JsonSchema, output=output_path)
    return runpy.run_path(output_path)
