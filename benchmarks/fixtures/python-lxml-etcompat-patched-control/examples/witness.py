import json
import sys
from pathlib import Path

import lxml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.parser import parse_document


marker_path = Path(__file__).with_name("entity-marker.txt").resolve()
marker = marker_path.read_text(encoding="utf8").strip()
xml = (
    '<!DOCTYPE root [<!ENTITY probe SYSTEM "'
    + marker_path.as_uri()
    + '">]><root>&probe;</root>'
)
try:
    values = parse_document(xml.encode("utf8"))
    error = None
except Exception as exception:
    values = []
    error = type(exception).__name__

print(
    json.dumps(
        {
            "disclosed": any(marker in (value or "") for value in values),
            "error": error,
            "lxml": lxml.__version__,
            "python": sys.version.split()[0],
            "values": values,
        }
    )
)
