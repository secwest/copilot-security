import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.parser import parse_profile


payload = "!!python/tuple [alpha, beta]"

try:
    result = parse_profile(payload)
    print(json.dumps({"accepted": True, "type": type(result).__name__}))
except Exception as error:
    print(json.dumps({"accepted": False, "error": type(error).__name__}))
