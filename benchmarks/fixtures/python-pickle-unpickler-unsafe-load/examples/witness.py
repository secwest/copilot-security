import io
import json
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import effects
from src.parser import parse_profile


class Probe:
    def __reduce__(self):
        return effects.mark, ("fixture-callable-invoked",)


payload = pickle.dumps(Probe(), protocol=4)

try:
    result = parse_profile(io.BytesIO(payload))
    print(
        json.dumps(
            {
                "accepted": True,
                "effect": effects.last_effect,
                "type": type(result).__name__,
            }
        )
    )
except Exception as error:
    print(
        json.dumps(
            {
                "accepted": False,
                "effect": effects.last_effect,
                "error": type(error).__name__,
            }
        )
    )
