import io
import json
import sys
from pathlib import Path

import joblib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import effects
from src.parser import parse_model


class Probe:
    def __reduce__(self):
        return effects.mark, ("fixture-callable-invoked",)


payload = io.BytesIO()
joblib.dump(Probe(), payload, compress=0, protocol=4)
payload.seek(0)
effects.last_effect = None

try:
    result = parse_model(payload)
    print(
        json.dumps(
            {
                "accepted": True,
                "effect": effects.last_effect,
                "joblib": joblib.__version__,
                "python": sys.version.split()[0],
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
                "joblib": joblib.__version__,
                "python": sys.version.split()[0],
            }
        )
    )
