import io
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import effects
from src.parser import parse_array


class Probe:
    def __reduce__(self):
        return effects.mark, ("fixture-callable-invoked",)


payload = io.BytesIO()
np.save(payload, np.array([Probe()], dtype=object), allow_pickle=True)
payload.seek(0)
effects.last_effect = None

try:
    result = parse_array(payload)
    print(
        json.dumps(
            {
                "accepted": True,
                "effect": effects.last_effect,
                "dtype": str(result.dtype),
                "numpy": np.__version__,
                "python": sys.version.split()[0],
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
                "numpy": np.__version__,
                "python": sys.version.split()[0],
            }
        )
    )
