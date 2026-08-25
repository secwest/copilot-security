# Python Joblib unsafe-load benchmark

The Flask route passes a bounded request-controlled model stream through one
relative wrapper into `joblib.load`. Joblib uses Python pickle for persistence,
so the checked-in witness proves that callable dispatch occurs before the load
returns. The paired JSON control preserves the same route, request stream,
wrapper, size budget, effect module, requirements, and malicious payload while
replacing only the unsafe deserialization boundary with `json.load`.

The witness invokes only the fixture-local `src.effects.mark` function. It does
not start a listener, access the network, invoke a shell, or write a file.
