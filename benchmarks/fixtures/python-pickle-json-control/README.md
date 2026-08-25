# Python pickle JSON-control benchmark

This fixture preserves the vulnerable benchmark's Flask route, relative
wrapper, fixture-local effect function, and witness. Its parser uses
standard-library `json.loads`, so the malicious pickle byte stream is rejected
before the embedded callable can run.
