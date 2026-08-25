# Unsafe python-statemachine SCXML evaluation

The Flask route accepts a bounded SCXML document and passes it through the
relative `run_statechart` wrapper. The wrapper constructs the official
`statemachine.io.scxml.processor.SCXMLProcessor`, parses the remote document,
and starts the statechart under `python-statemachine==3.1.2`. That affected
release evaluates SCXML datamodel expressions with Python `eval()` when the
initial state is entered.

`examples/witness.py` uses only a bounded arithmetic capability check. The
SCXML datamodel resolves `__import__` and asks `builtins.eval` to evaluate the
fixed expression `6 * 7`. It performs no shell command, file operation,
network request, credential access, persistence, or destructive action.

This fixture models GHSA-v4jc-pm6r-3vj8 / CVE-2026-47103 as a capability
boundary. It does not claim that fixture evidence proves a deployed service is
reachable or compromised.
