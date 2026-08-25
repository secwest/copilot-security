# Unsafe SymPy expression evaluation

The Flask route accepts a JSON mathematical expression and passes it through
the relative `parse_expression` wrapper. The wrapper calls the official
`sympy.parsing.sympy_parser.parse_expr` binding with its default global
namespace. SymPy documents that `parse_expr` uses Python `eval()` and must not
receive unsanitized input; the default namespace imports SymPy and exposes
Python builtin functions.

`examples/witness.py` uses only a bounded arithmetic capability check. It asks
the default namespace to resolve `__import__` and evaluate the fixed expression
`6 * 7`. It performs no shell command, file operation, network request,
credential access, persistence, or destructive action.

This fixture models the primitive behind GHSA-q27q-98j4-9pfv /
CVE-2026-55585 without claiming that fixture evidence proves a deployed Qwed
service is reachable or compromised.
