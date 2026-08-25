# Restricted python-statemachine SCXML evaluation control

This topology-matched control keeps the Flask route, relative wrapper,
official `SCXMLProcessor` binding, remote document, parse/start lifecycle, and
bounded witness identical to the affected fixture. It changes only the exact
package pin to `python-statemachine==3.2.0`.

Version 3.2.0 uses a restricted AST evaluator by default. It accepts ordinary
arithmetic but rejects function calls and builtins such as `__import__` while
loading the document, raising `InvalidDefinition`. An explicit
`SCXMLProcessor(trusted=True)` would intentionally restore full Python
`eval`/`exec` and is not used in this control.
