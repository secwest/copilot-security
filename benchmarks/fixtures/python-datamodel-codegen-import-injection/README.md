# Unsafe generated-model import execution

The Flask route accepts a JSON Schema and passes it through the relative
`compile_and_load` wrapper. The wrapper calls the official
`datamodel_code_generator.generate` API from
`datamodel-code-generator==0.63.0`, writes the generated model source, and
executes that source with `runpy.run_path`.

In affected releases, a schema-controlled `x-python-import` or
`customTypePath` value reaches `Import.from_full_path` and
`Imports.create_line` without rejecting a newline. The newline can add a
module-scope Python statement to the generated model. Generation is not itself
execution: this fixture is reportable because the same output path is later
executed.

`examples/witness.py` uses only a fixed arithmetic capability check. It emits
`print(6 * 7)`, captures standard output in memory, and uses an automatically
removed temporary directory. It performs no shell command, network request,
credential access, persistence, or destructive action.

This fixture models GHSA-5578-w22f-pfx9 / CVE-2026-55415 as a capability
boundary. It does not claim that fixture evidence proves a deployed service is
reachable or compromised.
