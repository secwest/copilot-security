# Validated generated-model import control

This topology-identical negative control changes only the generator dependency
to `datamodel-code-generator==0.64.0`. That repaired release validates schema
extension import paths and raises `Error` for the witness newline before it
writes a generated module. The application therefore has no generated source
to execute.

The same bounded arithmetic witness and application topology are retained so
the dependency repair—not a missing source, wrapper, generation call, or
execution call—explains the negative result.
