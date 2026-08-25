# Runtime

The bounded witness ran on CPython 3.12.3 with
`datamodel-code-generator==0.63.0`. The official generator wrote source
containing the fixed `print(6 * 7)` statement. `runpy.run_path` reached that
statement and captured `42` before a later, unrelated
`PydanticSchemaGenerationError` while resolving the deliberately minimal
fixture model.

Observed result:

```json
{
  "capability": null,
  "capability_output": "42\n42",
  "datamodel_code_generator": "0.63.0",
  "error": "PydanticSchemaGenerationError",
  "generated": true,
  "generated_contains_capability": true,
  "python": "3.12.3"
}
```
