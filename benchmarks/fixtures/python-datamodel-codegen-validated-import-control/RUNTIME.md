# Runtime

The bounded control ran on CPython 3.12.3 with
`datamodel-code-generator==0.64.0`. The official generator rejected the
malicious import path with `Error`; it wrote no generated module and produced
no arithmetic capability output.

Observed result:

```json
{
  "capability": null,
  "capability_output": null,
  "datamodel_code_generator": "0.64.0",
  "error": "Error",
  "generated": false,
  "python": "3.12.3"
}
```
