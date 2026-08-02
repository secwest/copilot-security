# Cross-file server-side template injection

The unauthenticated preview route passes caller-controlled Pug template source
through a relative import. The wrapper compiles that source as server-side
JavaScript-capable template grammar, allowing code execution in the service
process rather than treating the value as display data.
