# Go cross-package helper-chain object deletion

The DELETE route stages a path-selected invoice deletion, imports a typed
transaction coordinator from one internal package, and reaches the real commit
through a second internal package. Exact module, import-alias, exported-function,
parameter, alias, and leaf evidence is preserved. The offline driver proves the
cross-package helper chain makes the victim deletion durable without principal
scope.
