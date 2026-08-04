# Go helper-chain-committed object deletion

The DELETE route passes a path-selected invoice through one mutation wrapper,
stages the fixed SQL on a standard-library transaction, and finalizes it through
two uniquely resolved typed same-package helpers. The coordinator aliases and
forwards the transaction to the leaf commit helper. The offline driver proves
the full helper chain makes the victim deletion durable without principal scope.
