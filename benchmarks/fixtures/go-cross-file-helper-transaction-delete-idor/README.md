# Go helper-committed object deletion

The DELETE route passes a path-selected invoice through one mutation wrapper,
stages the fixed SQL on a standard-library transaction, and finalizes it through
a uniquely resolved typed same-package commit helper. The offline driver proves
that the helper makes the victim deletion durable without principal scope.
