# Duplicate-parameter authorization-bypass fixture

The public gateway parses the query string with `URLSearchParams.get`, which
selects the first `action` value, and authorizes a low-privilege `view` request.
It then forwards the original query string. The backend reparses it with
`Object.fromEntries`, which keeps the last duplicate value, and executes an
administrative `delete` action. A single request can therefore pass one
interpretation and trigger a different protected effect.
