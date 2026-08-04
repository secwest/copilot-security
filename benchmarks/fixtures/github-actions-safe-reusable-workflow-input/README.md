# Safe reusable workflow input fixture

This fixture forwards the same issue-comment body through the same local
`workflow_call` string input. The called workflow transfers it into an
intermediate environment variable and reads it through `process.env`, so the
value remains JavaScript data rather than becoming generated source.

The executable witness supplies the same injection payload and proves it is
logged as one inert string without observing the mock release token.
