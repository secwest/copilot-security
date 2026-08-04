# Safe composite action input fixture

This fixture forwards the same issue-comment body through the same local
composite-action input. The action transfers it into a step environment
variable and reads it through `process.env`, so the value remains JavaScript
data rather than becoming generated program source.

The executable witness supplies the same injection payload and proves it is
logged as one inert string without observing the mock release token.
