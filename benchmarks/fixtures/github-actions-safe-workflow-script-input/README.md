# Safe same-workflow script input fixture

This workflow receives the same pull request title under the same trigger,
permissions, secret environment, and GitHub Script action. It transfers the
expression into `TITLE` and reads `process.env.TITLE`, so the title remains one
JavaScript data value instead of becoming generated source.

The executable witness supplies the same injection payload and proves it cannot
create a token-observing statement.
