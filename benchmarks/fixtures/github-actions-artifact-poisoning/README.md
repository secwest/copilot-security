# GitHub Actions artifact-poisoning fixture

The unprivileged `PR Build` workflow checks out pull-request code and uploads
`release.mjs`. The privileged `Publish` workflow downloads that exact artifact
from its triggering run into the trusted workspace and executes it with a
write-capable token, OIDC, and a mock release secret available.

The executable witness uses harmless local files and a mock token; it never
contacts GitHub or an external service.
