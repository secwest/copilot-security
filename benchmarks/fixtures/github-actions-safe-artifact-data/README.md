# GitHub Actions isolated-artifact fixture

The same unprivileged `PR Build` workflow uploads attacker-controlled artifact
bytes. The privileged consumer follows GitHub's documented pattern: it extracts
outside the workspace beneath `runner.temp`, parses the artifact as a narrowly
typed integer, and fails closed instead of executing artifact content.

The fixture keeps the producer and artifact identity matched so the control
isolates consumption rather than removing the cross-workflow data transfer.
