# Contributing

Copilot Security is maintained by Secwest in
[`secwest/copilot-security`](https://github.com/secwest/copilot-security).

Before opening a change:

1. Search the repository's existing issues and pull requests.
2. Keep scanner state, environment variables, artifacts, processes, and
   package names inside the Copilot Security namespace.
3. Add or update tests for runtime, contract, and false-positive /
   false-negative behavior.
4. Run formatting, type checks, unit tests, package checks, and the relevant
   benchmark slice.
5. Do not lower benchmark thresholds to make a regression pass.

Security vulnerabilities should be reported privately as described in
[SECURITY.md](SECURITY.md), not in a public issue.
