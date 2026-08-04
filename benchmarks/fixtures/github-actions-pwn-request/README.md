# Privileged pull-request code execution

This GitHub Actions workflow uses `pull_request_target`, explicitly restores
fork checkout under `actions/checkout@v7`, and then executes package lifecycle
and test commands from that checkout. The process receives a write-capable
repository token and an explicit repository secret.

The paired witness materializes harmless attacker-controlled code in a private
temporary directory and proves that enabling the unsafe checkout permits that
code to observe a mock privileged token.
