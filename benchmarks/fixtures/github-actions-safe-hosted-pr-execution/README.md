# Hosted pull-request execution control

This matched workflow executes the same pull-request code with the same
read-only token and checkout settings on a standard GitHub-hosted runner. The
runner is a fresh ephemeral virtual machine rather than a reusable customer
host on which the pull request can establish persistence for later jobs.
