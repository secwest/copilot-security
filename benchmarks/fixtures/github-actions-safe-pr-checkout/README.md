# Protected privileged pull-request checkout

This matched workflow keeps `pull_request_target`, the same immutable fork
commit request, and the same subsequent package execution shape. It uses
`actions/checkout@v7` without `allow-unsafe-pr-checkout`, so Checkout's current
fork protection refuses the untrusted checkout. The job also grants only
read-only token permissions, exposes no explicit secret, and does not persist
checkout credentials.

The paired witness proves the protected checkout path rejects the simulated
fork before its code can execute.
