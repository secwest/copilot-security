# Self-hosted pull-request execution fixture

The pull-request job uses a reusable self-hosted runner, checks out the event's
untrusted merge commit, and executes repository-controlled package scripts.
The read-only token and disabled checkout credential persistence reduce direct
repository authority but do not isolate the runner host from attacker code.
