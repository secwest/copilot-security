# Hydra 1.3.4 blocklist control

This topology-matched control changes only the `hydra-core` dependency to
1.3.4. That advisory repair blocks the witness's sensitive `builtins.eval` target
before invocation. The control demonstrates the CVE boundary; it does not treat
a target blocklist as a general substitute for a trusted call-site allowlist.
