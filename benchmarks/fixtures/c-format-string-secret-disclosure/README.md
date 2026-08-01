# Attacker-controlled audit format string

The unauthenticated login path records the remote username while an active
administrator-session capability is available to the audit helper. The helper
passes the username as `snprintf`'s format argument and supplies the capability
as its first variadic argument.

An attacker can submit `%s` as the username. `snprintf` then interprets the
capability pointer as the requested string argument and emits the secret into
the externally visible audit message. Ordinary usernames still appear to work,
which keeps the defect out of the obvious error path.
