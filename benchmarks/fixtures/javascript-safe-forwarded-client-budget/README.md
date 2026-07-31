# Safe forwarded-client recovery fixture

The recovery endpoint trusts forwarding metadata only from an exact ingress
allowlist, validates canonical IPv4 hop syntax, and peels trusted proxies from
the right side of the chain. Attacker-prepended addresses therefore do not
change the actual client identity, and forwarding headers from direct untrusted
peers are ignored. Synchronous client- and account-scoped budgets also prevent
one source or distributed sources from exceeding the recovery-attempt limit.
