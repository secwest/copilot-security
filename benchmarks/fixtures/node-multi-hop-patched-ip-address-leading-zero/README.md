# Patched ip-address leading-zero guard

This source-identical control upgrades only `ip-address` to 10.3.1. The repaired parser rejects every multi-digit IPv4 octet beginning with zero before any trust-boundary classifier runs.
