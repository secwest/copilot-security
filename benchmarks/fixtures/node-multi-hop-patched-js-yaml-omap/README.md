# Patched js-yaml ordered-map parsing

This source-identical control upgrades only `js-yaml` to 4.3.1. The repaired `!!omap` resolver replaces each growing linear duplicate-key scan with constant-time own-key tracking while retaining duplicate rejection.

The dependency-free witness uses the same entry count and unique-key shape while proving that the repaired lookup work remains linear.
