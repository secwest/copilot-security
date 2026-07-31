# Decompression-bomb fixture

The importer accepts attacker-controlled raw-DEFLATE entries and inflates each
one completely before writing it. It does not bound compressed input, actual
expanded output, expansion ratio, entry count, per-entry output, or cumulative
bundle output, and it trusts no resource budget before allocation.
