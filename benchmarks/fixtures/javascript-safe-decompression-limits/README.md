# Safe decompression-limits fixture

The importer snapshots and caps bundle entry count, uses bounded index
iteration, snapshots entry fields and compressed bytes, rejects duplicate
names, validates compressed and declared sizes, caps actual output while
inflating, verifies the observed size, rejects excessive expansion ratios, and
enforces cumulative compressed-input and expanded-output budgets. Entries are
staged until the complete bundle validates, so an invalid suffix cannot leave a
stored prefix. Invalid streams fail closed while ordinary incompressible entries
remain usable.
