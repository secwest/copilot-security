# Go cross-file GORM SQL injection fixture

The HTTP query value crosses one same-package function boundary, is formatted into SQL query grammar, and reaches `gorm.io/gorm` through a deferred `Raw` builder that is closed by `Scan`. The executable witness uses a deterministic local, signature-compatible GORM subset over `database/sql` to prove that an injected predicate exposes an otherwise internal record without downloading dependencies.
