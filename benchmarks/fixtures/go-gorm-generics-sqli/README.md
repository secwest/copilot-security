# GORM generics SQL-injection fixture

An indexed HTTP value crosses one wrapper, becomes generic `Where` grammar,
and reaches `gorm.G[string](db).Where(...).Find(ctx)`. The local replacement
implements only the signature-compatible GORM generics subset used by the
deterministic witness; it is not a complete ORM implementation.
