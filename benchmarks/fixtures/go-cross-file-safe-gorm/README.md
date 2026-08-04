# Go cross-file safe GORM control

The request value crosses the same function boundary as the vulnerable fixture but remains a bound value after a fixed `Raw` query template. The deterministic local GORM adapter proves the attack string cannot change SQL grammar or expose the internal record.
