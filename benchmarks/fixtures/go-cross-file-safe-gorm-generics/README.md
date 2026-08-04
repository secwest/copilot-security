# Safe GORM generics control

This matched control preserves the handler, wrapper, exact generic GORM path,
builder, runner, and attack bytes but supplies the HTTP value only after a
fixed `Where` placeholder. The local replacement implements only the
signature-compatible subset needed by the deterministic witness.
