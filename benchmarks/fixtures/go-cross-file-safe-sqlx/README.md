# Go cross-file safe sqlx control

This control preserves the vulnerable fixture's handler, wrapper, sqlx receiver, destination, and database topology while keeping query grammar server-owned and passing the request value only as a placeholder argument. Its deterministic local sqlx adapter proves that the injection payload cannot expose the internal record.
