# Go cross-file committed object deletion

The DELETE route passes a path-selected invoice ID through one wrapper into a
standard-library transaction. The mutation is staged through `Tx.ExecContext`
and made durable by `Tx.Commit` without principal scope. The offline driver
proves that the committed transaction deletes the victim-owned invoice.
