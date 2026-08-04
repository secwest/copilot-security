# Go transferred-statement committed object deletion

The DELETE route prepares fixed SQL on a database, transfers that exact
statement into a standard-library transaction with `Tx.StmtContext`, and
executes an attacker-selected invoice ID without principal scope. The offline
driver proves that execution is staged and only `Tx.Commit` makes the victim
deletion durable.
