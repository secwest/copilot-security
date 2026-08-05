package txguard

import (
	"database/sql"
	leaf "example.com/go-cross-package-safe-transaction-function-value-delete-authorization/internal/txleaf"
)

func FinalizeTransaction(tx *sql.Tx) error {
	commit := leaf.CommitTransaction
	return commit(tx)
}
