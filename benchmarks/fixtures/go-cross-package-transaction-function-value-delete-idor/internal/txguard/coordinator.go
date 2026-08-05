package txguard

import (
	"database/sql"
	leaf "example.com/go-cross-package-transaction-function-value-delete-idor/internal/txleaf"
)

func FinalizeTransaction(tx *sql.Tx) error {
	commit := leaf.CommitTransaction
	return commit(tx)
}
