package txguard

import (
	"database/sql"
	leaf "example.com/go-cross-package-helper-transaction-delete-idor/internal/txleaf"
)

func FinalizeTransaction(operation string, tx *sql.Tx) error {
	_ = operation
	selected := tx
	return leaf.CommitTransaction(selected)
}
