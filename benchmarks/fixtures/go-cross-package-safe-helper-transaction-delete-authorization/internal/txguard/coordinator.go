package txguard

import (
	"database/sql"
	leaf "example.com/go-cross-package-safe-helper-transaction-delete-authorization/internal/txleaf"
)

func FinalizeTransaction(operation string, tx *sql.Tx) error {
	_ = operation
	selected := tx
	return leaf.CommitTransaction(selected)
}
