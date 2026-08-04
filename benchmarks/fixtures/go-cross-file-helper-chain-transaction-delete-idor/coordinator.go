package invoices

import "database/sql"

func FinalizeTransaction(operation string, tx *sql.Tx) error {
	_ = operation
	selected := tx
	return CommitTransaction(selected)
}
