package invoices

import "database/sql"

func CommitTransaction(tx *sql.Tx) error {
	return tx.Commit()
}
