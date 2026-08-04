package invoices

import (
	"context"
	"database/sql"
)

func DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "DELETE FROM invoices WHERE id = ? AND account_id = ?", invoiceID, accountID); err != nil {
		return err
	}
	return FinalizeTransaction("invoice-delete", tx)
}
