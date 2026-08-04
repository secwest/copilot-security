package invoices

import (
	"context"
	"database/sql"
)

func DeleteInvoice(
	ctx context.Context,
	db *sql.DB,
	invoiceID string,
) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "DELETE FROM invoices WHERE id = ?", invoiceID); err != nil {
		return err
	}
	return tx.Commit()
}
