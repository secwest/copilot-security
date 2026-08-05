package invoices

import (
	"context"
	"database/sql"
	factory "example.com/go-cross-package-transaction-factory-delete-idor/internal/txfactory"
)

func DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID string) error {
	tx, err := factory.StartTransaction(ctx, db)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "DELETE FROM invoices WHERE id = ?", invoiceID); err != nil {
		return err
	}
	return tx.Commit()
}
