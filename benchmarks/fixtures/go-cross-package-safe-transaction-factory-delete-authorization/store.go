package invoices

import (
	"context"
	"database/sql"
	factory "example.com/go-cross-package-safe-transaction-factory-delete-authorization/internal/txfactory"
)

func DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
	tx, err := factory.StartTransaction(ctx, db)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "DELETE FROM invoices WHERE id = ? AND account_id = ?", invoiceID, accountID); err != nil {
		return err
	}
	return tx.Commit()
}
