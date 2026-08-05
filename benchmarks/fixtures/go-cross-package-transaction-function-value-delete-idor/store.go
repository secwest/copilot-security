package invoices

import (
	"context"
	"database/sql"
	factory "example.com/go-cross-package-transaction-function-value-delete-idor/internal/txfactory"
	guard "example.com/go-cross-package-transaction-function-value-delete-idor/internal/txguard"
)

func DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID string) error {
	begin := factory.StartTransaction
	tx, err := begin(ctx, db)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "DELETE FROM invoices WHERE id = ?", invoiceID); err != nil {
		return err
	}
	finish := guard.FinalizeTransaction
	return finish(tx)
}
