package invoices

import (
	"context"
	"database/sql"
	factory "example.com/go-cross-package-safe-transaction-function-value-delete-authorization/internal/txfactory"
	guard "example.com/go-cross-package-safe-transaction-function-value-delete-authorization/internal/txguard"
)

func DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
	begin := factory.StartTransaction
	tx, err := begin(ctx, db)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "DELETE FROM invoices WHERE id = ? AND account_id = ?", invoiceID, accountID); err != nil {
		return err
	}
	finish := guard.FinalizeTransaction
	return finish(tx)
}
