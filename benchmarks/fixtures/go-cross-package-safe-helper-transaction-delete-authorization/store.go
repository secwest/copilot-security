package invoices

import (
	"context"
	"database/sql"
	guard "example.com/go-cross-package-safe-helper-transaction-delete-authorization/internal/txguard"
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
	return guard.FinalizeTransaction("invoice-delete", tx)
}
