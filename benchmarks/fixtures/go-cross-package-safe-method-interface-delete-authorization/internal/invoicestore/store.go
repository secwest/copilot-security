package invoicestore

import (
	"context"
	"database/sql"
)

type Store struct{}

func (*Store) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
	_, err := db.ExecContext(ctx, "DELETE FROM invoices WHERE id = ? AND account_id = ?", invoiceID, accountID)
	return err
}
