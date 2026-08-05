package invoicestore

import (
	"context"
	"database/sql"
)

type Store struct{}

func (*Store) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID string) error {
	_, err := db.ExecContext(ctx, "DELETE FROM invoices WHERE id = ?", invoiceID)
	return err
}
