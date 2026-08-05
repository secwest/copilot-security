package archive

import (
	"context"
	"database/sql"
)

type Store struct{}

func (*Store) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID string) error {
	_, err := db.ExecContext(ctx, "DELETE FROM archived_invoices WHERE id = ?", invoiceID)
	return err
}
