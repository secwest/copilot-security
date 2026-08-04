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
	stmt, err := db.PrepareContext(ctx, "DELETE FROM invoices WHERE id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, invoiceID)
	return err
}
