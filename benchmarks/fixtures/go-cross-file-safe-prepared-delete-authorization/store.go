package invoices

import (
	"context"
	"database/sql"
)

func DeleteInvoice(
	ctx context.Context,
	db *sql.DB,
	invoiceID, accountID string,
) error {
	stmt, err := db.PrepareContext(ctx, "DELETE FROM invoices WHERE id = ? AND account_id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, invoiceID, accountID)
	return err
}
