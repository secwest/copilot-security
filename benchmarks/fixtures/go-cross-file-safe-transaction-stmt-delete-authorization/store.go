package invoices

import (
	"context"
	"database/sql"
)

func DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
	baseStmt, err := db.PrepareContext(ctx, "DELETE FROM invoices WHERE id = ? AND account_id = ?")
	if err != nil {
		return err
	}
	defer baseStmt.Close()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	txStmt := tx.StmtContext(ctx, baseStmt)
	defer txStmt.Close()
	if _, err := txStmt.ExecContext(ctx, invoiceID, accountID); err != nil {
		return err
	}
	return tx.Commit()
}
