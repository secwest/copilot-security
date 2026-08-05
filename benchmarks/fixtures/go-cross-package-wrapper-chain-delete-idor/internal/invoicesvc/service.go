package invoicesvc

import (
	"context"
	"database/sql"
	repository "example.com/go-cross-package-wrapper-chain-delete-idor/internal/invoicestore"
)

func DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID string) error {
	selected := invoiceID
	return repository.DeleteInvoice(ctx, db, selected)
}
