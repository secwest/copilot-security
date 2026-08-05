package invoicesvc

import (
	"context"
	"database/sql"
	repository "example.com/go-cross-package-safe-wrapper-chain-delete-authorization/internal/invoicestore"
)

func DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
	selected := invoiceID
	owner := accountID
	return repository.DeleteInvoice(ctx, db, selected, owner)
}
