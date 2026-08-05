package invoicesvc

import (
	"context"
	"database/sql"
	repository "example.com/go-cross-package-safe-method-interface-delete-authorization/internal/invoicestore"
)

type InvoiceRepository interface {
	DeleteInvoice(context.Context, *sql.DB, string, string) error
}

type Service struct{}

func (*Service) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
	selected := invoiceID
	owner := accountID
	var invoices InvoiceRepository = &repository.Store{}
	return invoices.DeleteInvoice(ctx, db, selected, owner)
}
