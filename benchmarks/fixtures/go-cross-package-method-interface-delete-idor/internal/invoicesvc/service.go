package invoicesvc

import (
	"context"
	"database/sql"
	repository "example.com/go-cross-package-method-interface-delete-idor/internal/invoicestore"
)

type InvoiceRepository interface {
	DeleteInvoice(context.Context, *sql.DB, string) error
}

type Service struct{}

func (*Service) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID string) error {
	selected := invoiceID
	var invoices InvoiceRepository = &repository.Store{}
	return invoices.DeleteInvoice(ctx, db, selected)
}
