package service

import (
	"context"
	"database/sql"
)

type InvoiceRepository interface {
	DeleteInvoice(context.Context, *sql.DB, string, string) error
}

type Service struct{ repository InvoiceRepository }

func NewService(repository InvoiceRepository) *Service {
	return &Service{repository: repository}
}

func (service *Service) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
	selected := invoiceID
	owner := accountID
	return service.repository.DeleteInvoice(ctx, db, selected, owner)
}
