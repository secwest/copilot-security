package service

import (
	"context"
	"database/sql"
)

type InvoiceRepository interface {
	DeleteInvoice(context.Context, *sql.DB, string) error
}

type Service struct {
	repository InvoiceRepository
}

func NewService(repository InvoiceRepository) *Service {
	service := &Service{repository: repository}
	return service
}

func (service *Service) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID string) error {
	selected := invoiceID
	return service.repository.DeleteInvoice(ctx, db, selected)
}
