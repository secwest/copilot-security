package service

import (
	"context"
	"database/sql"
)

type InvoiceRepository interface {
	DeleteInvoice(context.Context, *sql.DB, string, string) error
}

type Service struct {
	layer *repositoryLayer
	label string
}

func NewService(repository InvoiceRepository, label string) *Service {
	service := &Service{
		layer: newRepositoryLayer(label),
	}
	selected := service
	selected.layer.repository = repository
	selected.label = label
	return service
}

func (service *Service) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
	selected := invoiceID
	return service.layer.repository.DeleteInvoice(ctx, db, selected, accountID)
}
