package service

import (
	"context"
	"database/sql"
	parent "example.com/go-cross-package-safe-imported-constructor-helper-parent-delete-authorization/internal/parent"
)

type Service struct {
	layer *parent.Layer
	label string
}

func NewService(repository parent.InvoiceRepository, label string) *Service {
	service := &Service{
		layer: parent.NewLayer(label),
	}
	selected := service
	selected.layer.Repository = repository
	selected.label = label
	return service
}

func (service *Service) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
	selected := invoiceID
	return service.layer.Repository.DeleteInvoice(ctx, db, selected, accountID)
}
