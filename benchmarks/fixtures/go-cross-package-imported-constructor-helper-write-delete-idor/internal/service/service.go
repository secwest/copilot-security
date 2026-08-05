package service

import (
	"context"
	"database/sql"
	parent "example.com/go-cross-package-imported-constructor-helper-write-delete-idor/internal/parent"
)

type Service struct {
	layer *parent.Layer
	label string
}

func NewService(repository parent.InvoiceRepository, label string) *Service {
	service := &Service{
		layer: parent.NewLayer(repository, label),
	}
	selected := service
	selected.label = label
	return selected
}

func (service *Service) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID string) error {
	selected := invoiceID
	return service.layer.Repository.DeleteInvoice(ctx, db, selected)
}
