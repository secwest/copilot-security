package service

import (
	"context"
	"database/sql"
	parent "example.com/go-cross-package-safe-imported-helper-multi-branch-write-authorization/internal/parent"
)

type Service struct {
	layer parent.Layer
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

func (service *Service) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
	selected := invoiceID
	return service.layer.Holder.Repository.DeleteInvoice(ctx, db, selected, accountID)
}
