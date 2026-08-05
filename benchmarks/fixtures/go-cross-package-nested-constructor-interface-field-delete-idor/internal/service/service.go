package service

import (
	"context"
	"database/sql"
)

type InvoiceRepository interface {
	DeleteInvoice(context.Context, *sql.DB, string) error
}

type repositoryLayer struct {
	repository InvoiceRepository
	label      string
}

type Service struct {
	layer *repositoryLayer
	label string
}

func NewService(repository InvoiceRepository, label string) *Service {
	service := &Service{
		layer: &repositoryLayer{repository: repository, label: label},
		label: label,
	}
	return service
}

func (service *Service) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID string) error {
	selected := invoiceID
	return service.layer.repository.DeleteInvoice(ctx, db, selected)
}
