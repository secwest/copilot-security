package service

import (
	"context"
	"database/sql"
)

type InvoiceRepository interface {
	DeleteInvoice(context.Context, *sql.DB, string, string) error
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
	return &Service{
		layer: &repositoryLayer{repository: repository, label: label},
		label: label,
	}
}

func (service *Service) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
	selected := invoiceID
	owner := accountID
	return service.layer.repository.DeleteInvoice(ctx, db, selected, owner)
}
