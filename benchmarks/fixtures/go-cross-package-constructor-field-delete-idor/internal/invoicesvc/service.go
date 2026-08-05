package invoicesvc

import (
	"context"
	"database/sql"
	repository "example.com/go-cross-package-constructor-field-delete-idor/internal/invoicestore"
)

type Service struct {
	repository repository.Store
}

func NewService() *Service {
	service := &Service{}
	return service
}

func (service *Service) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID string) error {
	selected := invoiceID
	return service.repository.DeleteInvoice(ctx, db, selected)
}
