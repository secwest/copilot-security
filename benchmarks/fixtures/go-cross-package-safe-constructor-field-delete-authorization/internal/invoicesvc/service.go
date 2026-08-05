package invoicesvc

import (
	"context"
	"database/sql"
	repository "example.com/go-cross-package-safe-constructor-field-delete-authorization/internal/invoicestore"
)

type Service struct {
	repository repository.Store
}

func NewService() *Service {
	service := &Service{}
	return service
}

func (service *Service) DeleteInvoice(ctx context.Context, db *sql.DB, invoiceID, accountID string) error {
	selected := invoiceID
	owner := accountID
	return service.repository.DeleteInvoice(ctx, db, selected, owner)
}
