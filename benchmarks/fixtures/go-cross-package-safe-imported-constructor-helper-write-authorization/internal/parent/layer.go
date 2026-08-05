package parent

import (
	"context"
	"database/sql"
)

type InvoiceRepository interface {
	DeleteInvoice(context.Context, *sql.DB, string, string) error
}

type Layer struct {
	Repository InvoiceRepository
	Label      string
}

func NewLayer(repository InvoiceRepository, label string) *Layer {
	layer := &Layer{}
	selected := layer
	selected.Repository = repository
	selected.Label = label
	return layer
}
