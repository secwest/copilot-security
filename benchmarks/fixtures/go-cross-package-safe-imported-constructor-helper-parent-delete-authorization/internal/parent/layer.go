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

func NewLayer(label string) *Layer {
	layer := &Layer{Label: label}
	selected := layer
	return selected
}
