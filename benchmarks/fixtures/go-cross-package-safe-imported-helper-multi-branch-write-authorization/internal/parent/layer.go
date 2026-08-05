package parent

import (
	"context"
	"database/sql"
)

type InvoiceRepository interface {
	DeleteInvoice(context.Context, *sql.DB, string, string) error
}

type Holder struct {
	Repository InvoiceRepository
}

type Layer struct {
	Holder *Holder
	Label  string
}

func NewLayer(repository InvoiceRepository, label string) Layer {
	layer := Layer{Holder: &Holder{}, Label: label}
	first := layer
	second := layer
	third := layer
	if label == "primary" {
		first.Holder.Repository = repository
	} else if label == "secondary" {
		second.Holder.Repository = repository
	} else {
		third.Holder.Repository = repository
	}
	return layer
}
