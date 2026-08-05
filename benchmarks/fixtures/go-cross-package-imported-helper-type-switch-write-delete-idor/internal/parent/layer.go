package parent

import (
	"context"
	"database/sql"
)

type InvoiceRepository interface {
	DeleteInvoice(context.Context, *sql.DB, string) error
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
	switch selected := repository.(type) {
	case nil:
		_ = selected
		first.Holder.Repository = repository
	case InvoiceRepository:
		second.Holder.Repository = repository
	default:
		third.Holder.Repository = repository
	}
	return layer
}
