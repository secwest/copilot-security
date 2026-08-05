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
	switch label {
	case "primary":
		first.Holder.Repository = repository
	case "secondary":
		second.Holder.Repository = repository
	default:
		third.Holder.Repository = repository
	}
	return layer
}
