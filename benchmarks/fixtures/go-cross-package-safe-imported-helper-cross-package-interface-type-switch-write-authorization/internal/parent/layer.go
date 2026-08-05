package parent

import (
	ctx "context"
	database "database/sql"
	contracts "example.com/go-cross-package-safe-imported-helper-cross-package-interface-type-switch-write-authorization/internal/contracts"
)

type InvoiceRepository interface {
	DeleteInvoice(requestContext ctx.Context, connection *database.DB, invoiceID, accountID string) (failure error)
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
	candidate := contracts.SelectedRepository(repository)
	selectedRepository := candidate
	switch selected := selectedRepository.(type) {
	case nil:
		_ = selected
		first.Holder.Repository = repository
	case contracts.SelectedRepository:
		second.Holder.Repository = repository
	default:
		third.Holder.Repository = repository
	}
	return layer
}
