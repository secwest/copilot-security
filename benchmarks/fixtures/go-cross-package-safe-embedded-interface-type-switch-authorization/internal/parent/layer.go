package parent

import (
	ctx "context"
	database "database/sql"
	contracts "example.com/go-cross-package-safe-embedded-interface-type-switch-authorization/internal/contracts"
)

type DeleteRepository interface {
	DeleteInvoice(requestContext ctx.Context, connection *database.DB, invoiceID, accountID string) (failure error)
}

type InvoiceRepository interface {
	DeleteRepository
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
