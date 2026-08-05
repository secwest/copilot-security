package parent

import (
	ctx "context"
	database "database/sql"
	contracts "example.com/go-cross-package-safe-type-alias-interface-authorization/internal/contracts"
)

type InvoiceID = string

type DeleteRepository interface {
	DeleteInvoice(requestContext ctx.Context, connection *database.DB, invoiceID InvoiceID, accountID string) (failure error)
}

type BaseRepository = DeleteRepository

type InvoiceRepository interface {
	BaseRepository
}

type RepositoryAlias = InvoiceRepository

type Holder struct {
	Repository RepositoryAlias
}

type Layer struct {
	Holder *Holder
	Label  string
}

func NewLayer(repository RepositoryAlias, label string) Layer {
	layer := Layer{Holder: &Holder{}, Label: label}
	first := layer
	second := layer
	third := layer
	candidate := contracts.SelectedAlias(repository)
	selectedRepository := candidate
	switch selected := selectedRepository.(type) {
	case nil:
		_ = selected
		first.Holder.Repository = repository
	case contracts.SelectedAlias:
		second.Holder.Repository = repository
	default:
		third.Holder.Repository = repository
	}
	return layer
}
