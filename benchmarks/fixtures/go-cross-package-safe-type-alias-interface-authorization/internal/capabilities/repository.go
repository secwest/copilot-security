package capabilities

import (
	"context"
	"database/sql"
)

type InvoiceID = string

type DeleteRepository interface {
	DeleteInvoice(context.Context, *sql.DB, InvoiceID, string) error
}
