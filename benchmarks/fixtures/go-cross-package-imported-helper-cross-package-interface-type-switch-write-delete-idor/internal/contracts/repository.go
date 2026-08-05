package contracts

import (
	"context"
	"database/sql"
)

type SelectedRepository interface {
	DeleteInvoice(context.Context, *sql.DB, string) error
}
