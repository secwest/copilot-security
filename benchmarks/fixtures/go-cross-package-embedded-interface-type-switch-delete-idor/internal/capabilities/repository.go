package capabilities

import (
	"context"
	"database/sql"
)

type DeleteRepository interface {
	DeleteInvoice(context.Context, *sql.DB, string) error
}
