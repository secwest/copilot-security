package txfactory

import (
	"context"
	"database/sql"
	leaf "example.com/go-cross-package-transaction-factory-delete-idor/internal/txleaf"
)

func StartTransaction(ctx context.Context, db *sql.DB) (*sql.Tx, error) {
	selected := db
	return leaf.OpenTransaction(ctx, selected)
}
