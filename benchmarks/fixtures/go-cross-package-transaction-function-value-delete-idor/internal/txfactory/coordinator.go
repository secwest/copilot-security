package txfactory

import (
	"context"
	"database/sql"
	leaf "example.com/go-cross-package-transaction-function-value-delete-idor/internal/txleaf"
)

func StartTransaction(ctx context.Context, db *sql.DB) (*sql.Tx, error) {
	open := leaf.OpenTransaction
	return open(ctx, db)
}
