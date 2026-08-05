package txleaf

import (
	"context"
	"database/sql"
)

func OpenTransaction(ctx context.Context, db *sql.DB) (*sql.Tx, error) {
	return db.BeginTx(ctx, nil)
}
