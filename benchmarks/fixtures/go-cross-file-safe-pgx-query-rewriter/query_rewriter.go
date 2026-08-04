package search

import (
	"context"

	"github.com/jackc/pgx/v5"
)

type SearchQuery struct {
	Status string
}

func (query SearchQuery) RewriteQuery(_ context.Context, _ *pgx.Conn, _ string, _ []any) (string, []any, error) {
	const sql = "SELECT secret FROM records WHERE status = $1"
	return sql, []any{query.Status}, nil
}
