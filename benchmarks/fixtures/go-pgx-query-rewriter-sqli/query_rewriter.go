package search

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

type SearchQuery struct {
	Status string
}

func (query SearchQuery) RewriteQuery(_ context.Context, _ *pgx.Conn, _ string, _ []any) (string, []any, error) {
	sql := fmt.Sprintf("SELECT secret FROM records WHERE status = '%s'", query.Status)
	return sql, nil, nil
}
