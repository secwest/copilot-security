package search

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Search(ctx context.Context, pool *pgxpool.Pool, status string) ([]string, error) {
	const query = "SELECT secret FROM records WHERE status = $1"
	rows, err := pool.Query(ctx, query, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var secrets []string
	for rows.Next() {
		var secret string
		if err := rows.Scan(&secret); err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)
	}
	return secrets, rows.Err()
}
