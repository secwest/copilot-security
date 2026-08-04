package search

import (
	"context"
	"database/sql"
)

func Search(ctx context.Context, db *sql.DB, status string) ([]string, error) {
	const query = "SELECT secret FROM records WHERE owner = 'alice' AND status = ?"
	rows, err := db.QueryContext(ctx, query, status)
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
