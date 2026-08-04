package pgconnsearch

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

func Search(ctx context.Context, conn *pgconn.PgConn, status string) []string {
	query := fmt.Sprintf("SELECT name FROM records WHERE status = '%s'", status)
	results := conn.Exec(ctx, query).ReadAll()
	if len(results) == 0 {
		return nil
	}
	names := make([]string, 0, len(results[0].Rows))
	for _, row := range results[0].Rows {
		names = append(names, string(row[0]))
	}
	return names
}
