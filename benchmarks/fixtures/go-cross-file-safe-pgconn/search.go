package pgconnsearch

import (
	"context"

	"github.com/jackc/pgx/v5/pgconn"
)

func Search(ctx context.Context, conn *pgconn.PgConn, status string) []string {
	result := conn.ExecParams(
		ctx,
		"SELECT name FROM records WHERE status = $1",
		[][]byte{[]byte(status)},
		nil,
		nil,
		nil,
	).Read()
	names := make([]string, 0, len(result.Rows))
	for _, row := range result.Rows {
		names = append(names, string(row[0]))
	}
	return names
}
