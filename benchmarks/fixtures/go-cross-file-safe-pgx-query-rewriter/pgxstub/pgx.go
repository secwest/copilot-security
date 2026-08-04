package pgx

import "context"

type Conn struct{}

type QueryRewriter interface {
	RewriteQuery(ctx context.Context, conn *Conn, sql string, args []any) (newSQL string, newArgs []any, err error)
}
