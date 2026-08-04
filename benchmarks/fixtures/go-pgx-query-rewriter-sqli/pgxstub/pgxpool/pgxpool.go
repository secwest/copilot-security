package pgxpool

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

type Pool struct{}

type Rows struct {
	values []string
	index  int
}

func NewTestPool() *Pool { return &Pool{} }

func (pool *Pool) Query(ctx context.Context, sql string, args ...any) (*Rows, error) {
	if len(args) > 0 {
		if rewriter, ok := args[0].(pgx.QueryRewriter); ok {
			var err error
			sql, args, err = rewriter.RewriteQuery(ctx, nil, sql, args[1:])
			if err != nil {
				return nil, err
			}
		}
	}
	const fixed = "SELECT secret FROM records WHERE status = $1"
	if sql == fixed {
		if len(args) != 1 {
			return nil, errors.New("expected one bound value")
		}
		status, ok := args[0].(string)
		if !ok {
			return nil, errors.New("expected a string value")
		}
		if status == "public" {
			return &Rows{values: []string{"public-status"}}, nil
		}
		return &Rows{}, nil
	}
	if strings.Contains(sql, "OR 1=1") {
		return &Rows{values: []string{"public-status", "internal-signing-key"}}, nil
	}
	if strings.Contains(sql, "status = 'public'") {
		return &Rows{values: []string{"public-status"}}, nil
	}
	return &Rows{}, nil
}

func (rows *Rows) Next() bool { return rows.index < len(rows.values) }

func (rows *Rows) Scan(destination ...any) error {
	if rows.index >= len(rows.values) || len(destination) != 1 {
		return errors.New("invalid scan")
	}
	value, ok := destination[0].(*string)
	if !ok {
		return errors.New("expected string destination")
	}
	*value = rows.values[rows.index]
	rows.index++
	return nil
}

func (rows *Rows) Close() {}

func (rows *Rows) Err() error { return nil }
