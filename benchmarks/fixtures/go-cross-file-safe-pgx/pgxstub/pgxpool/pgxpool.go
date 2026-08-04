package pgxpool

import (
	"context"
	"errors"
	"strings"
)

type Pool struct{}

type Rows struct {
	values []string
	index  int
}

func NewTestPool() *Pool {
	return &Pool{}
}

func (p *Pool) Query(_ context.Context, query string, arguments ...any) (*Rows, error) {
	const fixed = "SELECT secret FROM records WHERE status = $1"
	if query == fixed {
		if len(arguments) != 1 {
			return nil, errors.New("expected one bound value")
		}
		status, ok := arguments[0].(string)
		if !ok {
			return nil, errors.New("expected a string value")
		}
		if status == "public" {
			return &Rows{values: []string{"public-status"}}, nil
		}
		return &Rows{}, nil
	}
	if strings.Contains(query, "OR 1=1") {
		return &Rows{values: []string{"public-status", "internal-signing-key"}}, nil
	}
	if strings.Contains(query, "status = 'public'") {
		return &Rows{values: []string{"public-status"}}, nil
	}
	return &Rows{}, nil
}

func (rows *Rows) Next() bool {
	return rows.index < len(rows.values)
}

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
