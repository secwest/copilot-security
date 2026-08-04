package gorm

import (
	"context"
	"database/sql"

	"gorm.io/gorm/clause"
)

type Dialector interface {
	Database() *sql.DB
}

type DB struct {
	database *sql.DB
}

func Open(dialector Dialector, _ ...any) (*DB, error) {
	return &DB{database: dialector.Database()}, nil
}

type Interface[T any] interface {
	Where(query any, args ...any) ChainInterface[T]
}

type ChainInterface[T any] interface {
	Where(query any, args ...any) ChainInterface[T]
	Find(context.Context) ([]T, error)
}

type generic[T any] struct {
	database *sql.DB
	query    string
	args     []any
}

func G[T any](db *DB, _ ...clause.Expression) Interface[T] {
	return generic[T]{database: db.database}
}

func (builder generic[T]) Where(query any, args ...any) ChainInterface[T] {
	builder.query = "SELECT secret FROM records WHERE " + query.(string)
	builder.args = args
	return builder
}

func (builder generic[T]) Find(ctx context.Context) ([]T, error) {
	rows, err := builder.database.QueryContext(ctx, builder.query, builder.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []T
	for rows.Next() {
		var item T
		if err := rows.Scan(&item); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
