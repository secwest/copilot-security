package squirrel

import (
	"database/sql"
	"strings"
)

type BaseRunner interface {
	Exec(string, ...any) (sql.Result, error)
	Query(string, ...any) (*sql.Rows, error)
}

type SelectBuilder struct {
	runner     BaseRunner
	columns    []string
	from       string
	predicates []string
	arguments  []any
}

func Select(columns ...string) SelectBuilder {
	return SelectBuilder{columns: columns}
}

func (builder SelectBuilder) From(from string) SelectBuilder {
	builder.from = from
	return builder
}

func (builder SelectBuilder) Where(predicate any, arguments ...any) SelectBuilder {
	builder.predicates = append(builder.predicates, predicate.(string))
	builder.arguments = append(builder.arguments, arguments...)
	return builder
}

func (builder SelectBuilder) RunWith(runner BaseRunner) SelectBuilder {
	builder.runner = runner
	return builder
}

func (builder SelectBuilder) Query() (*sql.Rows, error) {
	query := "SELECT " + strings.Join(builder.columns, ", ") + " FROM " + builder.from
	if len(builder.predicates) > 0 {
		query += " WHERE " + strings.Join(builder.predicates, " AND ")
	}
	return builder.runner.Query(query, builder.arguments...)
}
