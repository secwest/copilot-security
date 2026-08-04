package pgconn

import (
	"context"
	"strings"
)

type Result struct {
	Rows [][][]byte
}

type MultiResultReader struct {
	results []Result
}

func (reader *MultiResultReader) ReadAll() []Result {
	return reader.results
}

type ResultReader struct {
	result Result
}

func (reader *ResultReader) Read() *Result {
	return &reader.result
}

type PgConn struct{}

func result(names ...string) Result {
	rows := make([][][]byte, 0, len(names))
	for _, name := range names {
		rows = append(rows, [][]byte{[]byte(name)})
	}
	return Result{Rows: rows}
}

func exactStatus(status string) Result {
	switch status {
	case "public":
		return result("public-status")
	case "locked":
		return result("internal-signing-key")
	default:
		return Result{}
	}
}

func (conn *PgConn) Exec(_ context.Context, sql string) *MultiResultReader {
	if strings.Contains(sql, "OR visibility = 'internal'") {
		return &MultiResultReader{results: []Result{result("public-status", "internal-signing-key")}}
	}
	marker := "WHERE status = '"
	start := strings.Index(sql, marker)
	if start < 0 {
		return &MultiResultReader{results: []Result{{}}}
	}
	value := sql[start+len(marker):]
	end := strings.IndexByte(value, '\'')
	if end < 0 {
		return &MultiResultReader{results: []Result{{}}}
	}
	return &MultiResultReader{results: []Result{exactStatus(value[:end])}}
}

func (conn *PgConn) ExecParams(_ context.Context, _ string, values [][]byte, _ []uint32, _ []int16, _ []int16) *ResultReader {
	if len(values) != 1 {
		return &ResultReader{}
	}
	return &ResultReader{result: exactStatus(string(values[0]))}
}
