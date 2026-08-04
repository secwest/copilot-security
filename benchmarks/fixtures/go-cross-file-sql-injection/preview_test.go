package search

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

type witnessDriver struct{}

func (witnessDriver) Open(string) (driver.Conn, error) { return witnessConn{}, nil }

type witnessConn struct{}

func (witnessConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not used by this witness")
}
func (witnessConn) Close() error              { return nil }
func (witnessConn) Begin() (driver.Tx, error) { return nil, errors.New("transactions are not used") }
func (witnessConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	values := [][]driver.Value{}
	if strings.Contains(strings.ToUpper(query), "OR 1=1") {
		values = append(values, []driver.Value{"internal-signing-key"})
	} else if strings.Contains(query, "status = 'public'") {
		values = append(values, []driver.Value{"public-status"})
	}
	return &witnessRows{values: values}, nil
}

type witnessRows struct {
	values [][]driver.Value
	index  int
}

func (*witnessRows) Columns() []string { return []string{"secret"} }
func (*witnessRows) Close() error      { return nil }
func (rows *witnessRows) Next(destination []driver.Value) error {
	if rows.index >= len(rows.values) {
		return io.EOF
	}
	copy(destination, rows.values[rows.index])
	rows.index++
	return nil
}

func TestInjectedPredicateReturnsInternalRecord(t *testing.T) {
	sql.Register("injection-witness", witnessDriver{})
	db, err := sql.Open("injection-witness", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	request := httptest.NewRequest("GET", "/search?status=%27%20OR%201%3D1%20--", nil)
	response := httptest.NewRecorder()
	SearchHandler(db, response, request)
	if !strings.Contains(response.Body.String(), "internal-signing-key") {
		t.Fatalf("injected predicate did not expose the internal row: %q", response.Body.String())
	}
}
