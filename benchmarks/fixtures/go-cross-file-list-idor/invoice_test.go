package invoices

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

type listDriver struct{}

func (listDriver) Open(string) (driver.Conn, error) { return listConn{}, nil }

type listConn struct{}

func (listConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not used")
}
func (listConn) Close() error              { return nil }
func (listConn) Begin() (driver.Tx, error) { return nil, errors.New("transactions are not used") }
func (listConn) QueryContext(_ context.Context, _ string, arguments []driver.NamedValue) (driver.Rows, error) {
	if len(arguments) == 1 && arguments[0].Value == "victim-project" {
		return &listRows{values: [][]driver.Value{{"victim-signing-key"}, {"victim-recovery-code"}}}, nil
	}
	return &listRows{}, nil
}

type listRows struct {
	values [][]driver.Value
	index  int
}

func (*listRows) Columns() []string { return []string{"secret"} }
func (*listRows) Close() error      { return nil }
func (rows *listRows) Next(destination []driver.Value) error {
	if rows.index >= len(rows.values) {
		return io.EOF
	}
	copy(destination, rows.values[rows.index])
	rows.index++
	return nil
}

func TestAttackerCanListVictimProjectInvoices(t *testing.T) {
	sql.Register("list-idor-witness", listDriver{})
	db, err := sql.Open("list-idor-witness", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	request := httptest.NewRequest("GET", "/projects/victim-project/invoices", nil)
	request.SetPathValue("projectID", "victim-project")
	response := httptest.NewRecorder()
	ProjectInvoicesHandler(db, response, request)
	if !strings.Contains(response.Body.String(), "victim-signing-key") ||
		!strings.Contains(response.Body.String(), "victim-recovery-code") {
		t.Fatalf("victim invoice collection was not disclosed: %q", response.Body.String())
	}
}
