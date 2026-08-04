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

	"gorm.io/gorm"
)

type witnessDriver struct{}

func (witnessDriver) Open(string) (driver.Conn, error) { return witnessConn{}, nil }

type witnessConn struct{}

func (witnessConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not used by this witness")
}
func (witnessConn) Close() error              { return nil }
func (witnessConn) Begin() (driver.Tx, error) { return nil, errors.New("transactions are not used") }
func (witnessConn) QueryContext(_ context.Context, query string, arguments []driver.NamedValue) (driver.Rows, error) {
	values := [][]driver.Value{}
	if query == "SELECT secret FROM records WHERE owner = 'alice' AND status = ?" && len(arguments) == 1 && arguments[0].Value == "public" {
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

type witnessDialector struct{ database *sql.DB }

func (dialector witnessDialector) Database() *sql.DB { return dialector.database }

func openWitness(t *testing.T) *gorm.DB {
	t.Helper()
	sql.Register("gorm-generics-safe-witness", witnessDriver{})
	database, err := sql.Open("gorm-generics-safe-witness", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	db, err := gorm.Open(witnessDialector{database: database})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestBoundValueCannotAlterGenericQueryGrammar(t *testing.T) {
	db := openWitness(t)
	attack := httptest.NewRequest("GET", "/search?status=%27%20OR%201%3D1%20--", nil)
	attackResponse := httptest.NewRecorder()
	SearchHandler(db, attackResponse, attack)
	if strings.Contains(attackResponse.Body.String(), "internal-signing-key") {
		t.Fatalf("bound value exposed the internal row: %q", attackResponse.Body.String())
	}

	allowed := httptest.NewRequest("GET", "/search?status=public", nil)
	allowedResponse := httptest.NewRecorder()
	SearchHandler(db, allowedResponse, allowed)
	if !strings.Contains(allowedResponse.Body.String(), "public-status") {
		t.Fatalf("safe query did not return its intended row: %q", allowedResponse.Body.String())
	}
}
