package invoices

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http/httptest"
	"testing"
)

type witnessDriver struct{ deleted *bool }
type witnessConn struct{ deleted *bool }

func (driver_ witnessDriver) Open(string) (driver.Conn, error) {
	return &witnessConn{deleted: driver_.deleted}, nil
}

func (*witnessConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not used")
}

func (*witnessConn) Close() error              { return nil }
func (*witnessConn) Begin() (driver.Tx, error) { return nil, errors.New("transactions are not used") }

func (connection *witnessConn) ExecContext(_ context.Context, query string, arguments []driver.NamedValue) (driver.Result, error) {
	if query != "DELETE FROM invoices WHERE id = ?" || len(arguments) != 1 {
		return nil, errors.New("unexpected aliased type switch helper mutation")
	}
	*connection.deleted = true
	return driver.RowsAffected(1), nil
}

func TestAttackerDeletesVictimThroughAliasedTypeSwitchHelper(t *testing.T) {
	deleted := false
	sql.Register("aliased-type-switch-helper-idor", witnessDriver{deleted: &deleted})
	db, err := sql.Open("aliased-type-switch-helper-idor", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	request := httptest.NewRequest("DELETE", "/invoices/victim-invoice", nil)
	request.SetPathValue("invoiceID", "victim-invoice")
	response := httptest.NewRecorder()
	InvoiceDeleteHandler(db, response, request)
	if response.Code != 204 || !deleted {
		t.Fatalf("aliased type switch helper did not delete: code=%d deleted=%v", response.Code, deleted)
	}
}
