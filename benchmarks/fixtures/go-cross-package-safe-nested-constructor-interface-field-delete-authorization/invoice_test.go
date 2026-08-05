package invoices

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http/httptest"
	"testing"
)

type witnessDriver struct{ owners map[string]string }
type witnessConn struct{ owners map[string]string }

func (driver_ witnessDriver) Open(string) (driver.Conn, error) {
	return &witnessConn{owners: driver_.owners}, nil
}
func (*witnessConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not used")
}
func (*witnessConn) Close() error              { return nil }
func (*witnessConn) Begin() (driver.Tx, error) { return nil, errors.New("transactions are not used") }
func (connection *witnessConn) ExecContext(_ context.Context, query string, arguments []driver.NamedValue) (driver.Result, error) {
	if query != "DELETE FROM invoices WHERE id = ? AND account_id = ?" || len(arguments) != 2 {
		return nil, errors.New("unexpected authorized nested-constructor mutation")
	}
	invoiceID, _ := arguments[0].Value.(string)
	accountID, _ := arguments[1].Value.(string)
	if connection.owners[invoiceID] == accountID {
		delete(connection.owners, invoiceID)
		return driver.RowsAffected(1), nil
	}
	return driver.RowsAffected(0), nil
}

func TestPrincipalScopeSurvivesNestedConstructorFields(t *testing.T) {
	owners := map[string]string{"victim-invoice": "victim-account"}
	sql.Register("safe-nested-constructor-field", witnessDriver{owners: owners})
	db, err := sql.Open("safe-nested-constructor-field", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	request := httptest.NewRequest("DELETE", "/invoices/victim-invoice", nil)
	request.SetPathValue("invoiceID", "victim-invoice")
	request = request.WithContext(context.WithValue(request.Context(), authenticatedAccountIDKey, "attacker-account"))
	response := httptest.NewRecorder()
	InvoiceDeleteHandler(db, response, request)
	if response.Code != 204 || owners["victim-invoice"] != "victim-account" {
		t.Fatalf("principal scope failed: code=%d owners=%v", response.Code, owners)
	}
}
