package invoices

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http/httptest"
	"testing"
)

type invoiceState struct {
	owners map[string]string
}

type constructorFieldDriver struct {
	state *invoiceState
}

func (driver_ constructorFieldDriver) Open(string) (driver.Conn, error) {
	return &constructorFieldConn{state: driver_.state}, nil
}

type constructorFieldConn struct {
	state *invoiceState
}

func (*constructorFieldConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not used")
}
func (*constructorFieldConn) Close() error { return nil }
func (*constructorFieldConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not used")
}
func (connection *constructorFieldConn) ExecContext(_ context.Context, query string, arguments []driver.NamedValue) (driver.Result, error) {
	if query != "DELETE FROM invoices WHERE id = ? AND account_id = ?" || len(arguments) != 2 {
		return nil, errors.New("unexpected authorized constructor-field mutation")
	}
	invoiceID, invoiceOK := arguments[0].Value.(string)
	accountID, accountOK := arguments[1].Value.(string)
	if !invoiceOK || !accountOK {
		return nil, errors.New("authorization values are not strings")
	}
	if connection.state.owners[invoiceID] != accountID {
		return driver.RowsAffected(0), nil
	}
	delete(connection.state.owners, invoiceID)
	return driver.RowsAffected(1), nil
}

func requestDelete(t *testing.T, db *sql.DB, accountID, invoiceID string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest("DELETE", "/invoices/"+invoiceID, nil)
	request.SetPathValue("invoiceID", invoiceID)
	request = request.WithContext(context.WithValue(request.Context(), authenticatedAccountIDKey, accountID))
	response := httptest.NewRecorder()
	InvoiceDeleteHandler(db, response, request)
	return response
}

func TestPrincipalPredicateScopesConstructorFieldDeletion(t *testing.T) {
	state := &invoiceState{owners: map[string]string{
		"victim-invoice":   "victim-account",
		"attacker-invoice": "attacker-account",
	}}
	sql.Register("authorized-constructor-field-witness", constructorFieldDriver{state: state})
	db, err := sql.Open("authorized-constructor-field-witness", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	blocked := requestDelete(t, db, "attacker-account", "victim-invoice")
	if blocked.Code != 204 {
		t.Fatalf("unexpected denied-delete response: code=%d body=%q", blocked.Code, blocked.Body.String())
	}
	if state.owners["victim-invoice"] != "victim-account" {
		t.Fatal("cross-account constructor-field deletion succeeded")
	}

	owned := requestDelete(t, db, "attacker-account", "attacker-invoice")
	if owned.Code != 204 {
		t.Fatalf("unexpected owned-delete response: code=%d body=%q", owned.Code, owned.Body.String())
	}
	if _, exists := state.owners["attacker-invoice"]; exists {
		t.Fatal("owned constructor-field deletion did not succeed")
	}
}
