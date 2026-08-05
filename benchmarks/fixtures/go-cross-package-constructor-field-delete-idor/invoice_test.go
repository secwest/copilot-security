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
	if query != "DELETE FROM invoices WHERE id = ?" || len(arguments) != 1 {
		return nil, errors.New("unexpected constructor-field mutation")
	}
	invoiceID, ok := arguments[0].Value.(string)
	if !ok {
		return nil, errors.New("invoice ID is not a string")
	}
	if _, exists := connection.state.owners[invoiceID]; !exists {
		return driver.RowsAffected(0), nil
	}
	delete(connection.state.owners, invoiceID)
	return driver.RowsAffected(1), nil
}

func TestAttackerDeletesVictimThroughConstructorAndField(t *testing.T) {
	state := &invoiceState{owners: map[string]string{
		"victim-invoice": "victim-account",
	}}
	sql.Register("constructor-field-delete-idor-witness", constructorFieldDriver{state: state})
	db, err := sql.Open("constructor-field-delete-idor-witness", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	request := httptest.NewRequest("DELETE", "/invoices/victim-invoice", nil)
	request.SetPathValue("invoiceID", "victim-invoice")
	response := httptest.NewRecorder()
	InvoiceDeleteHandler(db, response, request)
	if response.Code != 204 {
		t.Fatalf("unexpected response: code=%d body=%q", response.Code, response.Body.String())
	}
	if _, exists := state.owners["victim-invoice"]; exists {
		t.Fatal("victim deletion did not pass through the constructor and concrete field")
	}
}
