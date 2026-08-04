package invoices

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http/httptest"
	"testing"
)

type invoiceState struct {
	owners map[string]string
}

type mutationDriver struct {
	state *invoiceState
}

func (driver_ mutationDriver) Open(string) (driver.Conn, error) {
	return mutationConn{state: driver_.state}, nil
}

type mutationConn struct {
	state *invoiceState
}

func (connection mutationConn) Prepare(query string) (driver.Stmt, error) {
	return &mutationStmt{state: connection.state, query: query}, nil
}
func (mutationConn) Close() error { return nil }
func (mutationConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not used")
}

type mutationStmt struct {
	state *invoiceState
	query string
}

func (*mutationStmt) Close() error  { return nil }
func (*mutationStmt) NumInput() int { return 1 }
func (statement *mutationStmt) Exec(arguments []driver.Value) (driver.Result, error) {
	if statement.query != "DELETE FROM invoices WHERE id = ?" || len(arguments) != 1 {
		return nil, errors.New("unexpected prepared mutation")
	}
	invoiceID, ok := arguments[0].(string)
	if !ok {
		return nil, errors.New("invoice ID is not a string")
	}
	if _, exists := statement.state.owners[invoiceID]; !exists {
		return driver.RowsAffected(0), nil
	}
	delete(statement.state.owners, invoiceID)
	return driver.RowsAffected(1), nil
}
func (*mutationStmt) Query([]driver.Value) (driver.Rows, error) {
	return nil, errors.New("queries are not used")
}

func TestAttackerCanDeleteVictimInvoice(t *testing.T) {
	state := &invoiceState{owners: map[string]string{
		"victim-invoice": "victim-account",
	}}
	sql.Register("prepared-delete-idor-witness", mutationDriver{state: state})
	db, err := sql.Open("prepared-delete-idor-witness", "")
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
		t.Fatal("attacker-selected victim invoice was not deleted")
	}
}
