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
func (*mutationStmt) NumInput() int { return 2 }
func (statement *mutationStmt) Exec(arguments []driver.Value) (driver.Result, error) {
	if statement.query != "DELETE FROM invoices WHERE id = ? AND account_id = ?" || len(arguments) != 2 {
		return nil, errors.New("unexpected prepared mutation")
	}
	invoiceID, invoiceOK := arguments[0].(string)
	accountID, accountOK := arguments[1].(string)
	if !invoiceOK || !accountOK {
		return nil, errors.New("authorization values are not strings")
	}
	if statement.state.owners[invoiceID] != accountID {
		return driver.RowsAffected(0), nil
	}
	delete(statement.state.owners, invoiceID)
	return driver.RowsAffected(1), nil
}
func (*mutationStmt) Query([]driver.Value) (driver.Rows, error) {
	return nil, errors.New("queries are not used")
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

func TestPrincipalPredicateBlocksCrossAccountDelete(t *testing.T) {
	state := &invoiceState{owners: map[string]string{
		"victim-invoice":   "victim-account",
		"attacker-invoice": "attacker-account",
	}}
	sql.Register("authorized-prepared-delete-witness", mutationDriver{state: state})
	db, err := sql.Open("authorized-prepared-delete-witness", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	blocked := requestDelete(t, db, "attacker-account", "victim-invoice")
	if blocked.Code != 204 {
		t.Fatalf("unexpected denied-delete response: code=%d body=%q", blocked.Code, blocked.Body.String())
	}
	if state.owners["victim-invoice"] != "victim-account" {
		t.Fatal("cross-account deletion was not blocked")
	}

	owned := requestDelete(t, db, "attacker-account", "attacker-invoice")
	if owned.Code != 204 {
		t.Fatalf("unexpected owned-delete response: code=%d body=%q", owned.Code, owned.Body.String())
	}
	if _, exists := state.owners["attacker-invoice"]; exists {
		t.Fatal("owned invoice was not deleted")
	}
}
