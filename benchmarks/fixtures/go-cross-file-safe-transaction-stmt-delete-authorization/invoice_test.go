package invoices

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http/httptest"
	"testing"
)

const deleteQuery = "DELETE FROM invoices WHERE id = ? AND account_id = ?"

type invoiceState struct {
	owners map[string]string
}

type statementTransferDriver struct {
	state *invoiceState
}

func (driver_ statementTransferDriver) Open(string) (driver.Conn, error) {
	return &statementTransferConn{state: driver_.state}, nil
}

type statementTransferConn struct {
	state  *invoiceState
	active *statementTransferTx
}

func (connection *statementTransferConn) Prepare(query string) (driver.Stmt, error) {
	if query != deleteQuery {
		return nil, errors.New("unexpected prepared query")
	}
	return &deleteStmt{connection: connection, query: query}, nil
}
func (*statementTransferConn) Close() error { return nil }
func (connection *statementTransferConn) Begin() (driver.Tx, error) {
	if connection.active != nil {
		return nil, errors.New("transaction already active")
	}
	transaction := &statementTransferTx{connection: connection}
	connection.active = transaction
	return transaction, nil
}
func (connection *statementTransferConn) stage(query string, arguments []driver.NamedValue) (driver.Result, error) {
	if connection.active == nil || connection.active.done {
		return nil, errors.New("statement executed outside an active transaction")
	}
	if query != deleteQuery || len(arguments) != 2 {
		return nil, errors.New("unexpected transaction statement execution")
	}
	invoiceID, invoiceOK := arguments[0].Value.(string)
	accountID, accountOK := arguments[1].Value.(string)
	if !invoiceOK || !accountOK {
		return nil, errors.New("authorization values are not strings")
	}
	if connection.state.owners[invoiceID] != accountID {
		return driver.RowsAffected(0), nil
	}
	connection.active.staged = append(connection.active.staged, invoiceID)
	return driver.RowsAffected(1), nil
}

type deleteStmt struct {
	connection *statementTransferConn
	query      string
}

func (*deleteStmt) Close() error  { return nil }
func (*deleteStmt) NumInput() int { return 2 }
func (statement *deleteStmt) Exec(arguments []driver.Value) (driver.Result, error) {
	named := make([]driver.NamedValue, len(arguments))
	for index, value := range arguments {
		named[index] = driver.NamedValue{Ordinal: index + 1, Value: value}
	}
	return statement.connection.stage(statement.query, named)
}
func (*deleteStmt) Query([]driver.Value) (driver.Rows, error) {
	return nil, errors.New("query is not supported")
}
func (statement *deleteStmt) ExecContext(_ context.Context, arguments []driver.NamedValue) (driver.Result, error) {
	return statement.connection.stage(statement.query, arguments)
}

type statementTransferTx struct {
	connection *statementTransferConn
	staged     []string
	done       bool
}

func (transaction *statementTransferTx) Commit() error {
	if transaction.done {
		return errors.New("transaction already finalized")
	}
	for _, invoiceID := range transaction.staged {
		delete(transaction.connection.state.owners, invoiceID)
	}
	transaction.done = true
	transaction.connection.active = nil
	return nil
}
func (transaction *statementTransferTx) Rollback() error {
	if transaction.done {
		return errors.New("transaction already finalized")
	}
	transaction.staged = nil
	transaction.done = true
	transaction.connection.active = nil
	return nil
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

func TestPrincipalPredicateScopesTransferredStatementDeletion(t *testing.T) {
	state := &invoiceState{owners: map[string]string{
		"victim-invoice":   "victim-account",
		"attacker-invoice": "attacker-account",
	}}
	sql.Register("authorized-transaction-stmt-witness", statementTransferDriver{state: state})
	db, err := sql.Open("authorized-transaction-stmt-witness", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	blocked := requestDelete(t, db, "attacker-account", "victim-invoice")
	if blocked.Code != 204 {
		t.Fatalf("unexpected denied-delete response: code=%d body=%q", blocked.Code, blocked.Body.String())
	}
	if state.owners["victim-invoice"] != "victim-account" {
		t.Fatal("cross-account transferred-statement deletion was committed")
	}

	owned := requestDelete(t, db, "attacker-account", "attacker-invoice")
	if owned.Code != 204 {
		t.Fatalf("unexpected owned-delete response: code=%d body=%q", owned.Code, owned.Body.String())
	}
	if _, exists := state.owners["attacker-invoice"]; exists {
		t.Fatal("owned transferred-statement deletion was not committed")
	}
}
