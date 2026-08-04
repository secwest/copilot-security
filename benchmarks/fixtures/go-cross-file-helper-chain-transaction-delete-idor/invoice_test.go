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

type helperChainTransactionDriver struct {
	state *invoiceState
}

func (driver_ helperChainTransactionDriver) Open(string) (driver.Conn, error) {
	return &helperChainTransactionConn{state: driver_.state}, nil
}

type helperChainTransactionConn struct {
	state  *invoiceState
	active *helperChainTransactionTx
}

func (*helperChainTransactionConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not used")
}
func (*helperChainTransactionConn) Close() error { return nil }
func (connection *helperChainTransactionConn) Begin() (driver.Tx, error) {
	if connection.active != nil {
		return nil, errors.New("transaction already active")
	}
	transaction := &helperChainTransactionTx{connection: connection}
	connection.active = transaction
	return transaction, nil
}
func (connection *helperChainTransactionConn) ExecContext(_ context.Context, query string, arguments []driver.NamedValue) (driver.Result, error) {
	if connection.active == nil || connection.active.done {
		return nil, errors.New("mutation executed outside an active transaction")
	}
	if query != "DELETE FROM invoices WHERE id = ?" || len(arguments) != 1 {
		return nil, errors.New("unexpected transaction mutation")
	}
	invoiceID, ok := arguments[0].Value.(string)
	if !ok {
		return nil, errors.New("invoice ID is not a string")
	}
	if _, exists := connection.state.owners[invoiceID]; !exists {
		return driver.RowsAffected(0), nil
	}
	connection.active.staged = append(connection.active.staged, invoiceID)
	return driver.RowsAffected(1), nil
}

type helperChainTransactionTx struct {
	connection *helperChainTransactionConn
	staged     []string
	done       bool
}

func (transaction *helperChainTransactionTx) Commit() error {
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
func (transaction *helperChainTransactionTx) Rollback() error {
	if transaction.done {
		return errors.New("transaction already finalized")
	}
	transaction.staged = nil
	transaction.done = true
	transaction.connection.active = nil
	return nil
}

func TestAttackerCommitsVictimDeletionThroughHelperChain(t *testing.T) {
	state := &invoiceState{owners: map[string]string{
		"victim-invoice": "victim-account",
	}}
	sql.Register("helper-chain-transaction-delete-idor-witness", helperChainTransactionDriver{state: state})
	db, err := sql.Open("helper-chain-transaction-delete-idor-witness", "")
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
		t.Fatal("helper-chain-committed victim deletion did not become durable")
	}
}
