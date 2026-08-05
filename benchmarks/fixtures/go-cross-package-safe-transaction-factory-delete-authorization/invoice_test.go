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

type transactionFactoryDriver struct {
	state *invoiceState
}

func (driver_ transactionFactoryDriver) Open(string) (driver.Conn, error) {
	return &transactionFactoryConn{state: driver_.state}, nil
}

type transactionFactoryConn struct {
	state  *invoiceState
	active *transactionFactoryTx
}

func (*transactionFactoryConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not used")
}
func (*transactionFactoryConn) Close() error { return nil }
func (connection *transactionFactoryConn) Begin() (driver.Tx, error) {
	if connection.active != nil {
		return nil, errors.New("transaction already active")
	}
	transaction := &transactionFactoryTx{connection: connection}
	connection.active = transaction
	return transaction, nil
}
func (connection *transactionFactoryConn) ExecContext(_ context.Context, query string, arguments []driver.NamedValue) (driver.Result, error) {
	if connection.active == nil || connection.active.done {
		return nil, errors.New("mutation executed outside an active transaction")
	}
	if query != "DELETE FROM invoices WHERE id = ? AND account_id = ?" || len(arguments) != 2 {
		return nil, errors.New("unexpected transaction mutation")
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

type transactionFactoryTx struct {
	connection *transactionFactoryConn
	staged     []string
	done       bool
}

func (transaction *transactionFactoryTx) Commit() error {
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
func (transaction *transactionFactoryTx) Rollback() error {
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

func TestPrincipalPredicateScopesTransactionFactoryDeletion(t *testing.T) {
	state := &invoiceState{owners: map[string]string{
		"victim-invoice":   "victim-account",
		"attacker-invoice": "attacker-account",
	}}
	sql.Register("authorized-transaction-factory-witness", transactionFactoryDriver{state: state})
	db, err := sql.Open("authorized-transaction-factory-witness", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	blocked := requestDelete(t, db, "attacker-account", "victim-invoice")
	if blocked.Code != 204 {
		t.Fatalf("unexpected denied-delete response: code=%d body=%q", blocked.Code, blocked.Body.String())
	}
	if state.owners["victim-invoice"] != "victim-account" {
		t.Fatal("cross-account transaction-factory deletion became durable")
	}

	owned := requestDelete(t, db, "attacker-account", "attacker-invoice")
	if owned.Code != 204 {
		t.Fatalf("unexpected owned-delete response: code=%d body=%q", owned.Code, owned.Body.String())
	}
	if _, exists := state.owners["attacker-invoice"]; exists {
		t.Fatal("owned transaction-factory deletion did not become durable")
	}
}
