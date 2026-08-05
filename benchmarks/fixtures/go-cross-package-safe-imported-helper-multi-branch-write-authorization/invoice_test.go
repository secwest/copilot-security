package invoices

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http/httptest"
	"testing"
)

type witnessDriver struct {
	victimDeleted *bool
	ownedDeleted  *bool
}

type witnessConn struct {
	victimDeleted *bool
	ownedDeleted  *bool
}

func (driver_ witnessDriver) Open(string) (driver.Conn, error) {
	return &witnessConn{victimDeleted: driver_.victimDeleted, ownedDeleted: driver_.ownedDeleted}, nil
}

func (*witnessConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not used")
}

func (*witnessConn) Close() error              { return nil }
func (*witnessConn) Begin() (driver.Tx, error) { return nil, errors.New("transactions are not used") }

func (connection *witnessConn) ExecContext(_ context.Context, query string, arguments []driver.NamedValue) (driver.Result, error) {
	if query != "DELETE FROM invoices WHERE id = ? AND account_id = ?" || len(arguments) != 2 {
		return nil, errors.New("unexpected multi-branch helper mutation")
	}
	invoiceID, _ := arguments[0].Value.(string)
	accountID, _ := arguments[1].Value.(string)
	if invoiceID == "victim-invoice" && accountID == "attacker-account" {
		return driver.RowsAffected(0), nil
	}
	if invoiceID == "owned-invoice" && accountID == "attacker-account" {
		*connection.ownedDeleted = true
		return driver.RowsAffected(1), nil
	}
	*connection.victimDeleted = true
	return driver.RowsAffected(1), nil
}

func TestMultiBranchHelperPreservesAuthorization(t *testing.T) {
	victimDeleted := false
	ownedDeleted := false
	sql.Register("multi-branch-helper-safe", witnessDriver{victimDeleted: &victimDeleted, ownedDeleted: &ownedDeleted})
	db, err := sql.Open("multi-branch-helper-safe", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	request := httptest.NewRequest("DELETE", "/invoices/victim-invoice", nil)
	request.SetPathValue("invoiceID", "victim-invoice")
	request = request.WithContext(context.WithValue(request.Context(), authenticatedAccountIDKey, "attacker-account"))
	response := httptest.NewRecorder()
	InvoiceDeleteHandler(db, response, request)
	if response.Code != 204 || victimDeleted {
		t.Fatalf("multi-branch helper crossed ownership: code=%d victimDeleted=%v", response.Code, victimDeleted)
	}

	request = httptest.NewRequest("DELETE", "/invoices/owned-invoice", nil)
	request.SetPathValue("invoiceID", "owned-invoice")
	request = request.WithContext(context.WithValue(request.Context(), authenticatedAccountIDKey, "attacker-account"))
	response = httptest.NewRecorder()
	InvoiceDeleteHandler(db, response, request)
	if response.Code != 204 || !ownedDeleted {
		t.Fatalf("owned deletion failed: code=%d ownedDeleted=%v", response.Code, ownedDeleted)
	}
}
