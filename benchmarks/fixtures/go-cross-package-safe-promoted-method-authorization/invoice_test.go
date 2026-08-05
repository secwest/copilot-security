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
		return nil, errors.New("unexpected authorized promoted-method mutation")
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

func TestPromotedMethodPreservesOwnership(t *testing.T) {
	victimDeleted := false
	ownedDeleted := false
	sql.Register("promoted-method-authorization", witnessDriver{victimDeleted: &victimDeleted, ownedDeleted: &ownedDeleted})
	db, err := sql.Open("promoted-method-authorization", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, invoiceID := range []string{"victim-invoice", "owned-invoice"} {
		request := httptest.NewRequest("DELETE", "/invoices/"+invoiceID, nil)
		request.SetPathValue("invoiceID", invoiceID)
		response := httptest.NewRecorder()
		InvoiceDeleteHandler(db, response, authenticatedRequest(request, "attacker-account"))
		if response.Code != 204 {
			t.Fatalf("unexpected status for %s: %d", invoiceID, response.Code)
		}
	}
	if victimDeleted {
		t.Fatal("promoted method crossed the ownership boundary")
	}
	if !ownedDeleted {
		t.Fatal("promoted method did not delete the owned invoice")
	}
}
