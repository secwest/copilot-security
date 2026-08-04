package invoices

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net/http/httptest"
	"testing"
)

type invoiceDriver struct{}

func (invoiceDriver) Open(string) (driver.Conn, error) { return invoiceConn{}, nil }

type invoiceConn struct{}

func (invoiceConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not used")
}
func (invoiceConn) Close() error              { return nil }
func (invoiceConn) Begin() (driver.Tx, error) { return nil, errors.New("transactions are not used") }
func (invoiceConn) QueryContext(_ context.Context, _ string, arguments []driver.NamedValue) (driver.Rows, error) {
	if len(arguments) != 2 {
		return &invoiceRows{}, nil
	}
	invoiceID, accountID := arguments[0].Value, arguments[1].Value
	if invoiceID == "victim-invoice" && accountID == "victim-account" {
		return &invoiceRows{values: [][]driver.Value{{"victim-signing-key"}}}, nil
	}
	if invoiceID == "attacker-invoice" && accountID == "attacker-account" {
		return &invoiceRows{values: [][]driver.Value{{"attacker-document"}}}, nil
	}
	return &invoiceRows{}, nil
}

type invoiceRows struct {
	values [][]driver.Value
	index  int
}

func (*invoiceRows) Columns() []string { return []string{"secret"} }
func (*invoiceRows) Close() error      { return nil }
func (rows *invoiceRows) Next(destination []driver.Value) error {
	if rows.index >= len(rows.values) {
		return io.EOF
	}
	copy(destination, rows.values[rows.index])
	rows.index++
	return nil
}

func requestInvoice(t *testing.T, db *sql.DB, accountID, invoiceID string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest("GET", "/invoices/"+invoiceID, nil)
	request.SetPathValue("invoiceID", invoiceID)
	request = request.WithContext(context.WithValue(request.Context(), authenticatedAccountIDKey, accountID))
	response := httptest.NewRecorder()
	InvoiceHandler(db, response, request)
	return response
}

func TestAuthorizationPredicateBlocksCrossAccountRead(t *testing.T) {
	sql.Register("authorized-invoice-witness", invoiceDriver{})
	db, err := sql.Open("authorized-invoice-witness", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	blocked := requestInvoice(t, db, "attacker-account", "victim-invoice")
	if blocked.Code != 404 || blocked.Body.String() == "victim-signing-key" {
		t.Fatalf("cross-account read was not blocked: code=%d body=%q", blocked.Code, blocked.Body.String())
	}
	owned := requestInvoice(t, db, "attacker-account", "attacker-invoice")
	if owned.Code != 200 || owned.Body.String() != "attacker-document" {
		t.Fatalf("owned invoice was not returned: code=%d body=%q", owned.Code, owned.Body.String())
	}
}
