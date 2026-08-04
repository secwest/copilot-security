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
	if len(arguments) == 1 && arguments[0].Value == "victim-invoice" {
		return &invoiceRows{values: [][]driver.Value{{"victim-signing-key"}}}, nil
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

func TestAttackerCanReadVictimInvoice(t *testing.T) {
	sql.Register("idor-invoice-witness", invoiceDriver{})
	db, err := sql.Open("idor-invoice-witness", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	request := httptest.NewRequest("GET", "/invoices/victim-invoice", nil)
	request.SetPathValue("invoiceID", "victim-invoice")
	response := httptest.NewRecorder()
	InvoiceHandler(db, response, request)
	if response.Body.String() != "victim-signing-key" {
		t.Fatalf("victim invoice was not disclosed: %q", response.Body.String())
	}
}
