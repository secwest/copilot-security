package invoices

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

type listDriver struct{}

func (listDriver) Open(string) (driver.Conn, error) { return listConn{}, nil }

type listConn struct{}

func (listConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not used")
}
func (listConn) Close() error              { return nil }
func (listConn) Begin() (driver.Tx, error) { return nil, errors.New("transactions are not used") }
func (listConn) QueryContext(_ context.Context, _ string, arguments []driver.NamedValue) (driver.Rows, error) {
	if len(arguments) != 2 {
		return &listRows{}, nil
	}
	projectID, accountID := arguments[0].Value, arguments[1].Value
	if projectID == "victim-project" && accountID == "victim-account" {
		return &listRows{values: [][]driver.Value{{"victim-signing-key"}, {"victim-recovery-code"}}}, nil
	}
	if projectID == "attacker-project" && accountID == "attacker-account" {
		return &listRows{values: [][]driver.Value{{"attacker-document"}}}, nil
	}
	return &listRows{}, nil
}

type listRows struct {
	values [][]driver.Value
	index  int
}

func (*listRows) Columns() []string { return []string{"secret"} }
func (*listRows) Close() error      { return nil }
func (rows *listRows) Next(destination []driver.Value) error {
	if rows.index >= len(rows.values) {
		return io.EOF
	}
	copy(destination, rows.values[rows.index])
	rows.index++
	return nil
}

func requestProject(t *testing.T, db *sql.DB, accountID, projectID string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest("GET", "/projects/"+projectID+"/invoices", nil)
	request.SetPathValue("projectID", projectID)
	request = request.WithContext(context.WithValue(request.Context(), authenticatedAccountIDKey, accountID))
	response := httptest.NewRecorder()
	ProjectInvoicesHandler(db, response, request)
	return response
}

func TestAuthorizationPredicateScopesInvoiceCollection(t *testing.T) {
	sql.Register("safe-list-authorization-witness", listDriver{})
	db, err := sql.Open("safe-list-authorization-witness", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	blocked := requestProject(t, db, "attacker-account", "victim-project")
	if strings.Contains(blocked.Body.String(), "victim-signing-key") || blocked.Body.Len() != 0 {
		t.Fatalf("cross-account collection read was not blocked: %q", blocked.Body.String())
	}
	owned := requestProject(t, db, "attacker-account", "attacker-project")
	if owned.Code != 200 || owned.Body.String() != "attacker-document\n" {
		t.Fatalf("owned project collection was not returned: code=%d body=%q", owned.Code, owned.Body.String())
	}
}
