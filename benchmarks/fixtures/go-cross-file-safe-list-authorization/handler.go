package invoices

import (
	"database/sql"
	"net/http"
)

type authenticatedAccountIDContextKey struct{}

var authenticatedAccountIDKey authenticatedAccountIDContextKey

func ProjectInvoicesHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	accountID, ok := r.Context().Value(authenticatedAccountIDKey).(string)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	WriteProjectInvoices(r.Context(), db, w, projectID, accountID)
}
