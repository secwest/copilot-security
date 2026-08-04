package invoices

import (
	"database/sql"
	"net/http"
)

func ProjectInvoicesHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	WriteProjectInvoices(r.Context(), db, w, projectID)
}
