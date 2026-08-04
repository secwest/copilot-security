package invoices

import (
	"database/sql"
	"net/http"
)

type authenticatedAccountIDContextKey struct{}

var authenticatedAccountIDKey authenticatedAccountIDContextKey

func InvoiceHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	invoiceID := r.PathValue("invoiceID")
	accountID, ok := r.Context().Value(authenticatedAccountIDKey).(string)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	WriteInvoice(db, w, invoiceID, accountID)
}
