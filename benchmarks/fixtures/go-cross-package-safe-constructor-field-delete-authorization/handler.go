package invoices

import (
	"database/sql"
	service "example.com/go-cross-package-safe-constructor-field-delete-authorization/internal/invoicesvc"
	"net/http"
)

type authenticatedAccountIDContextKey struct{}

var authenticatedAccountIDKey authenticatedAccountIDContextKey

func InvoiceDeleteHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	invoiceID := r.PathValue("invoiceID")
	accountID, ok := r.Context().Value(authenticatedAccountIDKey).(string)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	invoices := service.NewService()
	if err := invoices.DeleteInvoice(r.Context(), db, invoiceID, accountID); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
