package invoices

import (
	"database/sql"
	primary "example.com/go-cross-package-safe-imported-helper-cross-package-interface-type-switch-write-authorization/internal/primary"
	service "example.com/go-cross-package-safe-imported-helper-cross-package-interface-type-switch-write-authorization/internal/service"
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
	repository := &primary.Store{}
	invoices := service.NewService(repository, "primary")
	if err := invoices.DeleteInvoice(r.Context(), db, invoiceID, accountID); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
