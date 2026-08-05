package invoices

import (
	"context"
	"database/sql"
	service "example.com/go-cross-package-safe-promoted-method-authorization/internal/service"
	store "example.com/go-cross-package-safe-promoted-method-authorization/internal/store"
	"net/http"
)

type authenticatedAccountKey struct{}

var authenticatedAccountIDKey authenticatedAccountKey

func InvoiceDeleteHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	invoiceID := r.PathValue("invoiceID")
	accountID := r.Context().Value(authenticatedAccountIDKey).(string)
	invoices := service.NewService(&store.Store{})
	if err := invoices.DeleteInvoice(r.Context(), db, invoiceID, accountID); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func authenticatedRequest(request *http.Request, accountID string) *http.Request {
	return request.WithContext(context.WithValue(request.Context(), authenticatedAccountIDKey, accountID))
}
