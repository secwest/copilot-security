package invoices

import (
	"database/sql"
	service "example.com/go-cross-package-promoted-method-delete-idor/internal/service"
	store "example.com/go-cross-package-promoted-method-delete-idor/internal/store"
	"net/http"
)

func InvoiceDeleteHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	invoiceID := r.PathValue("invoiceID")
	invoices := service.NewService(&store.Store{})
	if err := invoices.DeleteInvoice(r.Context(), db, invoiceID); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
