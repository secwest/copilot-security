package invoices

import (
	"database/sql"
	primary "example.com/go-cross-package-imported-helper-aliased-type-switch-write-delete-idor/internal/primary"
	service "example.com/go-cross-package-imported-helper-aliased-type-switch-write-delete-idor/internal/service"
	"net/http"
)

func InvoiceDeleteHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	invoiceID := r.PathValue("invoiceID")
	repository := &primary.Store{}
	invoices := service.NewService(repository, "primary")
	if err := invoices.DeleteInvoice(r.Context(), db, invoiceID); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
