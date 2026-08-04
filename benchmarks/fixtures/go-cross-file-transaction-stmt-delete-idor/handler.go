package invoices

import (
	"database/sql"
	"net/http"
)

func InvoiceDeleteHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	invoiceID := r.PathValue("invoiceID")
	if err := DeleteInvoice(r.Context(), db, invoiceID); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
