package invoices

import (
	"database/sql"
	"net/http"
)

func InvoiceHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	invoiceID := r.PathValue("invoiceID")
	WriteInvoice(db, w, invoiceID)
}
