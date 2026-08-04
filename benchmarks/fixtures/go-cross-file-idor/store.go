package invoices

import (
	"database/sql"
	"io"
	"net/http"
)

func WriteInvoice(db *sql.DB, w http.ResponseWriter, invoiceID string) {
	var secret string
	err := db.QueryRow("SELECT secret FROM invoices WHERE id = ?", invoiceID).Scan(&secret)
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	_, _ = io.WriteString(w, secret)
}
