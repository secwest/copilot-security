package invoices

import (
	"database/sql"
	"io"
	"net/http"
)

func WriteInvoice(db *sql.DB, w http.ResponseWriter, invoiceID, accountID string) {
	var secret string
	err := db.QueryRow("SELECT secret FROM invoices WHERE id = ? AND account_id = ?", invoiceID, accountID).Scan(&secret)
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	_, _ = io.WriteString(w, secret)
}
