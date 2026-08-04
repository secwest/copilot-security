package invoices

import (
	"context"
	"database/sql"
	"io"
	"net/http"
)

func WriteProjectInvoices(ctx context.Context, db *sql.DB, w http.ResponseWriter, projectID, accountID string) {
	rows, err := db.QueryContext(ctx, "SELECT secret FROM invoices WHERE project_id = ? AND account_id = ?", projectID, accountID)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var secret string
		if err := rows.Scan(&secret); err != nil {
			return
		}
		_, _ = io.WriteString(w, secret+"\n")
	}
}
