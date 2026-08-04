package search

import (
	"database/sql"
	"net/http"
	"strings"
)

func SearchHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	secrets, err := Search(r.Context(), db, status)
	if err != nil {
		http.Error(w, "search failed", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte(strings.Join(secrets, "\n")))
}
