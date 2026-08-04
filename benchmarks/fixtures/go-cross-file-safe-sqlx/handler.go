package search

import (
	"github.com/jmoiron/sqlx"
	"net/http"
	"strings"
)

func SearchHandler(db *sqlx.DB, w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	secrets, err := Search(db, status)
	if err != nil {
		http.Error(w, "search failed", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte(strings.Join(secrets, "\n")))
}
