package search

import (
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

func SearchHandler(pool *pgxpool.Pool, w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query()["status"][0]
	secrets, err := Search(r.Context(), pool, status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte(strings.Join(secrets, "\n")))
}
