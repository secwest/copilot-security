package search

import (
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

func SearchHandler(pool *pgxpool.Pool, w http.ResponseWriter, r *http.Request) {
	query := SearchQuery{Status: r.FormValue("status")}
	rows, err := pool.Query(r.Context(), "", query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var secrets []string
	for rows.Next() {
		var secret string
		if err := rows.Scan(&secret); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		secrets = append(secrets, secret)
	}
	_, _ = w.Write([]byte(strings.Join(secrets, "\n")))
}
