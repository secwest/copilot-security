package pgconnsearch

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgconn"
)

func SearchHandler(conn *pgconn.PgConn, w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query()["status"][0]
	for _, name := range Search(r.Context(), conn, status) {
		_, _ = w.Write([]byte(name))
	}
}
