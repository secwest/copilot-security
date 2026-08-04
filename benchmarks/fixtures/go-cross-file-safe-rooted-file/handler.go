package documents

import (
	"net/http"
)

func DocumentHandler(base string, w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	data, err := ReadDocument(base, name)
	if err != nil {
		http.Error(w, "document unavailable", http.StatusNotFound)
		return
	}
	_, _ = w.Write(data)
}
