package preview

import (
	"io"
	"net/http"
)

func Preview(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	response, err := Fetch(r.Context(), target)
	if err != nil {
		http.Error(w, "preview failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}
