package preview

import (
	"io"
	"net/http"
)

func Preview(w http.ResponseWriter, r *http.Request) {
	destination := r.URL.Query().Get("destination")
	response, err := Fetch(r.Context(), destination)
	if err != nil {
		http.Error(w, "unknown destination", http.StatusBadRequest)
		return
	}
	defer response.Body.Close()
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}
