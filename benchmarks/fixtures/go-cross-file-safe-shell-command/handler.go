package render

import "net/http"

func RenderHandler(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	output, err := Render(r.Context(), format)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, _ = w.Write(output)
}
