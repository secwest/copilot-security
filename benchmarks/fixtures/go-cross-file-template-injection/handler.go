package templatepreview

import "net/http"

func PreviewHandler(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("template")
	if err := RenderPreview(w, source); err != nil {
		http.Error(w, "invalid preview", http.StatusBadRequest)
	}
}
