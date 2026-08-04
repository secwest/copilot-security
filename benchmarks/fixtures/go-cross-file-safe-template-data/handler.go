package safetemplatepreview

import "net/http"

func PreviewHandler(w http.ResponseWriter, r *http.Request) {
	content := r.URL.Query().Get("template")
	if err := RenderPreview(w, content); err != nil {
		http.Error(w, "invalid preview", http.StatusBadRequest)
	}
}
