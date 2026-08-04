package safetemplatepreview

import (
	"html/template"
	"io"
)

const signingKey = "fixture signing secret"

func RenderPreview(output io.Writer, content string) error {
	parsed, err := template.New("preview").Parse(`<p>{{.}}</p>`)
	if err != nil {
		return err
	}
	return parsed.Execute(output, content)
}
