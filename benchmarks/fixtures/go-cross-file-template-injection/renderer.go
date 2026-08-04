package templatepreview

import (
	"io"
	"text/template"
)

const signingKey = "fixture signing secret"

func RenderPreview(output io.Writer, source string) error {
	functions := template.FuncMap{"readSigningKey": func() string { return signingKey }}
	parsed, err := template.New("preview").Funcs(functions).Parse(source)
	if err != nil {
		return err
	}
	return parsed.Execute(output, nil)
}
