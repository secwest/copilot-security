package render

import (
	"context"
	"errors"
	"os"
	"os/exec"
)

var manualFormats = map[string]string{
	"json": "render --format json",
	"text": "render --format text",
}

func Render(ctx context.Context, format string) ([]byte, error) {
	command, ok := manualFormats[format]
	if !ok {
		return nil, errors.New("unsupported format")
	}
	process := &exec.Cmd{Path: "sh", Dir: os.Getenv("GO_SHELL_WITNESS_DIR")}
	process.Args = []string{"sh", "-c", command}
	return process.CombinedOutput()
}
