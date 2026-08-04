package render

import (
	"context"
	"errors"
	"os/exec"
)

var formats = map[string]string{
	"json": "render --format json",
	"text": "render --format text",
}

func Render(ctx context.Context, format string) ([]byte, error) {
	command, ok := formats[format]
	if !ok {
		return nil, errors.New("unsupported format")
	}
	return exec.CommandContext(ctx, "sh", "-c", command).CombinedOutput()
}
