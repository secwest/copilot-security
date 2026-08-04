package render

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

func Render(ctx context.Context, format string) ([]byte, error) {
	command := fmt.Sprintf("render --format %s", format)
	process := &exec.Cmd{Path: "sh", Dir: os.Getenv("GO_SHELL_WITNESS_DIR")}
	process.Args = []string{"sh", "-c", command}
	return process.CombinedOutput()
}
