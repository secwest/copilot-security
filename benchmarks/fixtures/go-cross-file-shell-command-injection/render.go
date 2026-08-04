package render

import (
	"context"
	"fmt"
	"os/exec"
)

func Render(ctx context.Context, format string) ([]byte, error) {
	command := fmt.Sprintf("render --format %s", format)
	return exec.CommandContext(ctx, "sh", "-c", command).CombinedOutput()
}
