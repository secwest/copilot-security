package render

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("GO_SHELL_WITNESS") == "1" {
		command := strings.Join(os.Args[1:], " ")
		if strings.Contains(command, "expose-internal") {
			fmt.Print("internal-signing-key")
		} else if strings.Contains(command, "render --format text") {
			fmt.Print("public-format")
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func installManualShellWitness(t *testing.T) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	program, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	name := "sh"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, name), program, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GO_SHELL_WITNESS", "1")
	t.Setenv("GO_SHELL_WITNESS_DIR", directory)
}

func TestFixedManualSelectionRejectsShellGrammar(t *testing.T) {
	installManualShellWitness(t)
	attack := httptest.NewRequest(
		"GET",
		"/render?format=text%3B%20expose-internal",
		nil,
	)
	attackResponse := httptest.NewRecorder()
	RenderHandler(attackResponse, attack)
	if strings.Contains(attackResponse.Body.String(), "internal-signing-key") {
		t.Fatalf("fixed manual selection exposed the internal record: %q", attackResponse.Body.String())
	}

	allowed := httptest.NewRequest("GET", "/render?format=text", nil)
	allowedResponse := httptest.NewRecorder()
	RenderHandler(allowedResponse, allowed)
	if !strings.Contains(allowedResponse.Body.String(), "public-format") {
		t.Fatalf("safe manual command did not return its intended output: %q", allowedResponse.Body.String())
	}
}
