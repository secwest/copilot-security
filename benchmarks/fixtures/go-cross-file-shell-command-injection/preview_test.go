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

func installShellWitness(t *testing.T) {
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
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GO_SHELL_WITNESS", "1")
}

func TestRequestDerivedShellGrammarExposesInternalRecord(t *testing.T) {
	installShellWitness(t)
	request := httptest.NewRequest(
		"GET",
		"/render?format=text%3B%20expose-internal",
		nil,
	)
	response := httptest.NewRecorder()
	RenderHandler(response, request)
	if !strings.Contains(response.Body.String(), "internal-signing-key") {
		t.Fatalf("shell command did not expose the internal record: %q", response.Body.String())
	}
}
