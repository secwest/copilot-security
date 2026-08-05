package documents

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestRelativePathStillReadsSiblingSecret(t *testing.T) {
	workspace := t.TempDir()
	public := filepath.Join(workspace, "public")
	internal := filepath.Join(workspace, "internal")
	if err := os.MkdirAll(public, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(internal, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(internal, "signing-key.txt"), []byte("fixture signing secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		DocumentHandler(public, w, r)
	}))
	defer server.Close()

	response, err := http.Get(server.URL + "/document?name=" + url.QueryEscape(filepath.Join("..", "internal", "signing-key.txt")))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "fixture signing secret" {
		t.Fatalf("expected sibling secret disclosure, got status %d and body %q", response.StatusCode, body)
	}
}
