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

func TestRelativeParentBoundaryRejectsTraversal(t *testing.T) {
	workspace := t.TempDir()
	public := filepath.Join(workspace, "public")
	internal := filepath.Join(workspace, "internal")
	if err := os.MkdirAll(public, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(internal, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(public, "report.txt"), []byte("public report"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(internal, "signing-key.txt"), []byte("fixture signing secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		DocumentHandler(public, w, r)
	}))
	defer server.Close()

	attack, err := http.Get(server.URL + "/document?name=" + url.QueryEscape(filepath.Join("..", "internal", "signing-key.txt")))
	if err != nil {
		t.Fatal(err)
	}
	attackBody, err := io.ReadAll(attack.Body)
	attack.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if attack.StatusCode != http.StatusNotFound || string(attackBody) == "fixture signing secret" {
		t.Fatalf("expected traversal rejection, got status %d and body %q", attack.StatusCode, attackBody)
	}

	allowed, err := http.Get(server.URL + "/document?name=" + url.QueryEscape("report.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Body.Close()
	allowedBody, err := io.ReadAll(allowed.Body)
	if err != nil {
		t.Fatal(err)
	}
	if allowed.StatusCode != http.StatusOK || string(allowedBody) != "public report" {
		t.Fatalf("expected allowed public document, got status %d and body %q", allowed.StatusCode, allowedBody)
	}
}
