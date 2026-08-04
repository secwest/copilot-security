package templatepreview

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestTemplateSourceInvokesServerFunction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(PreviewHandler))
	defer server.Close()

	response, err := http.Get(server.URL + "/preview?template=" + url.QueryEscape("{{readSigningKey}}"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != signingKey {
		t.Fatalf("expected signing-key disclosure, got status %d and body %q", response.StatusCode, body)
	}
}
