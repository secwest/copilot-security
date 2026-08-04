package safetemplatepreview

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRequestValueRemainsEscapedTemplateData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(PreviewHandler))
	defer server.Close()

	payload := `{{readSigningKey}}<script>alert(1)</script>`
	response, err := http.Get(server.URL + "/preview?template=" + url.QueryEscape(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if response.StatusCode != http.StatusOK || strings.Contains(text, signingKey) || strings.Contains(text, "<script>") {
		t.Fatalf("expected inert escaped data, got status %d and body %q", response.StatusCode, body)
	}
	if !strings.Contains(text, "{{readSigningKey}}") || !strings.Contains(text, "&lt;script&gt;") {
		t.Fatalf("expected literal escaped payload, got %q", body)
	}
}
