package preview

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestAttackerControlsOutboundDestination(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "mock-cloud-metadata")
	}))
	defer internal.Close()

	preview := httptest.NewServer(http.HandlerFunc(Preview))
	defer preview.Close()

	response, err := http.Get(preview.URL + "/preview?url=" + url.QueryEscape(internal.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "mock-cloud-metadata" {
		t.Fatalf("expected internal response, got %q", body)
	}
}
