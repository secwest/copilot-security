package preview

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestServerOwnedSelectionAndRedirectRejection(t *testing.T) {
	var internalHits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		_, _ = io.WriteString(w, "mock-cloud-metadata")
	}))
	defer internal.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL, http.StatusFound)
	}))
	defer redirector.Close()

	previous := destinations["status"]
	destinations["status"] = redirector.URL
	t.Cleanup(func() { destinations["status"] = previous })

	preview := httptest.NewServer(http.HandlerFunc(Preview))
	defer preview.Close()

	attackerResponse, err := http.Get(preview.URL + "/preview?destination=" + url.QueryEscape(internal.URL))
	if err != nil {
		t.Fatal(err)
	}
	attackerResponse.Body.Close()
	if attackerResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected unknown destination rejection, got %d", attackerResponse.StatusCode)
	}

	allowedResponse, err := http.Get(preview.URL + "/preview?destination=status")
	if err != nil {
		t.Fatal(err)
	}
	allowedResponse.Body.Close()
	if allowedResponse.StatusCode != http.StatusFound {
		t.Fatalf("expected un-followed redirect, got %d", allowedResponse.StatusCode)
	}
	if internalHits.Load() != 0 {
		t.Fatal("redirect reached the internal service")
	}
}
