package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"

	"github.com/labstack/echo/v4"
)

const marker = "inert-echo-static-witness"

func echoVersion(t *testing.T) string {
	t.Helper()
	information, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("build information unavailable")
	}
	for _, dependency := range information.Deps {
		if dependency.Path == "github.com/labstack/echo/v4" {
			return dependency.Version
		}
	}
	t.Fatal("Echo dependency unavailable")
	return ""
}

func TestEncodedSeparatorBoundary(t *testing.T) {
	root := t.TempDir()
	adminDirectory := filepath.Join(root, "admin")
	if err := os.Mkdir(adminDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(adminDirectory, "marker.txt"), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}

	e := echo.New()
	admin := e.Group("/admin", requireSession)
	admin.GET("/*", protectedFile)
	e.StaticFS("/", os.DirFS(root))

	direct := httptest.NewRecorder()
	e.ServeHTTP(direct, httptest.NewRequest(http.MethodGet, "/admin/marker.txt", nil))
	if direct.Code != http.StatusForbidden || direct.Body.String() != "session required" {
		t.Fatalf("direct protected route was not denied: status=%d body=%q", direct.Code, direct.Body.String())
	}

	encoded := httptest.NewRecorder()
	e.ServeHTTP(encoded, httptest.NewRequest(http.MethodGet, "/admin%2Fmarker.txt", nil))
	version := echoVersion(t)
	affected := version == "v4.15.2"
	repaired := version == "v4.15.3"
	if !affected && !repaired {
		t.Fatalf("unexpected Echo version %q", version)
	}
	if affected && (encoded.Code != http.StatusOK || encoded.Body.String() != marker) {
		t.Fatalf("affected build did not reproduce disclosure: status=%d body=%q", encoded.Code, encoded.Body.String())
	}
	if repaired && (encoded.Code != http.StatusNotFound || encoded.Body.String() == marker) {
		t.Fatalf("repaired build did not reject encoded separator: status=%d body=%q", encoded.Code, encoded.Body.String())
	}

	result, err := json.Marshal(map[string]any{
		"affected":        affected,
		"encodedStatus":   encoded.Code,
		"markerDisclosed": encoded.Body.String() == marker,
		"repaired":        repaired,
		"version":         version,
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(result))
}
