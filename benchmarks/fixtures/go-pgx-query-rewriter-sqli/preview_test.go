package search

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRewrittenGrammarExposesInternalRecord(t *testing.T) {
	request := httptest.NewRequest("GET", "/search?status=public%27+OR+1%3D1+--", nil)
	response := httptest.NewRecorder()
	SearchHandler(pgxpool.NewTestPool(), response, request)
	if response.Code != 200 {
		t.Fatalf("unexpected status: %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "internal-signing-key") {
		t.Fatalf("rewritten predicate did not expose the internal record: %q", response.Body.String())
	}
}
