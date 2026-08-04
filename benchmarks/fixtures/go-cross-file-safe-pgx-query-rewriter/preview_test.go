package search

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReturnedArgumentsKeepAttackTextInert(t *testing.T) {
	request := httptest.NewRequest("GET", "/search?status=public%27+OR+1%3D1+--", nil)
	response := httptest.NewRecorder()
	SearchHandler(pgxpool.NewTestPool(), response, request)
	if response.Code != 200 {
		t.Fatalf("unexpected status: %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "internal-signing-key") {
		t.Fatalf("returned argument escaped its value boundary: %q", response.Body.String())
	}

	controlRequest := httptest.NewRequest("GET", "/search?status=public", nil)
	controlResponse := httptest.NewRecorder()
	SearchHandler(pgxpool.NewTestPool(), controlResponse, controlRequest)
	if !strings.Contains(controlResponse.Body.String(), "public-status") {
		t.Fatalf("expected public control row: %q", controlResponse.Body.String())
	}
}
