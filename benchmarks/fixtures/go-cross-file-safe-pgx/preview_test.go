package search

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestBoundMetacharactersRemainOneValue(t *testing.T) {
	pool := pgxpool.NewTestPool()
	attack := httptest.NewRequest("GET", "/search?status=public%27+OR+1%3D1+--", nil)
	attackResponse := httptest.NewRecorder()
	SearchHandler(pool, attackResponse, attack)
	if attackResponse.Code != 200 {
		t.Fatalf("unexpected attack status: %d", attackResponse.Code)
	}
	if strings.Contains(attackResponse.Body.String(), "internal-signing-key") {
		t.Fatalf("bound value changed query grammar: %q", attackResponse.Body.String())
	}
	allowed := httptest.NewRequest("GET", "/search?status=public", nil)
	allowedResponse := httptest.NewRecorder()
	SearchHandler(pool, allowedResponse, allowed)
	if allowedResponse.Body.String() != "public-status" {
		t.Fatalf("allowed bound value did not return its row: %q", allowedResponse.Body.String())
	}
}
