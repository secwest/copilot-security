package pgconnsearch

import (
	"context"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestBoundParameterRemainsOneValue(t *testing.T) {
	conn := &pgconn.PgConn{}
	attack := "public' OR visibility = 'internal' --"
	if names := Search(context.Background(), conn, attack); slices.Contains(names, "internal-signing-key") {
		t.Fatalf("bound attack bytes escaped into query grammar: %v", names)
	}
	if !slices.Contains(Search(context.Background(), conn, "public"), "public-status") {
		t.Fatal("allowed public status did not return its intended row")
	}
}
