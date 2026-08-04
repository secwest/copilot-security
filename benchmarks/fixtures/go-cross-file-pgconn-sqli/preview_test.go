package pgconnsearch

import (
	"context"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestSimpleProtocolInjectionChangesQueryGrammar(t *testing.T) {
	conn := &pgconn.PgConn{}
	attack := "public' OR visibility = 'internal' --"
	names := Search(context.Background(), conn, attack)
	if !slices.Contains(names, "internal-signing-key") {
		t.Fatalf("injected predicate did not expose the internal record: %v", names)
	}
	if !slices.Contains(Search(context.Background(), conn, "public"), "public-status") {
		t.Fatal("allowed public status did not return its intended row")
	}
}
