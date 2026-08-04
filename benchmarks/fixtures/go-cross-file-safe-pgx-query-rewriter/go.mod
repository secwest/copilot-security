module example.com/copilot-security/go-cross-file-safe-pgx-query-rewriter

go 1.26

require github.com/jackc/pgx/v5 v5.10.0

replace github.com/jackc/pgx/v5 => ./pgxstub
