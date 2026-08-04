# Safe pgconn SQL fixture

This matched offline module uses the same exact pgx v5 replacement and request bytes as the vulnerable fixture, but keeps SQL fixed and passes the request value only in `ExecParams` parameter bytes. The preview test proves the injected predicate remains one value while an allowed value still returns its intended row.
