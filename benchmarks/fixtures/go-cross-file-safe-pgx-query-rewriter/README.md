# Safe pgx QueryRewriter control

The control uses the same handler, custom rewriter, request bytes, and local
pgx-compatible witness as the exploit. `RewriteQuery` returns fixed SQL first
and the request field only in the returned arguments. The attack text remains
one bound value while the intended `public` input still returns its row.
