# Private-response cache isolation fixture

The origin uses exact route matching and marks authenticated account responses
`private, no-store`. The edge caches only successful responses that explicitly
declare themselves public, refuses requests carrying a session cookie, and
rejects private, no-store, and Set-Cookie responses. Deceptive suffixes never
reach the account handler, while a real public stylesheet still demonstrates a
working shared cache.
