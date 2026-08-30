# FastAPI fixed local redirect

The topology-matched control binds the same query parameter but percent-encodes
it behind a server-owned absolute-path prefix before constructing the official
`RedirectResponse` through the same relative wrapper. The resulting `Location` remains on the current origin and
contains the untrusted URL only as inert query data.
