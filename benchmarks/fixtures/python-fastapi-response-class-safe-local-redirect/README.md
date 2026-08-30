# FastAPI response-class fixed local redirect

The topology-matched control declares the same official FastAPI response class
and binds the same hostile query string. It percent-encodes that string beneath
a server-owned `/continue?next=` target before returning it. FastAPI therefore
emits a same-origin `Location`; the external URL survives only as inert query
data.
