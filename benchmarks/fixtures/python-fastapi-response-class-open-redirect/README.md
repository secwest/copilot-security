# FastAPI response-class open redirect

An official FastAPI GET path operation declares the official
`RedirectResponse` as its `response_class` and returns an attacker-controlled
query string directly. FastAPI constructs the redirect response and places that
string in the HTTP `Location` header. The pinned TestClient witness disables
redirect following, so it proves origin selection without contacting the
selected origin.
