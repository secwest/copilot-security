# FastAPI response-class open redirect

An official FastAPI GET path operation uses Python's implicit parenthesized
line joining to declare the official `RedirectResponse` as its multiline
`response_class`, then returns an attacker-controlled query string directly.
FastAPI constructs the redirect response and places that string in the HTTP
`Location` header. The pinned TestClient witness disables redirect following,
so it proves origin selection without contacting the selected origin.
