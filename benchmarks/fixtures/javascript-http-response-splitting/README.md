# HTTP response-splitting fixture

An unauthenticated report-download endpoint interpolates a query-string
filename into a raw `Content-Disposition` response header. An attacker can add
CR/LF bytes and inject `X-Accel-Redirect`, causing the deployment gateway to
serve an otherwise internal tenant export. The fixture preserves the exact raw
response and the gateway's protected-file substitution so the disclosure is an
executable effect rather than a header-name heuristic.
