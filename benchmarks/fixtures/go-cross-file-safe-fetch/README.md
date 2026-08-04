# Go net/http fixed-destination control

The handler passes an untrusted selector rather than a URL. `Fetch` performs an exact lookup in a server-owned map, constructs the request only from the selected complete URL, and configures `CheckRedirect` to return `http.ErrUseLastResponse`. The executable test proves that a direct internal URL is rejected and an allowed endpoint cannot redirect the client into the loopback-only mock metadata service.
