# Go net/http request-forgery fixture

The HTTP handler forwards a caller-controlled complete URL through one typed Go function boundary. `Fetch` constructs an official `net/http.Request` from that value and dispatches it through a proven `http.Client`. The executable test demonstrates access to a loopback-only mock metadata service.
