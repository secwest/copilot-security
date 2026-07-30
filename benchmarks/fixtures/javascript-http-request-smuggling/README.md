# HTTP request-smuggling fixture

The public gateway frames a request with `Content-Length` and authorizes only
the visible request target before forwarding the original byte stream. The
backend gives `Transfer-Encoding: chunked` precedence and processes every
remaining request on the connection. A conflicting request can therefore hide
an administrative request from the gateway while the backend executes it.
