# Java multi-hop SSRF

The query parameter crosses a Spring controller, a service, and a transport
before becoming the complete URI of a JDK `HttpRequest`. The injected
`HttpClient` sends that request without constraining its destination. A short
request deadline and a discarding response handler keep this fixture focused on
SSRF instead of introducing an unrelated unbounded-response finding.
