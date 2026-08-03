# Java WebClient multi-hop SSRF

The query parameter crosses a Spring controller, service, and transport before
becoming the complete URI passed to a typed reactive `WebClient`. A short
reactive timeout and explicit response-body release keep the fixture focused on
destination control rather than resource exhaustion.
