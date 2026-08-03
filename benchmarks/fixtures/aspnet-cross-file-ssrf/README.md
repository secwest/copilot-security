# ASP.NET cross-file SSRF fixture

The `target` query parameter crosses a constructor-injected service boundary
and becomes the complete URI passed to `HttpClient.GetAsync`. The short request
deadline and bounded response read isolate destination control from resource
exhaustion; they do not prevent requests to internal or link-local services.
