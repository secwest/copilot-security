# Java OkHttp multi-hop SSRF

A Spring request parameter crosses two uniquely typed service boundaries,
becomes the complete URL of an OkHttp `Request`, and is dispatched by a typed
`OkHttpClient`. The paired witness binds only to loopback.
