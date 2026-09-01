# Credentialed CORS fixed-origin control

This topology-matched control pins the credentialed CORS response to the
operator-owned application origin. A browser request from another origin sees
a mismatched `Access-Control-Allow-Origin` value and cannot read the response.

The witness invokes the real `cors` middleware with in-memory request and
response objects. It starts no server or listener, sends no request, and uses
no real session, cookie, credential, or account data.
