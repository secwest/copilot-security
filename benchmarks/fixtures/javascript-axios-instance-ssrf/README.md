# Axios instance SSRF fixture

The route passes an attacker-controlled complete URL through a relative module
boundary to an Axios instance. The instance has a fixed `baseURL`, but Axios
allows an absolute request URL to replace that base by default. The response is
returned to the caller, making internal-service reads observable.

This fixture is intentionally vulnerable. See the paired
`javascript-axios-instance-safe-fetch` fixture for exact server-owned request
selection, absolute-URL override rejection, and redirect rejection.
