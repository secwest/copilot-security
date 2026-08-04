# Axios instance fixed-destination control

The route value is only an exact key into server-owned relative request paths.
The Axios instance has a fixed HTTPS base, rejects absolute URL override, and
does not follow redirects. Attacker input never becomes URL syntax or request
configuration.

This is the paired negative control for `javascript-axios-instance-ssrf`.
