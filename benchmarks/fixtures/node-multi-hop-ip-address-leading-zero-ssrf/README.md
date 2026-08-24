# Vulnerable ip-address leading-zero SSRF guard

An attacker-controlled URL crosses three wrappers into a fail-closed `Address4.isPrivate()` guard before `fetch`. Version 10.3.0 reads `012.0.0.1` as public decimal `12.0.0.1`, while the WHATWG URL parser routes the original spelling to private octal `10.0.0.1`.
