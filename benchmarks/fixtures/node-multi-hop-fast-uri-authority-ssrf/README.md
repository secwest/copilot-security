# Vulnerable fast-uri authority-introducer SSRF guard

An attacker-controlled relative URL crosses three wrappers into a fail-closed `fast-uri` host allowlist before `fetch`. Version 4.1.1 resolves a leading backslash authority introducer under `allowed.example`, while the WHATWG URL consumer treats the same input as a network-path reference and connects to the attacker-selected host.
