# Vulnerable fast-uri encoded dot-segment path policy

An attacker-controlled asset URL crosses three wrappers into a fail-closed public-prefix policy. `fast-uri` 3.1.0 decodes and removes the encoded `..` segment during normalization, so the parsed path escapes the intended `public` subtree before reaching the rooted filesystem write.
