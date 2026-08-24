# Patched fast-uri authority-introducer guard

This source-identical control upgrades only `fast-uri` to 4.1.2. The repaired resolver rejects malformed backslash authority introducers instead of resolving them under the trusted base URL.
