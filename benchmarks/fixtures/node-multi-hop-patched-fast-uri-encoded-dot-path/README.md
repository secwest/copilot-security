# Patched fast-uri encoded dot-segment path policy

This source-identical control upgrades only `fast-uri` to 3.1.1. The repaired normalizer and parser preserve encoded dot segments as path data, keeping the resulting filesystem target within the intended literal `public/%2E%2E` subtree.
