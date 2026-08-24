# Repaired Fastify Static route guard

This source-identical control upgrades only `@fastify/static` to 10.1.1. The repaired plugin decodes and checks the full raw URL path before route-prefix stripping, rejecting both raw and percent-encoded non-leading parent segments before static normalization can reach the protected file.
