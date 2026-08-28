# MCP v2 SSRF fixture

The official SDK registers a schema-bearing tool whose client-controlled `url` input crosses a same-file helper and becomes the global `fetch` destination. The witness proves destination control using a disposable random-port loopback listener and closes it immediately; it makes no external request and uses no credential.

Run `npm install` and `npm run witness` with Node.js 22 or later.
