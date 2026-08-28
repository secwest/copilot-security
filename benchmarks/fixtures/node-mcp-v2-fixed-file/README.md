# MCP v2 fixed-file control

This topology-matched control uses the same official SDK, schema-bearing tool, same-file helper, and `node:fs/promises.writeFile` call as the exploit fixture. The file URL is fixed by operator configuration; both client-controlled strings are written only as file contents. The witness uses a fresh disposable temporary file and removes it immediately.

Run `npm install` and `npm run witness` with Node.js 22 or later.
