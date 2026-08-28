# MCP v2 fixed-argv control

This topology-matched control keeps the official SDK, schema-bearing tool, callback, same-file helper, child process, timeout, output capture, and response. It replaces shell evaluation with a fixed Node executable and places an explicit `--` end-of-options boundary before tool input. Its witness covers ordinary metacharacters and dash-prefixed Node options.

Run `npm install` and `npm run witness` with Node.js 22 or later.
