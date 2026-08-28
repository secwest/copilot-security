# MCP v2 worker data boundary

This topology-matched control retains the official MCP SDK v2 server, reachable stdio launcher, same tool schema and response, same helper, and `Worker(..., { eval: true })`. It parses two-operand arithmetic in the parent, keeps the worker source fixed and server-owned, and passes only numbers plus an allowlisted operator through Node's structured-cloned `workerData` channel.

Run `npm install` and `npm run witness` with Node.js 22 or later. The witness proves useful addition and multiplication still return `42`, while JavaScript object syntax is rejected before worker startup. It performs no filesystem, network, process, credential, or persistence operation.
