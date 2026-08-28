# MCP v2 path-traversal fixture

The official SDK registers a schema-bearing tool whose client-controlled `name` input crosses a same-file helper, is resolved against a document root without a containment check, and becomes the path argument to `node:fs/promises.writeFile`. The witness creates a new disposable temporary tree, writes only synthetic marker data one level outside its intended document subdirectory, verifies the boundary escape, and removes the tree immediately.

Run `npm install` and `npm run witness` with Node.js 22 or later.
