import assert from "node:assert/strict";
import { createServer } from "node:http";
import { loadUrl } from "./src/server.mjs";

const marker = "MCP_SSRF_LOOPBACK_WITNESS_OK";
const listener = createServer((_request, response) => response.end(marker));
await new Promise((resolve, reject) => {
  listener.once("error", reject);
  listener.listen(0, "127.0.0.1", resolve);
});
try {
  const address = listener.address();
  assert(address && typeof address === "object");
  const output = await loadUrl(`http://127.0.0.1:${address.port}/witness`);
  assert.equal(output, marker);
} finally {
  await new Promise((resolve, reject) =>
    listener.close((error) => (error ? reject(error) : resolve())),
  );
}
console.log("MCP v2 SSRF witness reached only a disposable loopback listener.");
