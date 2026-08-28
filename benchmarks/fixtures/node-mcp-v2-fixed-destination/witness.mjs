import assert from "node:assert/strict";
import { createServer } from "node:http";

const marker = "MCP_FIXED_DESTINATION_WITNESS_OK";
const listener = createServer((request, response) => {
  let body = "";
  request.setEncoding("utf8");
  request.on("data", (chunk) => (body += chunk));
  request.on("end", () => {
    assert.equal(body, marker);
    response.end(marker);
  });
});
await new Promise((resolve, reject) => {
  listener.once("error", reject);
  listener.listen(0, "127.0.0.1", resolve);
});
try {
  const address = listener.address();
  assert(address && typeof address === "object");
  process.env.MCP_WITNESS_PORT = String(address.port);
  const { sendMessage } = await import("./src/server.mjs");
  const output = await sendMessage(marker);
  assert.equal(output, marker);
} finally {
  delete process.env.MCP_WITNESS_PORT;
  await new Promise((resolve, reject) =>
    listener.close((error) => (error ? reject(error) : resolve())),
  );
}
console.log(
  "MCP v2 fixed-destination control kept tool input in the request body.",
);
