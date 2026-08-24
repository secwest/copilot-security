import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { nonceAlreadyBeenUsed } = require(
  "node-opcua-secure-channel/dist/source/server/server_secure_channel_layer.js",
);
const aggregateVersion = require("node-opcua/package.json").version;
const secureChannelVersion = require(
  "node-opcua-secure-channel/package.json",
).version;

function nonce(index) {
  const value = Buffer.alloc(32, 1);
  value.writeUInt32BE(index, 28);
  return value;
}

const first = nonce(1);
nonceAlreadyBeenUsed(first);
for (let index = 2; index <= 50_001; index += 1) {
  nonceAlreadyBeenUsed(nonce(index));
}

console.log(
  JSON.stringify({
    aggregateVersion,
    secureChannelVersion,
    uniqueNonceCount: 50_001,
    nonceBytes: 32,
    firstNonceRetained: nonceAlreadyBeenUsed(first),
  }),
);
