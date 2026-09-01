import assert from "node:assert/strict";

let receiverOrigin = "https://attacker.invalid";
let received;
globalThis.window = {
  localStorage: {
    getItem(key) {
      assert.equal(key, "access_token");
      return "bounded-benchmark-token";
    },
  },
  parent: {
    postMessage(payload, { targetOrigin }) {
      if (targetOrigin === "*" || targetOrigin === receiverOrigin) {
        received = payload;
      }
    },
  },
};

const { publishSession } = await import("../src/session-bridge.js");
publishSession();
assert.equal(received, undefined);

receiverOrigin = "https://portal.example";
publishSession();
assert.deepEqual(received, {
  type: "session",
  accessToken: "bounded-benchmark-token",
});
delete globalThis.window;
console.log({ attacker_receiver_observed_payload: 0, control: true });
