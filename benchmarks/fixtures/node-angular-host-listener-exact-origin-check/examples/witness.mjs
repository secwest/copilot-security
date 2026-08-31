import assert from "node:assert/strict";

class MessageBridge {
  handleMessage(event) {
    if (event.origin !== "https://portal.example") return;
    this.lastAction = event.data.action;
  }
}

const bridge = new MessageBridge();
bridge.handleMessage({
  origin: "https://portal.example",
  data: { action: "trusted-preview" },
});
assert.equal(bridge.lastAction, "trusted-preview");

bridge.handleMessage({
  origin: "https://attacker.invalid",
  data: { action: "attacker-preview" },
});
assert.equal(bridge.lastAction, "trusted-preview");
console.log({ attacker_payload_accepted: 0, control: true });
