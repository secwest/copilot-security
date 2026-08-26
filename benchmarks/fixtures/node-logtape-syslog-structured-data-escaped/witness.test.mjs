import assert from "node:assert/strict";
import { createSocket } from "node:dgram";
import { readFile } from "node:fs/promises";
import test from "node:test";

const manifest = JSON.parse(
  await readFile(
    new URL("node_modules/@logtape/syslog/package.json", import.meta.url),
    "utf8",
  ),
);
const affected = manifest.version === "2.1.4";
assert.ok(affected || manifest.version === "2.1.5");

test(`@logtape/syslog ${manifest.version} structured-data boundary`, async () => {
  const receiver = createSocket("udp4");
  await new Promise((resolve, reject) => {
    receiver.once("error", reject);
    receiver.bind(0, "127.0.0.1", resolve);
  });
  const address = receiver.address();
  assert.equal(address.address, "127.0.0.1");
  const capture = new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error("loopback syslog capture timed out")),
      5_000,
    );
    receiver.once("message", (message) => {
      clearTimeout(timeout);
      resolve(message);
    });
  });
  process.env.COPILOT_SECURITY_SYSLOG_PORT = String(address.port);
  let disposeAuditLogging;
  try {
    const application = await import("./src/audit.js");
    disposeAuditLogging = application.disposeAuditLogging;
    const marker = "COPILOT_SECURITY_INERT_FORGED_RECORD_MARKER";
    application.auditRequest({
      body: { audit: `accepted\n<134>1 ${marker}` },
    });
    await disposeAuditLogging();
    disposeAuditLogging = undefined;
    const message = await capture;
    assert.ok(Buffer.isBuffer(message));
    const newlineIndex = message.indexOf(0x0a);
    const containsDecimalEscape = message.includes(Buffer.from("#010"));
    const containsMarker = message.includes(Buffer.from(marker));
    assert.equal(newlineIndex >= 0, affected);
    assert.equal(containsDecimalEscape, !affected);
    assert.equal(containsMarker, true);
    console.log(
      JSON.stringify({
        version: manifest.version,
        transport: "udp",
        receiver: "127.0.0.1",
        datagrams: 1,
        bytes: message.length,
        newlineIndex,
        containsDecimalEscape,
        containsMarker,
      }),
    );
  } finally {
    delete process.env.COPILOT_SECURITY_SYSLOG_PORT;
    if (disposeAuditLogging !== undefined) await disposeAuditLogging();
    receiver.close();
  }
});
