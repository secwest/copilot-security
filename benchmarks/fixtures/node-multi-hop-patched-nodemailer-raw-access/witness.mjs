import assert from "node:assert/strict";
import { writeFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import nodemailer from "nodemailer";

const marker = `COPILOT_SECURITY_NODEMAILER_${process.pid}`;
const fixture = join(
  tmpdir(),
  `copilot-security-nodemailer-${process.pid}.txt`,
);
const send = (transport, message) =>
  new Promise((resolve, reject) =>
    transport.sendMail(message, (error, info) =>
      error ? reject(error) : resolve(info),
    ),
  );
const transport = nodemailer.createTransport({
  streamTransport: true,
  buffer: true,
  disableFileAccess: true,
  disableUrlAccess: true,
});

await writeFile(fixture, marker);
const server = createServer((_request, response) => response.end(marker));
try {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.equal(typeof address, "object");
  await assert.rejects(
    send(transport, {
      from: "scanner@example.test",
      to: "reviewer@example.test",
      raw: { path: fixture },
    }),
    { code: "EFILEACCESS" },
  );
  await assert.rejects(
    send(transport, {
      from: "scanner@example.test",
      to: "reviewer@example.test",
      raw: { href: `http://127.0.0.1:${address.port}/private` },
    }),
    { code: "EURLACCESS" },
  );
  console.log("patched Nodemailer raw access-policy enforcement reproduced");
} finally {
  await new Promise((resolve) => server.close(resolve));
  await rm(fixture, { force: true });
}
