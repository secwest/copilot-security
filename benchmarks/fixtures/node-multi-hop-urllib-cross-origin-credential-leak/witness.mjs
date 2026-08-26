import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { request } from "urllib";

const manifest = JSON.parse(
  await readFile(new URL("./package.json", import.meta.url)),
);
const version = manifest.dependencies.urllib;
let capturedAuthorization;

const listen = (server) =>
  new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
const close = (server) => new Promise((resolve) => server.close(resolve));

const receiver = createServer((incoming, response) => {
  capturedAuthorization = incoming.headers.authorization;
  response.writeHead(200, { "content-type": "text/plain" });
  response.end("bounded receiver");
});
const receiverPort = await listen(receiver);
const redirector = createServer((_incoming, response) => {
  response.writeHead(302, {
    location: `http://127.0.0.1:${receiverPort}/captured`,
  });
  response.end();
});
const redirectorPort = await listen(redirector);

try {
  const authorization = "Bearer copilot-security-bounded-witness";
  await request(`http://127.0.0.1:${redirectorPort}/start`, {
    headers: { Authorization: authorization },
    maxRedirects: 2,
  });
  if (version === "4.9.0") {
    assert.equal(capturedAuthorization, authorization);
  } else {
    assert.equal(capturedAuthorization, undefined);
  }
  console.log(
    JSON.stringify({
      version,
      redirectedAcrossOrigin: true,
      authorizationForwarded: capturedAuthorization !== undefined,
    }),
  );
} finally {
  await Promise.all([close(redirector), close(receiver)]);
}
