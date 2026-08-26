import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

const marker = "inert-traefik-route-boundary";
const binary = process.env.TRAEFIK_BINARY;
const expectation = process.env.TRAEFIK_EXPECT;

if (binary === undefined || !["affected", "repaired"].includes(expectation)) {
  throw new Error(
    "Set TRAEFIK_BINARY and TRAEFIK_EXPECT=affected|repaired before running the witness.",
  );
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve(server.address().port);
    });
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
}

function request(port, path) {
  return new Promise((resolve, reject) => {
    const request = import("node:http").then(({ request: send }) => {
      const outgoing = send(
        { host: "127.0.0.1", method: "GET", path, port },
        (response) => {
          const chunks = [];
          response.on("data", (chunk) => chunks.push(chunk));
          response.on("end", () =>
            resolve({
              body: Buffer.concat(chunks).toString("utf8"),
              status: response.statusCode,
            }),
          );
        },
      );
      outgoing.once("error", reject);
      outgoing.end();
    });
    request.catch(reject);
  });
}

async function waitUntilReady(port, child) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(
        `Traefik exited before readiness with ${child.exitCode}.`,
      );
    }
    try {
      const response = await request(port, "/admin");
      if (response.status === 401) return response;
    } catch {
      // The loopback listener is not ready yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Traefik did not become ready on its loopback listener.");
}

const versionResult = spawnSync(binary, ["version"], {
  encoding: "utf8",
  timeout: 5_000,
  windowsHide: true,
});
if (versionResult.status !== 0) {
  throw new Error("Unable to read the Traefik binary version.");
}
const version = /Version:\s*(\S+)/u.exec(versionResult.stdout)?.[1];
if (version === undefined)
  throw new Error("Traefik version output was unexpected.");
const expectedVersion = expectation === "affected" ? "3.7.6" : "3.7.7";
if (version !== expectedVersion) {
  throw new Error(`Expected Traefik ${expectedVersion}, received ${version}.`);
}

const root = await mkdtemp(join(tmpdir(), "copilot-security-traefik-witness-"));
const backendHits = [];
const backend = createServer((incoming, response) => {
  const rawPath = incoming.url ?? "";
  const normalizedPath = new URL(rawPath, "http://loopback.invalid").pathname;
  backendHits.push({ normalizedPath, rawPath });
  if (normalizedPath === "/admin") {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end(marker);
    return;
  }
  response.writeHead(404, { "content-type": "text/plain" });
  response.end("not found");
});

let traefik;
try {
  const backendPort = await listen(backend);
  const reservation = createServer();
  const proxyPort = await listen(reservation);
  await close(reservation);
  const committedConfiguration = await readFile(
    new URL("../dynamic.yml", import.meta.url),
    "utf8",
  );
  const dynamicPath = join(root, "dynamic.yml");
  await writeFile(
    dynamicPath,
    committedConfiguration.replace(
      "127.0.0.1:18081",
      `127.0.0.1:${backendPort}`,
    ),
  );

  const stderr = [];
  traefik = spawn(
    binary,
    [
      `--entrypoints.web.address=127.0.0.1:${proxyPort}`,
      `--providers.file.filename=${dynamicPath}`,
      "--api=false",
      "--log.level=ERROR",
    ],
    { cwd: root, stdio: ["ignore", "ignore", "pipe"], windowsHide: true },
  );
  traefik.stderr.on("data", (chunk) => {
    if (stderr.length < 20) stderr.push(chunk.toString("utf8"));
  });

  const direct = await waitUntilReady(proxyPort, traefik);
  const hitsBeforeCrafted = backendHits.length;
  const crafted = await request(proxyPort, "/api../admin");
  const craftedHits = backendHits.slice(hitsBeforeCrafted);
  const markerReached = crafted.body === marker;
  const directDenied = direct.status === 401 && hitsBeforeCrafted === 0;
  const affected = directDenied && markerReached;
  const repaired = directDenied && !markerReached && craftedHits.length === 0;

  if (expectation === "affected" && !affected) {
    throw new Error(
      `Affected boundary was not reproduced: ${JSON.stringify({ crafted, craftedHits, direct, stderr })}`,
    );
  }
  if (expectation === "repaired" && !repaired) {
    throw new Error(
      `Repaired boundary did not reject the path: ${JSON.stringify({ crafted, craftedHits, direct, stderr })}`,
    );
  }

  console.log(
    JSON.stringify({
      affected,
      backendHits: craftedHits,
      craftedStatus: crafted.status,
      directDenied,
      expectation,
      loopbackOnly: true,
      markerReached,
      repaired,
      version,
    }),
  );
} finally {
  if (traefik !== undefined && traefik.exitCode === null) traefik.kill();
  await close(backend).catch(() => undefined);
  await rm(root, { force: true, recursive: true });
}
