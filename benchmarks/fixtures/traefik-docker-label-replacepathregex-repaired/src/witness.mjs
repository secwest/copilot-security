import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer, request as sendRequest } from "node:http";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const marker = "inert-traefik-docker-label-route-boundary";
const expectation = process.env.TRAEFIK_EXPECT;
if (!["affected", "repaired"].includes(expectation)) {
  throw new Error(
    "Set TRAEFIK_EXPECT=affected|repaired before running the witness.",
  );
}

const fixtureRoot = fileURLToPath(new URL("..", import.meta.url));
const project = `copilot-security-traefik-${process.pid}-${randomBytes(4).toString("hex")}`;

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

function compose(arguments_, environment, timeout = 30_000) {
  return spawnSync(
    "docker",
    [
      "compose",
      "-p",
      project,
      "-f",
      join(fixtureRoot, "compose.yml"),
      ...arguments_,
    ],
    {
      cwd: fixtureRoot,
      encoding: "utf8",
      env: environment,
      maxBuffer: 1_000_000,
      timeout,
      windowsHide: true,
    },
  );
}

function checkedCompose(arguments_, environment, timeout) {
  const result = compose(arguments_, environment, timeout);
  if (result.status !== 0) {
    const detail = `${result.stderr ?? ""}\n${result.stdout ?? ""}`
      .trim()
      .slice(-4_000);
    throw new Error(`docker compose ${arguments_.join(" ")} failed: ${detail}`);
  }
  return result;
}

function request(port, path) {
  return new Promise((resolve, reject) => {
    const outgoing = sendRequest(
      { host: "127.0.0.1", method: "GET", path, port, timeout: 5_000 },
      (response) => {
        const chunks = [];
        let size = 0;
        response.on("data", (chunk) => {
          size += chunk.length;
          if (size <= 4_096) chunks.push(chunk);
        });
        response.on("end", () =>
          resolve({
            body: Buffer.concat(chunks).toString("utf8"),
            status: response.statusCode,
          }),
        );
      },
    );
    outgoing.once("error", reject);
    outgoing.once("timeout", () =>
      outgoing.destroy(new Error("request timed out")),
    );
    outgoing.end();
  });
}

async function waitUntilReady(port) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    try {
      const direct = await request(port, "/cps-benchmark-admin");
      const backend = await request(port, "/cps-benchmark-apihealth");
      if (direct.status === 401 && backend.status === 404) return direct;
    } catch {
      // Containers may still be starting on the loopback listener.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Traefik did not become ready on its loopback listener.");
}

const reservation = createServer();
const port = await listen(reservation);
await close(reservation);
const environment = {
  ...process.env,
  TRAEFIK_BENCHMARK_PORT: String(port),
};

let composeAttempted = false;
try {
  checkedCompose(["config", "--quiet"], environment);
  composeAttempted = true;
  checkedCompose(
    ["up", "--detach", "--pull", "always", "--wait"],
    environment,
    180_000,
  );

  const versionResult = checkedCompose(
    ["exec", "-T", "proxy", "traefik", "version"],
    environment,
  );
  const version = /Version:\s*(\S+)/u.exec(versionResult.stdout)?.[1];
  const expectedVersion = expectation === "affected" ? "3.7.6" : "3.7.7";
  if (version !== expectedVersion) {
    throw new Error(
      `Expected Traefik ${expectedVersion}, received ${version ?? "unknown"}.`,
    );
  }

  const direct = await waitUntilReady(port);
  const crafted = await request(
    port,
    "/cps-benchmark-api../cps-benchmark-admin",
  );
  await new Promise((resolve) => setTimeout(resolve, 200));
  const logs = checkedCompose(
    ["logs", "--no-color", "--no-log-prefix", "backend"],
    environment,
  ).stdout;
  const backendHits = logs
    .split(/\r?\n/u)
    .filter((line) => line.startsWith("{"))
    .map((line) => JSON.parse(line));
  const craftedHit = backendHits.some(
    (hit) =>
      hit.rawPath === "/../cps-benchmark-admin" &&
      hit.normalizedPath === "/cps-benchmark-admin",
  );
  const directDenied = direct.status === 401;
  const affected =
    directDenied &&
    crafted.status === 200 &&
    crafted.body === marker &&
    craftedHit;
  const repaired = directDenied && crafted.status === 400 && !craftedHit;

  if (expectation === "affected" && !affected) {
    throw new Error(
      `Affected boundary was not reproduced: ${JSON.stringify({ backendHits, crafted, direct })}`,
    );
  }
  if (expectation === "repaired" && !repaired) {
    throw new Error(
      `Repaired boundary did not reject the path: ${JSON.stringify({ backendHits, crafted, direct })}`,
    );
  }

  console.log(
    JSON.stringify({
      affected,
      backendHits,
      craftedStatus: crafted.status,
      directDenied,
      expectation,
      loopbackOnly: true,
      markerReached: crafted.body === marker,
      projectIsolated: true,
      repaired,
      version,
    }),
  );
} finally {
  if (composeAttempted) {
    compose(["down", "--volumes", "--remove-orphans"], environment, 60_000);
  }
}
