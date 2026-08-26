import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";

const fixture = process.cwd();
const require = createRequire(join(fixture, "package.json"));
const version = require("next/package.json").version;
const nextBin = require.resolve("next/dist/bin/next");
const { RouteModule } = require("next/dist/server/route-modules/route-module");
const {
  routerServerGlobal,
  RouterServerContextSymbol,
} = require("next/dist/server/lib/router-utils/router-server-context");
const boundedOutput = (chunks) => chunks.join("").slice(-32_768);

async function preparedRouteParameter() {
  const relativeProjectDir = `witness-${version}`;
  const routeModule = new RouteModule({
    userland: {},
    definition: {},
    distDir: ".next",
    relativeProjectDir,
  });
  routeModule.loadManifests = () => ({
    routesManifest: {
      version: 3,
      pages404: true,
      basePath: "",
      redirects: [],
      headers: [],
      dynamicRoutes: [],
      staticRoutes: [],
      dataRoutes: [],
      rewrites: { beforeFiles: [], afterFiles: [], fallback: [] },
    },
    prerenderManifest: {
      version: 4,
      routes: {},
      dynamicRoutes: {},
      notFoundRoutes: [],
      preview: {
        previewModeId: "0000000000000000",
        previewModeSigningKey: "0000000000000000",
        previewModeEncryptionKey: "0000000000000000",
      },
    },
    serverFilesManifest: { config: {} },
  });
  routerServerGlobal[RouterServerContextSymbol] ??= {};
  routerServerGlobal[RouterServerContextSymbol][relativeProjectDir] = {
    isWrappedByNextServer: true,
    nextConfig: {},
  };
  const previousRuntime = process.env.NEXT_RUNTIME;
  process.env.NEXT_RUNTIME = "edge";
  try {
    const prepared = await routeModule.prepare(
      {
        headers: {},
        method: "GET",
        url: "/documents/[slug]?nxtPslug=secret",
      },
      undefined,
      { srcPage: "/documents/[slug]", multiZoneDraftMode: false },
    );
    return prepared?.params?.slug;
  } finally {
    delete routerServerGlobal[RouterServerContextSymbol][relativeProjectDir];
    if (previousRuntime === undefined) delete process.env.NEXT_RUNTIME;
    else process.env.NEXT_RUNTIME = previousRuntime;
  }
}

async function run(args, timeoutMs) {
  const child = spawn(process.execPath, [nextBin, ...args], {
    cwd: fixture,
    env: {
      ...process.env,
      NEXT_TELEMETRY_DISABLED: "1",
      NEXT_PRIVATE_TEST_HEADERS: "1",
      NODE_ENV: "production",
      NOW_BUILDER: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const output = [];
  child.stdout.on("data", (chunk) => output.push(chunk.toString("utf8")));
  child.stderr.on("data", (chunk) => output.push(chunk.toString("utf8")));
  const timer = setTimeout(() => child.kill(), timeoutMs);
  const result = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
  clearTimeout(timer);
  if (result.code !== 0) {
    throw new Error(
      `next ${args[0]} failed (${result.code ?? result.signal}): ${boundedOutput(output)}`,
    );
  }
}

async function unusedPort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const port =
    typeof address === "object" && address !== null ? address.port : 0;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForServer(url, child, output) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`next start exited early: ${boundedOutput(output)}`);
    }
    try {
      const response = await fetch(url);
      if (response.status < 500) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`next start did not become ready: ${boundedOutput(output)}`);
}

await rm(join(fixture, ".next"), { force: true, recursive: true });
await run(["build"], 120_000);
const standaloneServer = join(fixture, ".next", "standalone", "server.js");
const standaloneSource = await readFile(standaloneServer, "utf8");
const configuredSource = standaloneSource.replace(
  /(startServer\(\{\s*)(minimalMode: (?:true|false),\r?\n {2})?/,
  "$1minimalMode: false,\n  ",
);
if (configuredSource === standaloneSource) {
  throw new Error(
    "standalone server did not expose the expected startServer boundary",
  );
}
await writeFile(standaloneServer, configuredSource);
const port = await unusedPort();
const origin = `http://127.0.0.1:${port}`;
const serverOutput = [];
const child = spawn(process.execPath, [standaloneServer], {
  cwd: fixture,
  env: {
    ...process.env,
    HOSTNAME: "127.0.0.1",
    NEXT_TELEMETRY_DISABLED: "1",
    NEXT_PRIVATE_TEST_HEADERS: "1",
    NODE_ENV: "production",
    NOW_BUILDER: "1",
    PORT: String(port),
  },
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true,
});
child.stdout.on("data", (chunk) => serverOutput.push(chunk.toString("utf8")));
child.stderr.on("data", (chunk) => serverOutput.push(chunk.toString("utf8")));

try {
  await waitForServer(`${origin}/documents/public`, child, serverOutput);
  const request = (path, id) =>
    fetch(`${origin}${path}`, {
      headers: { "x-invocation-id": `fixture:${id}` },
    });
  const direct = await request("/documents/secret", "direct");
  const publicResponse = await request("/documents/public", "public");
  const bypass = await request("/documents/public?nxtPslug=secret", "bypass");
  const publicBody = await publicResponse.text();
  const bypassBody = await bypass.text();
  const preparedParam = await preparedRouteParameter();
  if (version === "15.5.15" && preparedParam !== "secret") {
    throw new Error(`affected route preparation returned ${preparedParam}`);
  }
  if (version === "15.5.16" && preparedParam === "secret") {
    throw new Error("repaired route preparation accepted external nxtPslug");
  }
  console.log(
    JSON.stringify({
      version,
      directProtectedStatus: direct.status,
      publicMarker: publicBody.includes("bounded-public-document"),
      bypassStatus: bypass.status,
      ordinaryBypassReadProtectedMarker: bypassBody.includes(
        "bounded-secret-document",
      ),
      ordinaryBypassPreservedPublicMarker: bypassBody.includes(
        "bounded-public-document",
      ),
      wrappedTemplatePreparedParam: preparedParam,
    }),
  );
} finally {
  child.kill();
  await new Promise((resolve) => {
    if (child.exitCode !== null) resolve();
    else child.once("exit", resolve);
  });
}
