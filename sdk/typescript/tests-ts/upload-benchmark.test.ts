import { mkdtemp, mkdir, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";

interface UploadRequest {
  file: {
    originalname: string;
    mimetype: string;
    buffer: Buffer;
  };
}

interface UploadResponse {
  readonly statusCode: number;
  readonly body: unknown;
  status(code: number): UploadResponse;
  json(body: unknown): UploadResponse;
  end(): UploadResponse;
}

type UploadHandler = (
  request: UploadRequest,
  response: UploadResponse,
  applicationRoot: string,
) => Promise<unknown>;

type PluginActivator = (
  applicationRoot: string,
  application: Record<string, unknown>,
) => Promise<void>;

const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

test("upload benchmark proves cross-file extension execution and isolated canonical storage", async () => {
  const vulnerable = await loadFixture("javascript-executable-file-upload");
  const safe = await loadFixture("javascript-safe-profile-upload");
  const attack = request(
    "telemetry.mjs",
    "application/javascript",
    [
      "export async function activate(application) {",
      '  application.compromised = "uploaded-extension";',
      '  application.role = "administrator";',
      "}",
      "",
    ].join("\n"),
  );

  const vulnerableRoot = await temporaryRoot();
  const vulnerablePlugins = join(vulnerableRoot, "plugins");
  await mkdir(vulnerablePlugins);
  const vulnerableResponse = responseRecorder();
  await vulnerable.upload(attack, vulnerableResponse, vulnerableRoot);

  expect(vulnerableResponse.statusCode).toBe(201);
  expect(await readFile(join(vulnerablePlugins, "telemetry.mjs"), "utf8")).toBe(
    attack.file.buffer.toString("utf8"),
  );
  const vulnerableApplication: Record<string, unknown> = {};
  await vulnerable.activate(vulnerableRoot, vulnerableApplication);
  expect(vulnerableApplication).toEqual({
    compromised: "uploaded-extension",
    role: "administrator",
  });

  const safeRoot = await temporaryRoot();
  const safeProfiles = join(safeRoot, "data", "profiles");
  const safePlugins = join(safeRoot, "plugins");
  await Promise.all([
    mkdir(safeProfiles, { recursive: true }),
    mkdir(safePlugins, { recursive: true }),
  ]);
  const rejectedResponse = responseRecorder();
  await safe.upload(attack, rejectedResponse, safeRoot);

  expect(rejectedResponse.statusCode).toBe(415);
  expect(await readdir(safeProfiles)).toEqual([]);
  expect(await readdir(safePlugins)).toEqual([]);
  const safeApplication: Record<string, unknown> = {};
  await safe.activate(safeRoot, safeApplication);
  expect(safeApplication).toEqual({});

  const acceptedResponse = responseRecorder();
  await safe.upload(
    request("profile.json", "application/json", '{"theme":"dark"}'),
    acceptedResponse,
    safeRoot,
  );
  expect(acceptedResponse.statusCode).toBe(201);
  const stored = await readdir(safeProfiles);
  expect(stored).toHaveLength(1);
  expect(stored[0]).toMatch(/^[0-9a-f-]{36}\.json$/u);
  expect(await readFile(join(safeProfiles, stored[0]!), "utf8")).toBe(
    '{"theme":"dark"}\n',
  );
  expect(await readdir(safePlugins)).toEqual([]);
});

async function loadFixture(fixture: string): Promise<{
  upload: UploadHandler;
  activate: PluginActivator;
}> {
  const sourceRoot = resolve(
    process.cwd(),
    "..",
    "..",
    "benchmarks",
    "fixtures",
    fixture,
    "src",
  );
  const uploads = (await import(
    pathToFileURL(join(sourceRoot, "uploads.js")).href
  )) as {
    uploadPlugin?: unknown;
    storeProfile?: unknown;
  };
  const runner = (await import(
    pathToFileURL(join(sourceRoot, "plugin-runner.js")).href
  )) as {
    activatePlugins?: unknown;
  };
  const upload = uploads.uploadPlugin ?? uploads.storeProfile;
  expect(typeof upload).toBe("function");
  expect(typeof runner.activatePlugins).toBe("function");
  return {
    upload: upload as UploadHandler,
    activate: runner.activatePlugins as PluginActivator,
  };
}

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(
    join(tmpdir(), "copilot-security-upload-benchmark-"),
  );
  temporaryPaths.push(root);
  return root;
}

function request(
  originalname: string,
  mimetype: string,
  content: string,
): UploadRequest {
  return {
    file: {
      originalname,
      mimetype,
      buffer: Buffer.from(content, "utf8"),
    },
  };
}

function responseRecorder(): UploadResponse {
  let statusCode = 200;
  let body: unknown;
  const response: UploadResponse = {
    get statusCode() {
      return statusCode;
    },
    get body() {
      return body;
    },
    status(code) {
      statusCode = code;
      return response;
    },
    json(value) {
      body = value;
      return response;
    },
    end() {
      return response;
    },
  };
  return response;
}
