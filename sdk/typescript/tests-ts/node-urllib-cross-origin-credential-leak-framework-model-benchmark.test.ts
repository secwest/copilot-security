import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface FrameworkRecord {
  path: string;
  line: number;
  frameworkModel?: {
    id: string;
    scope: string;
    source: { kind: string; path: string; line: number };
    sink: { kind: string; path: string; line: number; cweIds: string[] };
    propagators: Array<{
      kind: string;
      path: string;
      line: number;
      symbol?: string;
    }>;
  };
}

interface BenchmarkManifest {
  schemaVersion: string;
  thresholds: Record<string, number>;
  cases: Array<{
    id: string;
    expected: Array<{
      cwe?: string[];
      acceptableSeverities?: string[];
      requireValidation?: boolean;
      requireAttackPath?: boolean;
      requireCodeEvidence?: boolean;
    }>;
  }>;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function urllibRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-http-urllib-cross-origin-credential-leak",
    );
}

async function writeCase(
  repository: string,
  id: string,
  source: string,
  version = "4.9.0",
  dependencySection = "dependencies",
  dependencyName = "urllib",
): Promise<void> {
  const root = join(repository, id);
  await mkdir(root, { recursive: true });
  await writeFile(
    join(root, "package.json"),
    JSON.stringify(
      {
        name: id,
        private: true,
        [dependencySection]: { [dependencyName]: version },
      },
      null,
      2,
    ),
  );
  await writeFile(join(root, "handler.mjs"), source);
}

async function writeNpmLock(
  repository: string,
  id: string,
  declaration: string,
  resolved: string,
  lockfileVersion = 3,
  rootDeclaration = declaration,
): Promise<void> {
  await writeFile(
    join(repository, id, "package-lock.json"),
    JSON.stringify(
      lockfileVersion === 1
        ? {
            name: id,
            lockfileVersion,
            dependencies: { urllib: { version: resolved } },
          }
        : {
            name: id,
            lockfileVersion,
            packages: {
              "": { dependencies: { urllib: rootDeclaration } },
              "node_modules/urllib": { version: resolved },
            },
          },
      null,
      2,
    ),
  );
}

const direct = (
  binding: string,
  call = "urllib.request",
  options = "{ headers: { Authorization: token } }",
) =>
  `${binding}\nexport function handler(request) {\n  const token = request.headers.authorization;\n  return ${call}("https://partner.example/api", ${options});\n}\n`;

describe("urllib cross-origin redirect credential leak framework benchmark", () => {
  test("keeps a strict affected and repaired benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-urllib-cross-origin-credential-leak-manifest.json",
        ),
        "utf8",
      ),
    ) as BenchmarkManifest;
    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 1 || value === 0,
      ),
    ).toBe(true);
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-multi-hop-urllib-cross-origin-credential-leak",
      "node-multi-hop-patched-urllib-cross-origin-credential",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-201", "CWE-522"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves the exact multi-hop source, request sink, credential, and dependency proof", async () => {
    const vulnerable = urllibRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-urllib-cross-origin-credential-leak",
        ),
      ),
    );
    const repaired = urllibRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-multi-hop-patched-urllib-cross-origin-credential",
        ),
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(repaired).toHaveLength(0);
    expect(vulnerable[0]).toMatchObject({
      path: "src/storage.js",
      line: 4,
      frameworkModel: {
        scope: "cross-file-multi-hop-wrapper",
        source: { path: "src/server.js", line: 4 },
        sink: {
          kind: "vulnerable-urllib-cross-origin-credential-forwarding",
          cweIds: ["CWE-201", "CWE-522"],
        },
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "urllib-runtime-dependency",
      path: "package.json",
      line: 9,
      symbol:
        "urllib@4.9.0:manifest-exact:cross-origin-authorization-forwarding:request",
    });
  });

  test("recognizes official bindings, request and curl, and standard credential forms", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-urllib-bindings-"),
    );
    temporaryPaths.push(repository);
    const cases = [
      ["named", direct('import { request as send } from "urllib";', "send")],
      ["default", direct('import urllib from "urllib";')],
      ["namespace", direct('import * as urllib from "urllib";', "urllib.curl")],
      [
        "import-equals",
        direct('import urllib = require("urllib");', "urllib.request"),
      ],
      [
        "commonjs",
        direct('const urllib = require("urllib");', "urllib.request"),
      ],
      [
        "destructured",
        direct('const { curl: send } = require("urllib");', "send"),
      ],
      ["direct-require", direct("", 'require("urllib").request')],
      [
        "http-client",
        direct(
          'import { HttpClient } from "urllib";\nconst client = new HttpClient();',
          "client.request",
        ),
      ],
      [
        "http-client2-namespace",
        direct(
          'import * as urllib from "urllib";\nconst client = new urllib.HttpClient2();',
          "client.curl",
        ),
      ],
      [
        "http-client-default-auth",
        'import { HttpClient } from "urllib";\nexport function handler(request) {\n  const client = new HttpClient({ defaultArgs: { auth: request.headers.authorization } });\n  return client.request("https://partner.example/api");\n}\n',
      ],
      [
        "http-client-default-digest-auth",
        'import { HttpClient2 } from "urllib";\nexport function handler(request) {\n  const defaults = { digestAuth: request.headers.authorization };\n  const clientOptions = { defaultArgs: defaults };\n  const client = new HttpClient2(clientOptions);\n  return client.curl("https://partner.example/api", {});\n}\n',
      ],
      [
        "v2-http-client-default-header",
        'const { HttpClient } = require("urllib");\nexport function handler(request) {\n  const client = new HttpClient({ defaultArgs: { headers: { Authorization: request.headers.authorization } } });\n  return client.request("https://partner.example/api");\n}\n',
        "2.44.0",
      ],
      [
        "cookie",
        direct(
          'import urllib from "urllib";',
          "urllib.request",
          "{ headers: { Cookie: token } }",
        ),
      ],
      [
        "proxy-authorization",
        direct(
          'import urllib from "urllib";',
          "urllib.request",
          '{ headers: { "Proxy-Authorization": token } }',
        ),
      ],
      [
        "auth",
        direct(
          'import urllib from "urllib";',
          "urllib.request",
          "{ auth: token }",
        ),
      ],
      [
        "digest-auth",
        direct(
          'import urllib from "urllib";',
          "urllib.request",
          "{ digestAuth: token }",
        ),
      ],
    ] as const;
    for (const [id, source, version] of cases)
      await writeCase(repository, id, source, version);
    expect(
      urllibRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path,
      ),
    ).toEqual(cases.map(([id]) => `${id}/handler.mjs`).sort());
  });

  test("models both affected release lines and declaration-consistent modern locks", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-urllib-versions-"),
    );
    temporaryPaths.push(repository);
    const source = direct('import urllib from "urllib";');
    for (const version of ["1.9.9", "2.43.0", "2.44.0", "3.0.0", "4.9.0"]) {
      await writeCase(repository, `affected-${version}`, source, version);
    }
    for (const version of ["2.44.1", "4.9.1", "5.0.0", "4.9.0-beta.1"]) {
      await writeCase(repository, `repaired-${version}`, source, version);
    }
    await writeCase(repository, "affected-lock", source, "^4.0.0");
    await writeNpmLock(repository, "affected-lock", "^4.0.0", "4.9.0");
    await writeCase(repository, "repaired-lock", source, "^4.0.0");
    await writeNpmLock(repository, "repaired-lock", "^4.0.0", "4.9.1");
    await writeCase(repository, "stale-lock", source, "^4.0.0");
    await writeNpmLock(
      repository,
      "stale-lock",
      "^4.0.0",
      "4.9.0",
      3,
      "^3.0.0",
    );
    await writeCase(repository, "v1-lock", source, "^4.0.0");
    await writeNpmLock(repository, "v1-lock", "^4.0.0", "4.9.0", 1);
    const records = urllibRecords(await buildResidualRiskInventory(repository));
    expect(records.map(({ path }) => path)).toEqual([
      "affected-1.9.9/handler.mjs",
      "affected-2.43.0/handler.mjs",
      "affected-2.44.0/handler.mjs",
      "affected-3.0.0/handler.mjs",
      "affected-4.9.0/handler.mjs",
      "affected-lock/handler.mjs",
    ]);
    expect(records.at(-1)?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-urllib-cross-origin-credential-forwarding",
    );
  });

  test("fails closed across redirect, credential, provenance, identity, and mutation boundaries", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-urllib-negatives-"),
    );
    temporaryPaths.push(repository);
    const binding = 'import urllib from "urllib";';
    const cases = [
      ["patched", direct(binding), "4.9.1", "dependencies", "urllib"],
      [
        "follow-disabled",
        direct(
          binding,
          "urllib.request",
          "{ followRedirect: false, headers: { Authorization: token } }",
        ),
        "4.9.0",
        "dependencies",
        "urllib",
      ],
      [
        "zero-redirects-v4",
        direct(
          binding,
          "urllib.request",
          "{ maxRedirects: 0, headers: { Authorization: token } }",
        ),
        "4.9.0",
        "dependencies",
        "urllib",
      ],
      [
        "negative-redirects-v2",
        direct(
          binding,
          "urllib.request",
          "{ maxRedirects: -1, headers: { Authorization: token } }",
        ),
        "2.44.0",
        "dependencies",
        "urllib",
      ],
      [
        "streaming-response",
        direct(
          binding,
          "urllib.request",
          '{ dataType: "stream", headers: { Authorization: token } }',
        ),
        "4.9.0",
        "dependencies",
        "urllib",
      ],
      [
        "dynamic-redirect-limit",
        direct(
          binding,
          "urllib.request",
          "{ maxRedirects: request.query.limit, headers: { Authorization: token } }",
        ),
        "4.9.0",
        "dependencies",
        "urllib",
      ],
      [
        "custom-header",
        direct(
          binding,
          "urllib.request",
          '{ headers: { "x-api-key": token } }',
        ),
        "4.9.0",
        "dependencies",
        "urllib",
      ],
      [
        "static-credential",
        direct(
          binding,
          "urllib.request",
          '{ headers: { Authorization: "Bearer fixed" } }',
        ),
        "4.9.0",
        "dependencies",
        "urllib",
      ],
      ["dev-only", direct(binding), "4.9.0", "devDependencies", "urllib"],
      ["wrong-package", direct(binding), "4.9.0", "dependencies", "not-urllib"],
      [
        "local-lookalike",
        direct('import urllib from "./urllib.js";'),
        "4.9.0",
        "dependencies",
        "urllib",
      ],
      [
        "reassigned-binding",
        direct(binding).replace(
          "export function handler",
          "urllib = replacement;\nexport function handler",
        ),
        "4.9.0",
        "dependencies",
        "urllib",
      ],
      [
        "replaced-member",
        direct(binding).replace(
          "export function handler",
          "urllib.request = replacement;\nexport function handler",
        ),
        "4.9.0",
        "dependencies",
        "urllib",
      ],
      [
        "replaced-http-client-class",
        direct(
          'import * as urllib from "urllib";\nurllib.HttpClient = replacement;\nconst client = new urllib.HttpClient();',
          "client.request",
        ),
        "4.9.0",
        "dependencies",
        "urllib",
      ],
      [
        "v4-default-headers-are-not-request-headers",
        'import { HttpClient } from "urllib";\nexport function handler(request) {\n  const client = new HttpClient({ defaultArgs: { headers: { Authorization: request.headers.authorization } } });\n  return client.request("https://partner.example/api");\n}\n',
        "4.9.0",
        "dependencies",
        "urllib",
      ],
      [
        "default-follow-disabled",
        'import { HttpClient } from "urllib";\nexport function handler(request) {\n  const client = new HttpClient({ defaultArgs: { followRedirect: false, auth: request.headers.authorization } });\n  return client.request("https://partner.example/api");\n}\n',
        "4.9.0",
        "dependencies",
        "urllib",
      ],
      [
        "default-zero-redirects-v4",
        'import { HttpClient } from "urllib";\nexport function handler(request) {\n  const client = new HttpClient({ defaultArgs: { maxRedirects: 0, auth: request.headers.authorization } });\n  return client.request("https://partner.example/api");\n}\n',
        "4.9.0",
        "dependencies",
        "urllib",
      ],
      [
        "default-streaming-response",
        'import { HttpClient } from "urllib";\nexport function handler(request) {\n  const client = new HttpClient({ defaultArgs: { dataType: "stream", auth: request.headers.authorization } });\n  return client.request("https://partner.example/api");\n}\n',
        "4.9.0",
        "dependencies",
        "urllib",
      ],
      [
        "request-auth-override-clears-default",
        'import { HttpClient } from "urllib";\nexport function handler(request) {\n  const client = new HttpClient({ defaultArgs: { auth: request.headers.authorization } });\n  return client.request("https://partner.example/api", { auth: undefined });\n}\n',
        "4.9.0",
        "dependencies",
        "urllib",
      ],
    ] as const;
    for (const [id, source, version, section, name] of cases) {
      await writeCase(repository, id, source, version, section, name);
    }
    expect(urllibRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );

    await writeCase(
      repository,
      "v2-zero-still-redirects",
      direct(
        binding,
        "urllib.request",
        "{ maxRedirects: 0, headers: { Authorization: token } }",
      ),
      "2.44.0",
    );
    await writeCase(
      repository,
      "false-stream-still-redirects",
      direct(
        binding,
        "urllib.request",
        "{ stream: false, writeStream: null, headers: { Authorization: token } }",
      ),
    );
    await writeCase(
      repository,
      "null-limit-uses-default",
      direct(
        binding,
        "urllib.request",
        "{ maxRedirects: null, headers: { Authorization: token } }",
      ),
    );
    await writeCase(
      repository,
      "request-enables-default-disabled-redirect",
      'import { HttpClient } from "urllib";\nexport function handler(request) {\n  const client = new HttpClient({ defaultArgs: { followRedirect: false, auth: request.headers.authorization } });\n  return client.request("https://partner.example/api", { followRedirect: true });\n}\n',
    );
    await writeCase(
      repository,
      "v2-default-zero-still-redirects",
      'import { HttpClient } from "urllib";\nexport function handler(request) {\n  const client = new HttpClient({ defaultArgs: { maxRedirects: 0, auth: request.headers.authorization } });\n  return client.request("https://partner.example/api");\n}\n',
      "2.44.0",
    );
    expect(
      urllibRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path,
      ),
    ).toEqual([
      "false-stream-still-redirects/handler.mjs",
      "null-limit-uses-default/handler.mjs",
      "request-enables-default-disabled-redirect/handler.mjs",
      "v2-default-zero-still-redirects/handler.mjs",
      "v2-zero-still-redirects/handler.mjs",
    ]);
  });

  test("adds field-local validation guidance without overstating redirect impact", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({
        frameworkModel: {
          id: "node-http-urllib-cross-origin-credential-leak",
        },
      }),
    );
    expect(prompt).toContain("GHSA-hq3h-g68c-hp78");
    expect(prompt).toContain("default with a ten-hop limit");
    expect(prompt).toContain("maxRedirects:0 as a 2.x control");
    expect(prompt).toContain("two separate loopback listeners");
    expect(prompt).toContain("do not infer SSRF");
  });
});
