import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface BenchmarkManifest {
  schemaVersion: string;
  thresholds: Record<string, number>;
  cases: Array<{
    id: string;
    findingsPaths: string[];
    expected: Array<{
      cwe?: string[];
      requireValidation?: boolean;
      requireAttackPath?: boolean;
      requireCodeEvidence?: boolean;
    }>;
  }>;
}

interface FrameworkRecord {
  path: string;
  frameworkModel?: {
    id: string;
    scope: string;
    source: { path: string; line: number };
    sink: { path: string; line: number; cweIds: string[] };
    propagators: Array<{ kind: string; path: string; line: number }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

const benchmarkRoot = resolve(import.meta.dir, "..", "..", "..", "benchmarks");
const caseIds = [
  "javascript-axios-instance-ssrf",
  "javascript-axios-instance-safe-fetch",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function records(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord);
}

function axiosRecord(
  inventory: string,
  path?: string,
): FrameworkRecord | undefined {
  return records(inventory).find(
    (record) =>
      record.frameworkModel?.id === "node-http-ssrf" &&
      (path === undefined || record.path === path),
  );
}

describe("Node Axios SSRF framework-model effectiveness benchmark", () => {
  test("keeps the Axios exploit and fixed-destination control under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-axios-ssrf-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;

    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([...caseIds]);
    expect(
      manifest.cases.filter(({ expected }) => expected.length > 0),
    ).toHaveLength(1);
    expect(
      manifest.cases.filter(({ expected }) => expected.length === 0),
    ).toHaveLength(1);
    for (const benchmarkCase of manifest.cases) {
      expect(benchmarkCase.findingsPaths).toHaveLength(1);
      for (const expected of benchmarkCase.expected) {
        expect(expected.cwe).toEqual(["CWE-918"]);
        expect(expected.requireValidation).toBeTrue();
        expect(expected.requireAttackPath).toBeTrue();
        expect(expected.requireCodeEvidence).toBeTrue();
      }
    }
  });

  test("preserves the exact request-to-Axios-instance URL path", async () => {
    const record = axiosRecord(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "javascript-axios-instance-ssrf"),
      ),
    );

    expect(record?.frameworkModel).toMatchObject({
      id: "node-http-ssrf",
      scope: "cross-file-wrapper",
      source: { path: "src/server.js", line: 4 },
      sink: { path: "src/upstream.js", line: 10, cweIds: ["CWE-918"] },
      candidateControls: [],
    });
    expect(record?.frameworkModel?.propagators.map(({ kind }) => kind)).toEqual(
      ["relative-module-import", "wrapper-call-argument", "wrapper-parameter"],
    );
  });

  test("retains exact fixed-selection, absolute-override, and redirect controls", async () => {
    const record = axiosRecord(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "javascript-axios-instance-safe-fetch"),
      ),
    );

    expect(record?.frameworkModel).toMatchObject({
      id: "node-http-ssrf",
      scope: "cross-file-wrapper",
      source: { path: "src/server.js", line: 4 },
      sink: { path: "src/upstream.js", line: 17, cweIds: ["CWE-918"] },
    });
    expect(record?.frameworkModel?.candidateControls).toEqual(
      expect.arrayContaining([
        {
          kind: "fixed-destination-allowlist",
          path: "src/upstream.js",
          line: 16,
        },
        {
          kind: "axios-absolute-url-override-disabled",
          path: "src/upstream.js",
          line: 10,
        },
        {
          kind: "redirects-disabled",
          path: "src/upstream.js",
          line: 11,
        },
      ]),
    );
  });

  test("recognizes ESM, import-equals, CommonJS, multiline, and request-config URL sinks", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-axios-identities-"),
    );
    temporaryPaths.push(repository);
    const fixtures = new Map<string, string>([
      [
        "aliased.ts",
        [
          'import transport from "axios";',
          'const client = transport.create({ baseURL: "https://api.example/" });',
          "export function preview(request) {",
          "  const target = request.query.url;",
          "  return client.get<string>(",
          "    target,",
          "  );",
          "}",
        ].join("\n"),
      ],
      [
        "commonjs.cjs",
        [
          'const axios = require("axios");',
          "const client = axios.create();",
          "exports.preview = function preview(request) {",
          "  const target = request.query.url;",
          "  return client.post(target, { preview: true });",
          "};",
        ].join("\n"),
      ],
      [
        "namespace.ts",
        [
          'import * as transport from "axios";',
          "export function preview(request) {",
          "  const target = request.query.url;",
          "  return transport.get(target);",
          "}",
        ].join("\n"),
      ],
      [
        "import-equals.ts",
        [
          'import transport = require("axios");',
          "export function preview(request) {",
          "  const target = request.query.url;",
          "  return transport.get(target);",
          "}",
        ].join("\n"),
      ],
      [
        "request-config.ts",
        [
          'import axios from "axios";',
          "export function preview(request) {",
          "  const target = request.query.url;",
          '  return axios.request({ url: target, method: "get" });',
          "}",
        ].join("\n"),
      ],
    ]);
    for (const [path, contents] of fixtures) {
      await writeFile(join(repository, path), `${contents}\n`);
    }

    const inventory = await buildResidualRiskInventory(repository);
    for (const path of fixtures.keys()) {
      expect(axiosRecord(inventory, path)?.frameworkModel).toMatchObject({
        id: "node-http-ssrf",
        scope: "same-file",
        sink: { path, cweIds: ["CWE-918"] },
      });
    }
  });

  test("rejects local shadows, body-only flow, reassigned instances, and comment controls", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-axios-controls-"),
    );
    temporaryPaths.push(repository);
    await mkdir(join(repository, "src"));
    await writeFile(
      join(repository, "src", "shadow.js"),
      [
        '/* import axios from "axios"; */',
        "const axios = { get(value) { return value; } };",
        "export function preview(request) {",
        "  const target = request.query.url;",
        "  return axios.get(target);",
        "}",
        "",
      ].join("\n"),
    );
    await writeFile(
      join(repository, "src", "body-only.ts"),
      [
        'import axios from "axios";',
        "const client = axios.create();",
        "export function preview(request) {",
        "  const target = request.query.url;",
        '  return client.post("https://api.example/fixed", target);',
        "}",
        "",
      ].join("\n"),
    );
    await writeFile(
      join(repository, "src", "reassigned.ts"),
      [
        'import axios from "axios";',
        "let client = axios.create();",
        "client = localClient;",
        "export function preview(request) {",
        "  const target = request.query.url;",
        "  return client.get(target);",
        "}",
        "",
      ].join("\n"),
    );
    await writeFile(
      join(repository, "src", "reassigned-root.ts"),
      [
        'import axios from "axios";',
        "axios = localTransport;",
        "const client = axios.create();",
        "export function preview(request) {",
        "  const target = request.query.url;",
        "  return client.get(target);",
        "}",
        "",
      ].join("\n"),
    );
    await writeFile(
      join(repository, "src", "parameter-shadow.ts"),
      [
        'import axios from "axios";',
        "const client = axios.create();",
        "export function preview(request, client) {",
        "  const target = request.query.url;",
        "  return client.get(target);",
        "}",
        "",
      ].join("\n"),
    );
    await writeFile(
      join(repository, "src", "comment-control.ts"),
      [
        'import axios from "axios";',
        "const client = axios.create();",
        "// allowAbsoluteUrls: false",
        'const documentation = "allowAbsoluteUrls: false; maxRedirects: 0";',
        "const unrelatedOptions = { allowAbsoluteUrls: false, maxRedirects: 0 };",
        "export function preview(request) {",
        "  const target = request.query.url;",
        "  return client.get(target);",
        "}",
        "",
      ].join("\n"),
    );

    const inventory = await buildResidualRiskInventory(repository);
    expect(axiosRecord(inventory, "src/shadow.js")).toBeUndefined();
    expect(axiosRecord(inventory, "src/body-only.ts")).toBeUndefined();
    expect(axiosRecord(inventory, "src/reassigned.ts")).toBeUndefined();
    expect(axiosRecord(inventory, "src/reassigned-root.ts")).toBeUndefined();
    expect(axiosRecord(inventory, "src/parameter-shadow.ts")).toBeUndefined();
    expect(
      axiosRecord(inventory, "src/comment-control.ts")?.frameworkModel
        ?.candidateControls,
    ).not.toContainEqual(
      expect.objectContaining({
        kind: "axios-absolute-url-override-disabled",
      }),
    );
    expect(
      axiosRecord(inventory, "src/comment-control.ts")?.frameworkModel
        ?.candidateControls,
    ).not.toContainEqual(
      expect.objectContaining({
        kind: "redirects-disabled",
      }),
    );
  });

  test("teaches the reviewer Axios authority and path boundaries", () => {
    const prompt = scanQualityGatePrompt("{}");
    expect(prompt).toContain("Axios baseURL");
    expect(prompt).toContain("allowAbsoluteUrls: false");
    expect(prompt).toContain("relative-path traversal");
    expect(prompt).toContain("Axios instance");
  });
});
