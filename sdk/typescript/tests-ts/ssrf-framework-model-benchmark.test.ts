import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface BenchmarkCase {
  id: string;
  findingsPaths: string[];
  expected: Array<{
    cwe?: string[];
    requireValidation?: boolean;
    requireAttackPath?: boolean;
    requireCodeEvidence?: boolean;
  }>;
}

interface BenchmarkManifest {
  schemaVersion: string;
  thresholds: Record<string, number>;
  cases: BenchmarkCase[];
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

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const caseIds = [
  "javascript-cross-file-ssrf",
  "javascript-cross-file-safe-fetch",
  "python-cross-file-ssrf",
  "python-cross-file-safe-fetch",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function parseRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord);
}

function ssrfRecord(
  inventory: string,
  scope: string,
): FrameworkRecord | undefined {
  return parseRecords(inventory).find((record) => {
    const model = record.frameworkModel;
    return (
      model !== undefined &&
      ["node-http-ssrf", "python-web-ssrf"].includes(model.id) &&
      model.scope === scope
    );
  });
}

describe("SSRF framework-model effectiveness benchmark", () => {
  test("keeps Node and Python positives and controls under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "ssrf-framework-manifest.json"),
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
    ).toHaveLength(2);
    expect(
      manifest.cases.filter(({ expected }) => expected.length === 0),
    ).toHaveLength(2);
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

  test("emits same-file Node SSRF and retains fixed-origin controls", async () => {
    const vulnerable = ssrfRecord(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "javascript-ssrf"),
      ),
      "same-file",
    );
    const safe = ssrfRecord(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "javascript-safe-fetch"),
      ),
      "same-file",
    );

    expect(vulnerable?.frameworkModel).toMatchObject({
      id: "node-http-ssrf",
      source: { path: "src/preview.js", line: 2 },
      sink: {
        path: "src/preview.js",
        line: 3,
        cweIds: ["CWE-918"],
      },
      candidateControls: [],
    });
    expect(safe?.frameworkModel?.candidateControls).toContainEqual({
      kind: "fixed-origin-url-construction",
      path: "src/preview.js",
      line: 6,
    });
    expect(safe?.frameworkModel?.candidateControls).toContainEqual({
      kind: "redirects-disabled",
      path: "src/preview.js",
      line: 10,
    });
  });

  test("does not misclassify a URL substring check as an exact-host control", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-weak-ssrf-guard-"),
    );
    temporaryPaths.push(repository);
    await writeFile(
      join(repository, "server.js"),
      [
        "export function preview(request) {",
        "  const target = request.query.url;",
        '  if (!target.includes("assets.example.internal")) throw new Error("blocked");',
        "  return fetch(target);",
        "}",
        "",
      ].join("\n"),
    );

    const record = ssrfRecord(
      await buildResidualRiskInventory(repository),
      "same-file",
    );
    expect(record?.frameworkModel?.sink.cweIds).toEqual(["CWE-918"]);
    expect(record?.frameworkModel?.candidateControls).not.toContainEqual(
      expect.objectContaining({ kind: "parsed-host-exact-allowlist" }),
    );
    const prompt = scanQualityGatePrompt(JSON.stringify(record));
    expect(prompt).toContain(
      "URL or hostname substring checks never prove an exact host boundary",
    );
    expect(prompt).toContain(
      "without complete address validation and connection pinning it does not close DNS rebinding",
    );
  });

  test("preserves exact JavaScript and Python cross-file SSRF paths", async () => {
    const inventories = new Map<string, string>();
    for (const id of caseIds) {
      inventories.set(
        id,
        await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id)),
      );
    }

    const javascript = ssrfRecord(
      inventories.get("javascript-cross-file-ssrf")!,
      "cross-file-wrapper",
    );
    expect(javascript?.frameworkModel).toMatchObject({
      id: "node-http-ssrf",
      source: { path: "src/server.js", line: 4 },
      sink: { path: "src/upstream.js", line: 4, cweIds: ["CWE-918"] },
    });
    expect(
      javascript?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "relative-module-import",
      "wrapper-call-argument",
      "wrapper-parameter",
    ]);

    const safeJavascript = ssrfRecord(
      inventories.get("javascript-cross-file-safe-fetch")!,
      "cross-file-wrapper",
    );
    expect(safeJavascript?.frameworkModel?.candidateControls).toEqual(
      expect.arrayContaining([
        {
          kind: "fixed-destination-allowlist",
          path: "src/upstream.js",
          line: 8,
        },
        {
          kind: "redirects-disabled",
          path: "src/upstream.js",
          line: 10,
        },
      ]),
    );

    const python = ssrfRecord(
      inventories.get("python-cross-file-ssrf")!,
      "cross-file-wrapper",
    );
    expect(python?.frameworkModel).toMatchObject({
      id: "python-web-ssrf",
      source: { path: "src/server.py", line: 10 },
      sink: { path: "src/upstream.py", line: 7, cweIds: ["CWE-918"] },
    });
    expect(python?.frameworkModel?.propagators.map(({ kind }) => kind)).toEqual(
      ["relative-python-import", "wrapper-call-argument", "wrapper-parameter"],
    );

    const safePython = ssrfRecord(
      inventories.get("python-cross-file-safe-fetch")!,
      "cross-file-wrapper",
    );
    expect(safePython?.frameworkModel?.candidateControls).toEqual(
      expect.arrayContaining([
        {
          kind: "fixed-destination-allowlist",
          path: "src/upstream.py",
          line: 11,
        },
        {
          kind: "redirects-disabled",
          path: "src/upstream.py",
          line: 13,
        },
      ]),
    );
  });

  test("carries SSRF sources through one explicit relay in both languages", async () => {
    const javascriptRoot = await mkdtemp(
      join(tmpdir(), "copilot-security-javascript-ssrf-relay-"),
    );
    temporaryPaths.push(javascriptRoot);
    await mkdir(join(javascriptRoot, "src"), { recursive: true });
    await writeFile(
      join(javascriptRoot, "src", "upstream.js"),
      "export function fetchPreview(target) { return fetch(target); }\n",
    );
    await writeFile(
      join(javascriptRoot, "src", "service.js"),
      [
        'import { fetchPreview } from "./upstream.js";',
        "export function dispatchPreview(target) {",
        "  return fetchPreview(target);",
        "}",
        "",
      ].join("\n"),
    );
    await writeFile(
      join(javascriptRoot, "src", "server.js"),
      [
        'import { dispatchPreview } from "./service.js";',
        "export function preview(request) {",
        "  const target = request.query.url;",
        "  return dispatchPreview(target);",
        "}",
        "",
      ].join("\n"),
    );

    const javascript = ssrfRecord(
      await buildResidualRiskInventory(javascriptRoot),
      "cross-file-multi-hop-wrapper",
    );
    expect(javascript?.frameworkModel?.source.path).toBe("src/server.js");
    expect(javascript?.frameworkModel?.sink.path).toBe("src/upstream.js");
    expect(javascript?.frameworkModel?.propagators).toHaveLength(6);

    const pythonRoot = await mkdtemp(
      join(tmpdir(), "copilot-security-python-ssrf-relay-"),
    );
    temporaryPaths.push(pythonRoot);
    await mkdir(join(pythonRoot, "src"), { recursive: true });
    await writeFile(join(pythonRoot, "src", "__init__.py"), "");
    await writeFile(
      join(pythonRoot, "src", "upstream.py"),
      "import requests\n\ndef fetch_preview(target):\n    return requests.get(target)\n",
    );
    await writeFile(
      join(pythonRoot, "src", "service.py"),
      "from .upstream import fetch_preview\n\ndef dispatch_preview(target):\n    return fetch_preview(target)\n",
    );
    await writeFile(
      join(pythonRoot, "src", "server.py"),
      'from flask import request\nfrom .service import dispatch_preview\n\ndef preview():\n    target = request.args.get("url", "")\n    return dispatch_preview(target)\n',
    );

    const python = ssrfRecord(
      await buildResidualRiskInventory(pythonRoot),
      "cross-file-multi-hop-wrapper",
    );
    expect(python?.frameworkModel?.source.path).toBe("src/server.py");
    expect(python?.frameworkModel?.sink.path).toBe("src/upstream.py");
    expect(python?.frameworkModel?.propagators).toHaveLength(6);
  });
});
