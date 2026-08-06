import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface BenchmarkCase {
  id: string;
  fixture: string;
  findingsPaths: string[];
  expected: unknown[];
}

interface BenchmarkManifest {
  schemaVersion: string;
  thresholds: Record<string, number>;
  cases: BenchmarkCase[];
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

describe("multi-hop framework-model effectiveness benchmark", () => {
  test("keeps four-file positives and negatives paired under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "multi-hop-framework-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;

    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "javascript-multi-hop-command-injection",
      "javascript-multi-hop-safe-command",
      "javascript-multi-hop-sql-injection",
      "javascript-multi-hop-safe-sql",
    ]);
    expect(
      manifest.cases.filter(({ expected }) => expected.length > 0),
    ).toHaveLength(2);
    expect(
      manifest.cases.filter(({ expected }) => expected.length === 0),
    ).toHaveLength(2);
    for (const benchmarkCase of manifest.cases) {
      expect(benchmarkCase.findingsPaths).toHaveLength(1);
    }
  });

  test("emits ordered multi-hop propagation and preserves negative controls", async () => {
    const inventories = new Map<string, string>();
    for (const id of [
      "javascript-multi-hop-command-injection",
      "javascript-multi-hop-safe-command",
      "javascript-multi-hop-sql-injection",
      "javascript-multi-hop-safe-sql",
    ]) {
      inventories.set(
        id,
        await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id)),
      );
    }

    const command = inventories.get("javascript-multi-hop-command-injection");
    expect(command).toContain('"scope":"cross-file-multi-hop-wrapper"');
    expect(command?.match(/"kind":"relative-module-import"/gu)).toHaveLength(3);
    expect(command?.match(/"kind":"wrapper-call-argument"/gu)).toHaveLength(3);
    expect(command?.match(/"kind":"wrapper-parameter"/gu)).toHaveLength(3);
    expect(command).toContain('"path":"src/gateway.js"');
    expect(inventories.get("javascript-multi-hop-safe-command")).not.toContain(
      '"scope":"cross-file-multi-hop-wrapper"',
    );
    expect(inventories.get("javascript-multi-hop-sql-injection")).toContain(
      '"id":"node-http-sql"',
    );
    expect(inventories.get("javascript-multi-hop-safe-sql")).toContain(
      '"kind":"bound-query-parameters"',
    );
  });

  test("rejects outer reassignment and a fourth relative-import hop", async () => {
    const root = await mkdtemp(join(tmpdir(), "javascript-import-depth-"));
    const source = join(root, "src");
    try {
      await mkdir(source, { recursive: true });
      await writeFile(
        join(source, "runner.js"),
        [
          'import { exec } from "node:child_process";',
          "export function runHost(host) {",
          "  return exec(`ping ${host}`);",
          "}",
          "",
        ].join("\n"),
      );
      await writeFile(
        join(source, "service.js"),
        [
          'import { runHost } from "./runner.js";',
          "export function dispatchHost(host) {",
          "  return runHost(host);",
          "}",
          "",
        ].join("\n"),
      );
      await writeFile(
        join(source, "server.js"),
        [
          'import { routeHost } from "./gateway.js";',
          "export function checkHost(request) {",
          '  const host = String(request.query.host ?? "");',
          "  return routeHost(host);",
          "}",
          "",
        ].join("\n"),
      );
      await writeFile(
        join(source, "gateway.js"),
        [
          'import { dispatchHost } from "./service.js";',
          "export function routeHost(host) {",
          '  host = "fixed";',
          "  return dispatchHost(host);",
          "}",
          "",
        ].join("\n"),
      );
      expect(await buildResidualRiskInventory(root)).not.toContain(
        '"scope":"cross-file-multi-hop-wrapper"',
      );

      await writeFile(
        join(source, "gateway.js"),
        [
          'import { forwardHost } from "./facade.js";',
          "export function routeHost(host) {",
          "  return forwardHost(host);",
          "}",
          "",
        ].join("\n"),
      );
      await writeFile(
        join(source, "facade.js"),
        [
          'import { dispatchHost } from "./service.js";',
          "export function forwardHost(host) {",
          "  return dispatchHost(host);",
          "}",
          "",
        ].join("\n"),
      );
      expect(await buildResidualRiskInventory(root)).not.toContain(
        '"scope":"cross-file-multi-hop-wrapper"',
      );

      await writeFile(
        join(source, "runner.js"),
        [
          'import { exec } from "node:child_process";',
          'import { dispatchHost } from "./service.js";',
          "export function runHost(host) {",
          "  return exec(`ping ${host}`);",
          "}",
          "export function reenterHost(host) {",
          "  return dispatchHost(host);",
          "}",
          "",
        ].join("\n"),
      );
      await writeFile(
        join(source, "server.js"),
        [
          'import { reenterHost } from "./runner.js";',
          "export function checkHost(request) {",
          '  const host = String(request.query.host ?? "");',
          "  return reenterHost(host);",
          "}",
          "",
        ].join("\n"),
      );
      expect(await buildResidualRiskInventory(root)).not.toContain(
        '"scope":"cross-file-multi-hop-wrapper"',
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("teaches the reviewer the exact three-hop import ceiling", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({ frameworkModel: { language: "javascript" } }),
    );
    expect(prompt).toContain(
      "JavaScript/TypeScript and Python prove either two or three ordered language-matched call/parameter hops",
    );
    expect(prompt).toContain("reassignment before any recorded call");
  });
});
