import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import {
  buildFindingQualityGapInventory,
  buildResidualRiskInventory,
} from "../src/residual-risk.js";

const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

async function scanBrowserSource(
  source: string,
  sourcePath = "session-bridge.ts",
): Promise<any[]> {
  const repository = await mkdtemp(join(tmpdir(), "browser-postmessage-"));
  temporaryPaths.push(repository);
  await mkdir(join(repository, "src"));
  await writeFile(
    join(repository, "package.json"),
    JSON.stringify({ private: true, type: "module" }),
  );
  await writeFile(join(repository, "src", sourcePath), source);
  return (await buildResidualRiskInventory(repository))
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line))
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-browser-postmessage-wildcard-sensitive-data",
    );
}

describe("browser postMessage sensitive-data model", () => {
  test("keeps the executable wildcard and fixed-origin fixtures paired", async () => {
    const fixtureRoot = resolve(
      process.cwd(),
      "..",
      "..",
      "benchmarks",
      "fixtures",
    );
    const records = async (name: string): Promise<any[]> =>
      (await buildResidualRiskInventory(join(fixtureRoot, name)))
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line))
        .filter(
          (record) =>
            record.frameworkModel?.id ===
            "node-browser-postmessage-wildcard-sensitive-data",
        );

    const vulnerable = await records(
      "node-browser-postmessage-wildcard-sensitive-data",
    );
    const control = await records(
      "node-browser-postmessage-fixed-origin-sensitive-data",
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      source: { kind: "browser-sensitive-storage", line: 3 },
      sink: {
        kind: "cross-window-wildcard-postmessage",
        line: 4,
        cweIds: ["CWE-201", "CWE-359"],
      },
      propagators: expect.arrayContaining([
        expect.objectContaining({
          kind: "browser-sensitive-value",
          symbol: "localStorage.getItem(access_token)",
        }),
        expect.objectContaining({
          kind: "browser-window-target",
          symbol: "navigable-window:window.parent",
        }),
        expect.objectContaining({
          kind: "postmessage-wildcard-target-origin",
          symbol: "options-target-origin",
        }),
      ]),
    });
    expect(control).toHaveLength(0);
  });

  test("detects browser storage disclosure through the options overload", async () => {
    const found = await scanBrowserSource(
      [
        'const TARGET_ORIGIN = "*";',
        "export function publishSession() {",
        '  const accessToken = window.localStorage.getItem("access_token");',
        "  window.parent.postMessage(",
        '    { type: "session", accessToken },',
        "    { targetOrigin: TARGET_ORIGIN },",
        "  );",
        "}",
      ].join("\n"),
    );

    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      source: { kind: "browser-sensitive-storage", line: 3 },
      sink: {
        kind: "cross-window-wildcard-postmessage",
        line: 4,
        cweIds: ["CWE-201", "CWE-359"],
      },
    });
  });

  test("detects positional wildcard cookie disclosure to opener and top", async () => {
    const opener = await scanBrowserSource(
      [
        "export function publishCookies() {",
        '  window.opener?.postMessage(document.cookie, "*");',
        "}",
      ].join("\n"),
    );
    const top = await scanBrowserSource(
      [
        "export function publishCookies() {",
        '  globalThis.top.postMessage(window.document.cookie, "*");',
        "}",
      ].join("\n"),
    );
    const unqualified = await scanBrowserSource(
      [
        "export function publishSession() {",
        '  const token = sessionStorage.getItem("id_token");',
        '  parent.postMessage({ token }, "*");',
        "}",
      ].join("\n"),
    );
    const assigned = await scanBrowserSource(
      [
        "const target = top;",
        "export function publishSession() {",
        '  const token = sessionStorage.getItem("id_token");',
        '  target.postMessage({ token }, "*");',
        "}",
      ].join("\n"),
    );
    expect(opener).toHaveLength(1);
    expect(opener[0]?.frameworkModel).toMatchObject({
      source: { kind: "browser-sensitive-cookie", line: 2 },
      sink: { line: 2, cweIds: ["CWE-201", "CWE-359"] },
    });
    expect(top).toHaveLength(1);
    expect(unqualified).toHaveLength(1);
    expect(assigned).toHaveLength(1);
  });

  test("follows stable popup, object, JSON, base64, and encoding flow", async () => {
    const found = await scanBrowserSource(
      [
        'const popup = window.open("https://portal.example");',
        "export function publishSession() {",
        '  const refresh = sessionStorage.getItem("refreshToken");',
        "  const message = JSON.stringify({",
        "    credential: `Bearer ${encodeURIComponent(btoa(refresh))}` ,",
        "  });",
        '  popup?.postMessage(message, "*");',
        "}",
      ].join("\n"),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel?.source).toEqual({
      kind: "browser-sensitive-storage",
      path: "src/session-bridge.ts",
      line: 3,
    });
    expect(found[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "browser-window-target",
          symbol: "opened-window:popup",
        }),
      ]),
    );
  });

  test("treats fixed and omitted target origins as controls", async () => {
    const fixed = await scanBrowserSource(
      [
        "export function publishSession() {",
        '  const token = localStorage.getItem("session_token");',
        '  window.parent.postMessage({ token }, "https://portal.example");',
        "}",
      ].join("\n"),
    );
    const options = await scanBrowserSource(
      [
        'const DELIVERY = { targetOrigin: "https://portal.example" };',
        "export function publishSession() {",
        '  const token = localStorage.getItem("session_token");',
        "  window.parent.postMessage({ token }, DELIVERY);",
        "}",
      ].join("\n"),
    );
    const omitted = await scanBrowserSource(
      [
        "export function publishSession() {",
        '  const token = localStorage.getItem("session_token");',
        "  window.parent.postMessage({ token });",
        "}",
      ].join("\n"),
    );
    expect(fixed).toHaveLength(0);
    expect(options).toHaveLength(0);
    expect(omitted).toHaveLength(0);
  });

  test("rejects nonsensitive storage and non-Window postMessage lookalikes", async () => {
    const nonsensitive = await scanBrowserSource(
      [
        "export function publishTheme() {",
        '  const theme = window.localStorage.getItem("theme");',
        '  window.parent.postMessage({ theme }, "*");',
        "}",
      ].join("\n"),
    );
    const object = await scanBrowserSource(
      [
        "const channel = { postMessage() {} };",
        "export function publishSession() {",
        '  const token = window.localStorage.getItem("access_token");',
        '  channel.postMessage(token, "*");',
        "}",
      ].join("\n"),
    );
    const worker = await scanBrowserSource(
      [
        'const worker = new Worker("worker.js");',
        "export function publishSession() {",
        '  const token = window.localStorage.getItem("access_token");',
        '  worker.postMessage(token, "*");',
        "}",
      ].join("\n"),
    );
    expect(nonsensitive).toHaveLength(0);
    expect(object).toHaveLength(0);
    expect(worker).toHaveLength(0);
  });

  test("rejects shadowed globals, reassigned flow, dynamic origins, and spreads", async () => {
    const shadowedWindow = await scanBrowserSource(
      [
        "export function publishSession(window: Window) {",
        '  const token = window.localStorage.getItem("access_token");',
        '  window.parent.postMessage(token, "*");',
        "}",
      ].join("\n"),
    );
    const shadowedStorage = await scanBrowserSource(
      [
        'const localStorage = { getItem: () => "public" };',
        "export function publishSession() {",
        '  const token = localStorage.getItem("access_token");',
        '  window.parent.postMessage(token, "*");',
        "}",
      ].join("\n"),
    );
    const arrowShadow = await scanBrowserSource(
      [
        "export const publishSession = (window: Window) => {",
        '  const token = window.localStorage.getItem("access_token");',
        '  window.parent.postMessage(token, "*");',
        "};",
      ].join("\n"),
    );
    const shadowedParent = await scanBrowserSource(
      [
        "export function publishSession(parent: MessagePort) {",
        '  const token = localStorage.getItem("access_token");',
        '  parent.postMessage(token, "*");',
        "}",
      ].join("\n"),
    );
    const reassigned = await scanBrowserSource(
      [
        "export function publishSession() {",
        '  let token = localStorage.getItem("access_token");',
        '  token = "redacted";',
        '  window.parent.postMessage(token, "*");',
        "}",
      ].join("\n"),
    );
    const dynamic = await scanBrowserSource(
      [
        "export function publishSession(origin: string) {",
        '  const token = localStorage.getItem("access_token");',
        "  window.parent.postMessage(token, { targetOrigin: origin });",
        "}",
      ].join("\n"),
    );
    const spread = await scanBrowserSource(
      [
        'const delivery = { targetOrigin: "*", ...window.delivery };',
        "export function publishSession() {",
        '  const token = localStorage.getItem("access_token");',
        "  window.parent.postMessage(token, delivery);",
        "}",
      ].join("\n"),
    );
    expect(shadowedWindow).toHaveLength(0);
    expect(shadowedStorage).toHaveLength(0);
    expect(arrowShadow).toHaveLength(0);
    expect(shadowedParent).toHaveLength(0);
    expect(reassigned).toHaveLength(0);
    expect(dynamic).toHaveLength(0);
    expect(spread).toHaveLength(0);
  });

  test("excludes tests and requires disclosure evidence in both narratives", async () => {
    const source = [
      "export function publishSession() {",
      '  const token = localStorage.getItem("access_token");',
      '  window.parent.postMessage(token, "*");',
      "}",
    ].join("\n");
    expect(
      await scanBrowserSource(source, "session-bridge.test.ts"),
    ).toHaveLength(0);

    const repository = resolve(
      process.cwd(),
      "..",
      "..",
      "benchmarks",
      "fixtures",
      "node-browser-postmessage-wildcard-sensitive-data",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(join(tmpdir(), "postmessage-quality-"));
    temporaryPaths.push(scanDirectory);
    const finding: any = {
      occurrenceId: "occ_browser_postmessage_quality",
      taxonomy: { cwe: ["CWE-201", "CWE-359"] },
      locations: [
        { path: "src/session-bridge.js", startLine: 3, role: "source" },
        { path: "src/session-bridge.js", startLine: 4, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "stored-token",
          path: "src/session-bridge.js",
          startLine: 3,
          code: 'const accessToken = window.localStorage.getItem("access_token");',
          explanation: "Stored access token.",
          role: "source",
        },
        {
          id: "wildcard-send",
          path: "src/session-bridge.js",
          startLine: 4,
          code: "window.parent.postMessage(",
          explanation: "Cross-window send.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A value is sent.",
        method: "source review",
        evidence: ["stored-token", "wildcard-send"],
      },
      attackPath: {
        summary: "A value is sent.",
        dataflow: {
          source: "stored-token",
          sink: "wildcard-send",
          outcome: "message delivery",
        },
        evidenceRefs: ["stored-token", "wildcard-send"],
      },
    };
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );
    const incomplete = await buildFindingQualityGapInventory(
      scanDirectory,
      repository,
      inventory,
    );
    expect(incomplete).toContain("missing_model_specific_validation_evidence");
    expect(incomplete).toContain("missing_model_specific_attack_path_evidence");

    const contract =
      "The access token from localStorage key access_token flows into the window.parent postMessage options overload with wildcard targetOrigin. If an embedding window navigates cross-origin, that receiver can observe the session credential; this information disclosure is CWE-201 and CWE-359.";
    finding.validation.summary = contract;
    finding.attackPath.summary = contract;
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );
    const complete = await buildFindingQualityGapInventory(
      scanDirectory,
      repository,
      inventory,
    );
    expect(complete).not.toContain(
      "missing_model_specific_validation_evidence",
    );
    expect(complete).not.toContain(
      "missing_model_specific_attack_path_evidence",
    );
  });

  test("teaches the reviewer the exact confidentiality boundary", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"node-browser-postmessage-wildcard-sensitive-data"}}',
    );
    expect(prompt).toContain(
      "node-browser-postmessage-wildcard-sensitive-data",
    );
    expect(prompt).toContain("localStorage/sessionStorage");
    expect(prompt).toContain("parent/top/opener");
    expect(prompt).toContain("options-object targetOrigin");
    expect(prompt).toContain("Encoding, URI escaping");
    expect(prompt).toContain("omitted targetOrigin");
    expect(prompt).toContain("CWE-201/CWE-359");
    expect(prompt).toContain("account takeover");
  });
});
