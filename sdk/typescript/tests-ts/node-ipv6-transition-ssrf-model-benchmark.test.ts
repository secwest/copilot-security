import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface FrameworkRecord {
  path: string;
  frameworkModel?: {
    id: string;
    scope: string;
    source: { kind: string; path: string; line: number };
    sink: { kind: string; path: string; line: number; cweIds: string[] };
    propagators: Array<{ kind: string; path: string; line: number }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

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

const benchmarkRoot = resolve(import.meta.dir, "..", "..", "..", "benchmarks");
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function specializedRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-ssrf-ipv6-transition-incomplete-guard",
    );
}

async function fixtureRecords(id: string): Promise<FrameworkRecord[]> {
  return specializedRecords(
    await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id)),
  );
}

async function repositoryRecords(
  files: Readonly<Record<string, string>>,
): Promise<FrameworkRecord[]> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-ipv6-transition-"),
  );
  temporaryPaths.push(repository);
  for (const [path, source] of Object.entries(files)) {
    const destination = join(repository, path);
    await mkdir(resolve(destination, ".."), { recursive: true });
    await writeFile(destination, source);
  }
  return specializedRecords(await buildResidualRiskInventory(repository));
}

function singleFileSource(options: {
  guard: string;
  canonicalizer?: string;
  hostExpression?: string;
}): string {
  return `${options.canonicalizer ?? ""}
function isPrivateIpv4(host) {
  return /^(?:10\\.|127\\.|169\\.254\\.|192\\.168\\.)/.test(host);
}

export async function preview(request) {
  const rawUrl = request.query.url;
  const host = new URL(rawUrl).hostname;
  ${options.guard.replaceAll("$HOST", options.hostExpression ?? "host")}
  return fetch(rawUrl);
}
`;
}

describe("Node IPv6-transition SSRF incomplete-guard model", () => {
  test("keeps the exploit and complete canonicalization control under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-ipv6-transition-ssrf-manifest.json"),
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
      "javascript-ipv6-transition-ssrf",
      "javascript-safe-ipv6-transition-fetch",
    ]);
    expect(manifest.cases[0]?.findingsPaths).toHaveLength(1);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-918"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.findingsPaths).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves the exact request, guard, and outbound-request path", async () => {
    const vulnerable = await fixtureRecords("javascript-ipv6-transition-ssrf");
    const safe = await fixtureRecords("javascript-safe-ipv6-transition-fetch");
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      id: "node-ssrf-ipv6-transition-incomplete-guard",
      scope: "cross-file-wrapper",
      source: {
        kind: "http-request-field",
        path: "src/server.js",
        line: 4,
      },
      sink: {
        kind: "outbound-http-url",
        path: "src/upstream.js",
        line: 8,
        cweIds: ["CWE-918", "CWE-1389"],
      },
    });
    expect(vulnerable[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "incomplete-ipv6-transition-address-guard",
      path: "src/upstream.js",
      line: 7,
    });
    expect(
      vulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "relative-module-import",
      "wrapper-call-argument",
      "wrapper-parameter",
    ]);
    expect(safe).toEqual([]);
  });

  test("retains mapped-only normalization because NAT64 and 6to4 remain", async () => {
    const records = await repositoryRecords({
      "mapped-only.js": singleFileSource({
        canonicalizer: `function canonicalizeMappedAddress(host) {
  if (host.startsWith("::ffff:")) return host.slice(7);
  return host;
}`,
        guard:
          'const canonicalHost = canonicalizeMappedAddress(host);\n  if (isPrivateIpv4(canonicalHost)) throw new Error("private");',
      }),
    });
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.scope).toBe("same-file");
  });

  test("binds direct host values in fetch and native HTTP option sinks", async () => {
    const records = await repositoryRecords({
      "fetch-host.js": `function isPrivateIpv4(host) { return host.startsWith("127."); }
export async function preview(request) {
  const host = request.query.host;
  if (isPrivateIpv4(host)) throw new Error("private");
  return fetch(host);
}
`,
      "http-host.js": `import * as http from "node:http";
function isPrivateIpv4(host) { return host.startsWith("127."); }
export function preview(request) {
  const host = request.query.host;
  if (isPrivateIpv4(host)) throw new Error("private");
  return http.get({ hostname: host, path: "/" });
}
`,
    });
    expect(records.map(({ path }) => path).sort()).toEqual([
      "fetch-host.js",
      "http-host.js",
    ]);
  });

  test("requires a fail-closed IPv4 guard on the sink host", async () => {
    const records = await repositoryRecords({
      "log-only.js": singleFileSource({
        guard: 'if (isPrivateIpv4($HOST)) console.warn("private");',
      }),
      "other-host.js": singleFileSource({
        guard:
          'const otherHost = request.query.audit;\n  if (isPrivateIpv4(otherHost)) throw new Error("private");',
      }),
      "no-guard.js": singleFileSource({ guard: "void host;" }),
    });
    expect(records).toEqual([]);
  });

  test("does not accept comments as complete transition handling", async () => {
    const records = await repositoryRecords({
      "comment.js": singleFileSource({
        canonicalizer: `// canonicalize ::ffff:, 64:ff9b::, and 2002: with slice()
function auditOnly(host) { return host; }`,
        guard: 'if (isPrivateIpv4($HOST)) throw new Error("private");',
      }),
    });
    expect(records).toHaveLength(1);
  });

  test("does not let an unused complete canonicalizer suppress a raw-host guard", async () => {
    const records = await repositoryRecords({
      "unused-complete.js": singleFileSource({
        canonicalizer: `function canonicalizeIpv6TransitionAddress(host) {
  if (host.startsWith("::ffff:")) return host.slice(7);
  if (host.startsWith("64:ff9b::")) return extractEmbeddedIpv4(host);
  if (host.startsWith("2002:")) return extractEmbeddedIpv4(host);
  return host;
}`,
        guard: 'if (isPrivateIpv4($HOST)) throw new Error("private");',
      }),
    });
    expect(records).toHaveLength(1);
  });

  test("excludes conventional test and example paths", async () => {
    const source = singleFileSource({
      guard: 'if (isPrivateIpv4($HOST)) throw new Error("private");',
    });
    const records = await repositoryRecords({
      "src/preview.test.ts": source,
      "tests/preview.js": source,
      "examples/preview.js": source,
    });
    expect(records).toEqual([]);
  });

  test("teaches the quality gate to validate every transition family", () => {
    const prompt = scanQualityGatePrompt("inventory-row");
    expect(prompt).toContain(
      "For node-ssrf-ipv6-transition-incomplete-guard rows",
    );
    expect(prompt).toContain("IPv4-mapped IPv6");
    expect(prompt).toContain("NAT64");
    expect(prompt).toContain("6to4");
  });
});
