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
  "javascript-idor",
  "javascript-safe-authorization",
  "javascript-cross-file-idor",
  "javascript-cross-file-safe-authorization",
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

function authorizationRecord(
  inventory: string,
  path?: string,
): FrameworkRecord | undefined {
  return records(inventory).find(
    (record) =>
      record.frameworkModel?.id === "node-http-object-authorization" &&
      (path === undefined || record.path === path),
  );
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

describe("Node object-authorization framework-model effectiveness benchmark", () => {
  test("keeps same-file and cross-file exploit/control pairs under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-object-authorization-manifest.json"),
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
        expect(expected.cwe).toEqual(["CWE-639", "CWE-862"]);
        expect(expected.requireValidation).toBeTrue();
        expect(expected.requireAttackPath).toBeTrue();
        expect(expected.requireCodeEvidence).toBeTrue();
      }
    }
  });

  test("preserves same-file object selection and the exact ownership filter", async () => {
    const vulnerable = authorizationRecord(
      await fixtureInventory("javascript-idor"),
    );
    const safe = authorizationRecord(
      await fixtureInventory("javascript-safe-authorization"),
    );

    expect(vulnerable?.frameworkModel).toMatchObject({
      id: "node-http-object-authorization",
      scope: "same-file",
      source: { path: "src/invoices.js", line: 2 },
      sink: {
        path: "src/invoices.js",
        line: 2,
        cweIds: ["CWE-639", "CWE-862"],
      },
      candidateControls: [],
    });
    expect(safe?.frameworkModel).toMatchObject({
      id: "node-http-object-authorization",
      scope: "same-file",
      source: { path: "src/invoices.js", line: 2 },
      sink: { path: "src/invoices.js", line: 2 },
    });
    expect(safe?.frameworkModel?.candidateControls).toContainEqual({
      kind: "principal-bound-object-filter",
      path: "src/invoices.js",
      line: 4,
    });
  });

  test("preserves the cross-file object-reference path and owner constraint", async () => {
    const vulnerable = authorizationRecord(
      await fixtureInventory("javascript-cross-file-idor"),
    );
    const safe = authorizationRecord(
      await fixtureInventory("javascript-cross-file-safe-authorization"),
    );

    expect(vulnerable?.frameworkModel).toMatchObject({
      id: "node-http-object-authorization",
      scope: "cross-file-wrapper",
      source: { path: "src/server.js", line: 4 },
      sink: {
        path: "src/invoices.js",
        line: 7,
        cweIds: ["CWE-639", "CWE-862"],
      },
      candidateControls: [],
    });
    expect(
      vulnerable?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "relative-module-import",
      "wrapper-call-argument",
      "wrapper-parameter",
    ]);
    expect(safe?.frameworkModel).toMatchObject({
      id: "node-http-object-authorization",
      scope: "cross-file-wrapper",
      source: { path: "src/server.js", line: 4 },
      sink: { path: "src/invoices.js", line: 6 },
    });
    expect(safe?.frameworkModel?.candidateControls).toContainEqual({
      kind: "principal-bound-object-filter",
      path: "src/invoices.js",
      line: 8,
    });
  });

  test("supports multiline generic ORM lookups and post-lookup authorization", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-object-authorization-"),
    );
    temporaryPaths.push(repository);
    await writeFile(
      join(repository, "prisma.ts"),
      [
        "export async function readInvoice(request, response, prisma) {",
        "  const invoiceId = String(request.params.invoiceId);",
        "  const invoice = await prisma.invoice.findUnique<Invoice>({",
        "    where: { id: invoiceId },",
        "  });",
        "  if (!invoice || invoice.ownerId !== request.user.customerId) {",
        "    return response.status(404).end();",
        "  }",
        "  return response.json(invoice);",
        "}",
        "",
      ].join("\n"),
    );

    const record = authorizationRecord(
      await buildResidualRiskInventory(repository),
      "prisma.ts",
    );
    expect(record?.frameworkModel).toMatchObject({
      id: "node-http-object-authorization",
      scope: "same-file",
      source: { path: "prisma.ts", line: 2 },
      sink: { path: "prisma.ts", line: 3 },
    });
    expect(record?.frameworkModel?.candidateControls).toContainEqual({
      kind: "post-lookup-object-authorization",
      path: "prisma.ts",
      line: 6,
    });
  });

  test("rejects unrelated, fixed, reassigned, comment, and string pseudo-flows", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-object-controls-"),
    );
    temporaryPaths.push(repository);
    await mkdir(join(repository, "src"));
    const fixtures = new Map<string, string>([
      [
        "unrelated.js",
        [
          "export function read(request, database) {",
          "  const invoiceId = request.params.invoiceId;",
          '  return database.invoices.findById("server-owned-id");',
          "}",
        ].join("\n"),
      ],
      [
        "reassigned.js",
        [
          "export function read(request, database) {",
          "  let invoiceId = request.params.invoiceId;",
          '  invoiceId = "server-owned-id";',
          "  return database.invoices.findById(invoiceId);",
          "}",
        ].join("\n"),
      ],
      [
        "text-only.js",
        [
          "// database.invoices.findById(request.params.invoiceId)",
          'export const example = "database.invoices.findById(request.params.invoiceId)";',
        ].join("\n"),
      ],
      [
        "attacker-owner-alias.js",
        [
          "export function read(request, database) {",
          "  const invoiceId = request.params.invoiceId;",
          "  const userId = request.params.userId;",
          "  return database.invoices.findOne({ id: invoiceId, ownerId: userId });",
          "}",
        ].join("\n"),
      ],
    ]);
    for (const [name, contents] of fixtures) {
      await writeFile(join(repository, "src", name), `${contents}\n`);
    }

    const inventory = await buildResidualRiskInventory(repository);
    for (const name of fixtures.keys()) {
      const record = authorizationRecord(inventory, `src/${name}`);
      if (name === "attacker-owner-alias.js") {
        expect(record?.frameworkModel?.candidateControls).toEqual([]);
      } else {
        expect(record).toBeUndefined();
      }
    }
  });

  test("does not promote attacker owner fields or unrelated principal text into controls", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-object-counterevidence-"),
    );
    temporaryPaths.push(repository);
    await writeFile(
      join(repository, "invoices.js"),
      [
        "export function read(request, database) {",
        "  const currentCustomerId = request.user.customerId;",
        "  return database.invoices.findOne({",
        "    id: request.params.invoiceId,",
        "    ownerId: request.params.ownerId,",
        "  });",
        "}",
        "",
      ].join("\n"),
    );

    const record = authorizationRecord(
      await buildResidualRiskInventory(repository),
    );
    expect(record?.frameworkModel?.candidateControls).toEqual([]);
  });

  test("teaches exact object authorization rather than authentication or UUID folklore", () => {
    const prompt = scanQualityGatePrompt("{}");
    expect(prompt).toContain("object-level authorization");
    expect(prompt).toContain("attacker-controlled object identifier");
    expect(prompt).toContain("authenticated principal");
    expect(prompt).toContain("UUID");
    expect(prompt).toContain("same requested object");
  });
});
