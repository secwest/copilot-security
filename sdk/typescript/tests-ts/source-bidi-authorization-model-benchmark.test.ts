import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

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
      requiredTextAnyOf?: string[][];
      locations?: Array<{ startLine: number; endLine: number }>;
    }>;
  }>;
}

interface AuthorizationFixture {
  canDeleteDocument(
    user: { id: string; isAdmin: boolean },
    document: { ownerId: string },
  ): boolean;
}

interface DisplayControlRecord {
  path: string;
  line: number;
  categories: string[];
  excerptBase64: string;
  sourceDisplayControl?: {
    codePoint: string;
    abbreviation: string;
    pairStatus: string;
  };
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

describe("Unicode bidirectional source-spoofing authorization benchmark", () => {
  test("keeps a strict exploit and natural-language control pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "source-bidi-authorization-manifest.json"),
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
      "javascript-trojan-source-authorization-bypass",
      "javascript-bidi-natural-language-control",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-863"],
      acceptableSeverities: ["high", "critical"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
      requiredTextAnyOf: [
        ["bidirectional", "bidi", "trojan source", "U+202E"],
        ["unconditional", "non-admin", "non-administrator", "owner"],
      ],
      locations: [{ startLine: 4, endLine: 5 }],
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("emits exact byte-safe candidates only for the exploit fixture", async () => {
    const affected = displayControlRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-trojan-source-authorization-bypass",
        ),
      ),
    );
    const control = displayControlRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-bidi-natural-language-control",
        ),
      ),
    );

    expect(affected).toHaveLength(4);
    expect(control).toEqual([]);
    expect(
      affected.map((record) => record.sourceDisplayControl?.abbreviation),
    ).toEqual(["RLO", "LRI", "LRI", "PDI"]);
    expect(affected[0]).toMatchObject({
      path: "src/authorize.js",
      line: 4,
      sourceDisplayControl: {
        codePoint: "U+202E",
        pairStatus: "unpaired-opener",
      },
    });
    expect(
      affected.every((record) =>
        record.categories.includes("source-bidi-explicit-control"),
      ),
    ).toBe(true);
    const rawControls = /[\u202A-\u202E\u2066-\u2069]/u;
    expect(
      affected.every((record) => !rawControls.test(JSON.stringify(record))),
    ).toBe(true);
    expect(
      affected.some((record) =>
        rawControls.test(
          Buffer.from(record.excerptBase64, "base64").toString("utf8"),
        ),
      ),
    ).toBe(true);
  });

  test("proves the exploit and negative-control authorization outcomes", async () => {
    const affected = await loadFixture(
      "javascript-trojan-source-authorization-bypass",
    );
    const control = await loadFixture(
      "javascript-bidi-natural-language-control",
    );
    const outsider = { id: "attacker", isAdmin: false };
    const document = { ownerId: "victim" };

    expect(affected.canDeleteDocument(outsider, document)).toBe(true);
    expect(control.canDeleteDocument(outsider, document)).toBe(false);
  });

  test("requires logical-order validation and rejects Unicode-language folklore", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("For source-bidi-* rows");
    expect(prompt).toContain("logical token order");
    expect(prompt).toContain("CVE-2021-42574/Trojan Source");
    expect(prompt).toContain("ordinary right-to-left prose");
    expect(prompt).toContain("test/benchmark fixtures");
    expect(prompt).toContain("never reproduce an unsafe excerpt");
  });
});

function displayControlRecords(inventory: string): DisplayControlRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as DisplayControlRecord)
    .filter((record) => record.sourceDisplayControl !== undefined);
}

async function loadFixture(name: string): Promise<AuthorizationFixture> {
  const source = join(benchmarkRoot, "fixtures", name, "src", "authorize.js");
  return (await import(pathToFileURL(source).href)) as AuthorizationFixture;
}
