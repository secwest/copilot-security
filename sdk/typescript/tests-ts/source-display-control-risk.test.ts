import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildResidualRiskInventory } from "../src/residual-risk.js";
import { sourceDisplayControlRiskRecords } from "../src/source-display-control-risk.js";

const temporaryPaths: string[] = [];
const control = (codePoint: number): string => String.fromCodePoint(codePoint);

afterEach(async () => {
  await Promise.all(
    temporaryPaths.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

describe("source display control candidates", () => {
  test("elevates an unpaired override in a comment without exposing it in JSONL", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-bidi-override-"),
    );
    temporaryPaths.push(repository);
    await mkdir(join(repository, "src"));
    const override = control(0x202e);
    await writeFile(
      join(repository, "src", "authorize.js"),
      [
        "export function canDelete(user, document) {",
        `  // ${override} } if (user.id === document.ownerId) {`,
        "  return true;",
        "}",
        "",
      ].join("\n"),
    );

    const inventory = await buildResidualRiskInventory(repository);
    const records = inventory.split("\n").map((line) => JSON.parse(line));
    const candidate = records.find((record) =>
      record.categories.includes("source-bidi-override-control"),
    );

    expect(candidate.path).toBe("src/authorize.js");
    expect(candidate.line).toBe(2);
    expect(candidate.priority).toBeUndefined();
    expect(candidate.sourceDisplayControl).toMatchObject({
      schemaVersion: "1.0",
      codePoint: "U+202E",
      abbreviation: "RLO",
      family: "override",
      column: 6,
      pairStatus: "unpaired-opener",
      lexicalContextHint: "comment-like",
    });
    expect(inventory).not.toContain(override);
    expect(
      Buffer.from(candidate.excerptBase64, "base64").toString("utf8"),
    ).toContain(override);
  });

  test("records same-line and cross-line pairs with exact partner locations", () => {
    const lri = control(0x2066);
    const pdi = control(0x2069);
    const sameLine = sourceDisplayControlRiskRecords("same.js", [
      `const label = "${lri}עברית${pdi}";`,
    ]);
    const crossLine = sourceDisplayControlRiskRecords("cross.js", [
      `// ${lri}owner check`,
      `// continuation${pdi}`,
    ]);

    expect(sameLine).toHaveLength(2);
    expect(
      sameLine.every(
        (record) =>
          record.sourceDisplayControl.pairStatus === "paired-same-line",
      ),
    ).toBe(true);
    expect(crossLine).toHaveLength(2);
    expect(
      crossLine.every((record) =>
        record.categories.includes("source-bidi-cross-line-control"),
      ),
    ).toBe(true);
    expect(crossLine[0]!.sourceDisplayControl).toMatchObject({
      pairedLine: 2,
      pairedColumn: 16,
    });
    expect(crossLine[1]!.sourceDisplayControl).toMatchObject({
      pairedLine: 1,
      pairedColumn: 4,
    });
  });

  test("flags directional marks only when they touch ASCII syntax", () => {
    const rlm = control(0x200f);
    const records = sourceDisplayControlRiskRecords("operators.rs", [
      `return x ${rlm}<<${rlm} 8;`,
      `// Arabic prose ${rlm} مثال`,
    ]);

    expect(records).toHaveLength(2);
    expect(
      records.every((record) =>
        record.categories.includes("source-bidi-mark-adjacent-syntax"),
      ),
    ).toBe(true);
    expect(records.map((record) => record.line)).toEqual([1, 1]);
  });

  test("does not turn ordinary right-to-left source prose into a candidate", () => {
    const records = sourceDisplayControlRiskRecords("localized.ts", [
      "// هذه رسالة خطأ للمستخدم",
      'const message = "הבקשה נדחתה";',
    ]);

    expect(records).toEqual([]);
  });

  test("does not let a PDI pair nested embedding controls beyond its isolate", () => {
    const lri = control(0x2066);
    const rlo = control(0x202e);
    const pdi = control(0x2069);
    const pdf = control(0x202c);
    const records = sourceDisplayControlRiskRecords("nested.js", [
      `${lri}${rlo}hidden${pdi}${pdf}`,
    ]);

    expect(
      records.map((record) => [
        record.sourceDisplayControl.abbreviation,
        record.sourceDisplayControl.pairStatus,
      ]),
    ).toEqual([
      ["LRI", "paired-same-line"],
      ["RLO", "unpaired-opener"],
      ["PDI", "paired-same-line"],
      ["PDF", "unpaired-closer"],
    ]);
  });

  test("bounds hostile control floods while retaining middle overrides", () => {
    const lri = control(0x2066);
    const rlo = control(0x202e);
    const lines = [
      lri.repeat(2_000),
      `${lri.repeat(1_000)}${rlo}${lri.repeat(1_000)}`,
      lri.repeat(2_000),
    ];
    const records = sourceDisplayControlRiskRecords("flood.js", lines);

    expect(records.length).toBeLessThanOrEqual(193);
    expect(
      records.some(
        (record) => record.sourceDisplayControl.codePoint === "U+202E",
      ),
    ).toBe(true);
    expect(
      records.every(
        (record) =>
          record.sourceDisplayControl.fileControlCount === 6_001 &&
          record.sourceDisplayControl.inventoryTruncated === true &&
          record.sourceDisplayControl.pairStatus === "unknown-truncated" &&
          record.categories.includes("source-bidi-inventory-truncated"),
      ),
    ).toBe(true);
    expect(records[0]!.sourceDisplayControl.retainedControlCount).toBe(
      records.length,
    );
    expect(
      Math.max(...records.map((record) => record.excerpt.length)),
    ).toBeLessThan(7_000);
  });
});
