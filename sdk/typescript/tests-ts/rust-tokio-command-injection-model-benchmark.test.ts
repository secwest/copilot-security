import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";
import type { RustCommandInjectionRecord } from "../src/rust-command-risk.js";

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
      requiredValidationTextAnyOf?: string[][];
      requiredAttackPathTextAnyOf?: string[][];
      forbiddenText?: string[];
    }>;
  }>;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const vulnerableId = "rust-axum-tokio-shell-command-injection";
const controlId = "rust-axum-tokio-argv-command";
const handlerPath = "src/handlers/diagnostics.rs";

async function readUtf8(path: string): Promise<string> {
  return (await readFile(path, "utf8")).replace(/\r\n/g, "\n");
}

async function fixtureRecords(
  id: string,
): Promise<RustCommandInjectionRecord[]> {
  const inventory = await buildResidualRiskInventory(
    join(benchmarkRoot, "fixtures", id),
  );
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as RustCommandInjectionRecord)
    .filter(
      (record) => record.frameworkModel?.id === "rust-web-command-injection",
    );
}

describe("Rust Tokio command-injection model benchmark", () => {
  test("keeps the Tokio exploit and literal-argv control under perfect gates", async () => {
    const manifest = JSON.parse(
      await readUtf8(
        join(benchmarkRoot, "rust-tokio-command-injection-manifest.json"),
      ),
    ) as BenchmarkManifest;
    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      vulnerableId,
      controlId,
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-78", "CWE-88"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(
      manifest.cases[0]?.expected[0]?.requiredValidationTextAnyOf,
    ).toHaveLength(6);
    expect(
      manifest.cases[0]?.expected[0]?.requiredAttackPathTextAnyOf,
    ).toHaveLength(7);
    expect(manifest.cases[0]?.expected[0]?.forbiddenText).toHaveLength(6);
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("emits one exact Tokio shell row and no literal-argv row", async () => {
    const vulnerable = await fixtureRecords(vulnerableId);
    const control = await fixtureRecords(controlId);
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: handlerPath,
      line: 15,
      categories: ["rust-web-command-injection"],
      frameworkModel: {
        schemaVersion: "1.2",
        id: "rust-web-command-injection",
        language: "rust",
        scope: "same-file",
        source: {
          kind: "rust-http-extractor",
          path: handlerPath,
          line: 10,
          symbol: "axum::Query(input)",
        },
        sink: {
          kind: "rust-process-shell-command",
          path: handlerPath,
          line: 15,
          symbol: "tokio::process::Command;method=output;argument=2",
          cweIds: ["CWE-78", "CWE-88"],
        },
        candidateControls: [],
      },
    });
    expect(
      vulnerable[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual(["rust-local-assignment", "rust-format-macro"]);
    expect(control).toEqual([]);
  });

  test("keeps source, builder, execution, and response topology aligned", async () => {
    const sources = await Promise.all(
      [vulnerableId, controlId].map((id) =>
        readUtf8(
          join(
            benchmarkRoot,
            "fixtures",
            id,
            "src",
            "handlers",
            "diagnostics.rs",
          ),
        ),
      ),
    );
    for (const source of sources) {
      expect(source).toContain(
        "pub async fn diagnostics(Query(input): Query<DiagnosticQuery>)",
      );
      expect(source).toContain("use tokio::process::Command;");
      expect(source).toContain(".output()\n        .await");
      expect(source).toContain("String::from_utf8_lossy(&output.stdout)");
    }
    expect(sources[0]).toContain('Command::new("sh")');
    expect(sources[0]).toContain('.arg("-c")');
    expect(sources[0]).toContain("format!(");
    expect(sources[1]).toContain('Command::new("printf")');
    expect(sources[1]).toContain('.arg("%s")');
    expect(sources[1]).not.toContain("format!(");
  });

  test("pins a Cargo-1.75-compatible current Tokio runtime", async () => {
    const fixtureData = await Promise.all(
      [vulnerableId, controlId].map(async (id) => ({
        manifest: await readUtf8(
          join(benchmarkRoot, "fixtures", id, "Cargo.toml"),
        ),
        lock: await readUtf8(join(benchmarkRoot, "fixtures", id, "Cargo.lock")),
        witness: await readUtf8(
          join(benchmarkRoot, "fixtures", id, "examples", "witness.rs"),
        ),
      })),
    );
    for (const fixture of fixtureData) {
      expect(fixture.manifest).toContain('tokio = { version = "=1.53.1"');
      expect(fixture.manifest).toContain('"macros", "process", "rt"');
      expect(fixture.lock).toStartWith(
        "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 3",
      );
      expect(fixture.lock).toContain('name = "tokio"\nversion = "1.53.1"');
      expect(fixture.witness).toContain("#[tokio::main");
      expect(fixture.witness).toContain("RUST_COMMAND_MARKER");
      expect(fixture.witness).not.toContain("std::fs");
      expect(fixture.witness).not.toContain("std::net");
    }
  });

  test("adds a locked hosted Tokio witness differential", async () => {
    const workflow = await readUtf8(
      resolve(
        benchmarkRoot,
        "..",
        ".github",
        "workflows",
        "rust-fixture-ci.yml",
      ),
    );
    expect(workflow).toContain("axum-tokio-command-fixtures:");
    expect(workflow).toContain("cargo check --locked");
    expect(workflow).toContain(
      "rust-axum-tokio-shell-command-injection/Cargo.toml",
    );
    expect(workflow).toContain("rust-axum-tokio-argv-command/Cargo.toml");
    expect(workflow).toContain(
      'test "$vulnerable" = "shell_expanded_marker=1"',
    );
    expect(workflow).toContain('test "$control" = "shell_expanded_marker=0"');
  });

  test("teaches reviewer proof that is stricter than the CodeQL sink map", async () => {
    const inventory = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", vulnerableId),
    );
    const prompt = scanQualityGatePrompt(inventory);
    expect(inventory).toContain(
      '"tokio::process::Command;method=output;argument=2"',
    );
    expect(prompt).toContain(
      "rows whose sink symbol names tokio::process::Command",
    );
    expect(prompt).toContain("missing await is not execution prevention");
    expect(prompt).toContain(
      "does not make a fixed executable plus one remote literal argument into shell grammar",
    );
    expect(prompt).toContain(
      "CodeQL's August 2026 model treats tokio new, arg, and args",
    );
    expect(prompt).toContain("exact official Tokio identity");
  });

  test("keeps the canonical corpus paired at 189 exploit/control pairs", async () => {
    const manifest = JSON.parse(
      await readUtf8(join(benchmarkRoot, "manifest.json")),
    ) as BenchmarkManifest;
    const cases = new Map(manifest.cases.map((item) => [item.id, item]));
    expect(manifest.cases).toHaveLength(378);
    expect(cases.get(vulnerableId)?.expected).toHaveLength(1);
    expect(cases.get(controlId)?.expected).toEqual([]);
  });
});
