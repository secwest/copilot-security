import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import {
  buildFindingQualityGapInventory,
  buildResidualRiskInventory,
} from "../src/residual-risk.js";
import {
  rustCommandInjectionRecords,
  type RustCommandInjectionRecord,
} from "../src/rust-command-risk.js";

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
const caseIds = [
  "rust-axum-shell-command-injection",
  "rust-axum-argv-command",
] as const;
const handlerPath = "src/handlers/diagnostics.rs";

function records(
  source: string,
  path = handlerPath,
): RustCommandInjectionRecord[] {
  return rustCommandInjectionRecords(path, source.split(/\r?\n/u), source);
}

function axum(
  body: string,
  parameter = "Query(input): Query<Payload>",
  extractor = "Query",
  processImport = "use std::process::Command;",
): string {
  return `use axum::extract::${extractor};
${processImport}

async fn handler(${parameter}) -> String {
${body}
    String::new()
}
`;
}

async function fixtureRecords(
  id: (typeof caseIds)[number],
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

describe("Rust Axum and Actix Web command-injection model benchmark", () => {
  test("keeps shell grammar and literal argv under perfect gates", async () => {
    const benchmark = JSON.parse(
      await readFile(
        join(benchmarkRoot, "rust-axum-command-injection-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;
    expect(benchmark.schemaVersion).toBe("1.0");
    expect(
      Object.values(benchmark.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(benchmark.cases.map(({ id }) => id)).toEqual([...caseIds]);
    expect(benchmark.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-78", "CWE-88"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(
      benchmark.cases[0]?.expected[0]?.requiredValidationTextAnyOf,
    ).toHaveLength(4);
    expect(
      benchmark.cases[0]?.expected[0]?.requiredAttackPathTextAnyOf,
    ).toHaveLength(4);
    expect(benchmark.cases[0]?.expected[0]?.forbiddenText).toHaveLength(4);
    expect(benchmark.cases[1]?.expected).toEqual([]);
  });

  test("preserves exact extractor, format flow, shell boundary, and sink", async () => {
    const vulnerable = await fixtureRecords(caseIds[0]);
    const safe = await fixtureRecords(caseIds[1]);
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
          symbol: "std::process::Command;method=output;argument=2",
          cweIds: ["CWE-78", "CWE-88"],
        },
        candidateControls: [],
      },
    });
    expect(
      vulnerable[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual(["rust-local-assignment", "rust-format-macro"]);
    expect(safe).toEqual([]);
  });

  test("keeps paired topology aligned at the request and process boundaries", async () => {
    const vulnerable = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[0],
        "src",
        "handlers",
        "diagnostics.rs",
      ),
      "utf8",
    );
    const safe = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[1],
        "src",
        "handlers",
        "diagnostics.rs",
      ),
      "utf8",
    );
    for (const source of [vulnerable, safe]) {
      expect(source).toContain(
        "pub async fn diagnostics(Query(input): Query<DiagnosticQuery>)",
      );
      expect(source).toContain("use std::process::Command;");
      expect(source).toContain(".arg(");
      expect(source).toContain(".output()");
      expect(source).toContain("String::from_utf8_lossy(&output.stdout)");
    }
    expect(vulnerable).toContain('Command::new("sh")');
    expect(vulnerable).toContain('.arg("-c")');
    expect(safe).toContain('Command::new("printf")');
    expect(safe).toContain('.arg("%s")');
  });

  test("keeps harmless native witnesses and a dedicated hosted gate", async () => {
    const vulnerable = await readFile(
      join(benchmarkRoot, "fixtures", caseIds[0], "witness.rs"),
      "utf8",
    );
    const safe = await readFile(
      join(benchmarkRoot, "fixtures", caseIds[1], "witness.rs"),
      "utf8",
    );
    for (const witness of [vulnerable, safe]) {
      expect(witness).toContain("RUST_COMMAND_MARKER");
      expect(witness).toContain("shell_expanded_marker={}");
      expect(witness).not.toContain("std::fs");
      expect(witness).not.toContain("std::net");
    }
    expect(vulnerable).toContain('Command::new("sh")');
    expect(safe).toContain('Command::new("printf")');

    const workflow = await readFile(
      resolve(
        benchmarkRoot,
        "..",
        ".github",
        "workflows",
        "rust-fixture-ci.yml",
      ),
      "utf8",
    );
    expect(workflow).toContain("permissions:\n  contents: read");
    expect(workflow).toContain(
      "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
    );
    expect(workflow).toContain("persist-credentials: false");
    expect(workflow).toContain("rustfmt --edition 2021 --check");
    expect(workflow).toContain("rustc --edition 2021");
    expect(workflow).toContain(
      'test "$vulnerable" = "shell_expanded_marker=1"',
    );
    expect(workflow).toContain('test "$control" = "shell_expanded_marker=0"');
  });

  test("recognizes Axum request extractors and exact import aliases", () => {
    for (const extractor of ["Query", "Path", "Form", "Json"] as const) {
      const found = records(
        axum(
          '    Command::new("sh").arg("-c").arg(input.value).status();',
          `${extractor}(input): ${extractor}<Payload>`,
          extractor,
        ),
      );
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.source.symbol).toBe(
        `axum::${extractor}(input)`,
      );
    }
    const aliased = records(`use axum::extract::Query as RequestQuery;
use std::process::Command as ProcessCommand;
async fn handler(RequestQuery(input): RequestQuery<Payload>) {
    ProcessCommand::new("bash").arg("-c").arg(input.value).spawn();
}
`);
    expect(aliased).toHaveLength(1);
    expect(aliased[0]?.frameworkModel.source.symbol).toBe("axum::Query(input)");
    const tuple = records(`use axum::extract::Path;
use std::process::Command;
async fn handler<'a>(Path((tenant, command)): Path<(&'a str, String)>) {
    let _ = tenant;
    Command::new("sh").arg("-c").arg(command).status();
}
`);
    expect(tuple).toHaveLength(1);
    expect(tuple[0]?.frameworkModel.source.symbol).toBe("axum::Path(command)");
  });

  test("recognizes Actix Web extractors without accepting local lookalikes", () => {
    const actix = records(`use actix_web::web;
use std::process::Command;
async fn handler(input: web::Json<Payload>) {
    Command::new("sh").arg("-c").arg(&input.value).output();
}
`);
    expect(actix).toHaveLength(1);
    expect(actix[0]?.frameworkModel.source.symbol).toBe(
      "actix-web::Json(input)",
    );
    const direct = records(`use actix_web::web::Query;
use std::process::Command;
async fn handler(input: Query<Payload>) {
    Command::new("sh").arg("-c").arg(input.value).status();
}
`);
    expect(direct).toHaveLength(1);
    expect(
      records(`struct Query<T>(T);
struct Command;
impl Command { fn new<T>(_value: T) -> Self { Self } }
async fn handler(Query(input): Query<Payload>) {
    Command::new("sh").arg("-c").arg(input.value).status();
}
`),
    ).toEqual([]);
  });

  test("recognizes shell, cmd, PowerShell, and interpreter grammar positions", () => {
    const commands = [
      ['"/bin/sh"', '"-c"', "rust-process-shell-command"],
      ['"bash"', '"-c"', "rust-process-shell-command"],
      ['"cmd.exe"', '"/C"', "rust-process-shell-command"],
      ['"powershell.exe"', '"-Command"', "rust-process-shell-command"],
      ['"pwsh"', '"-c"', "rust-process-shell-command"],
      ['"python3"', '"-c"', "rust-process-interpreter-command"],
      ['"node"', '"--eval"', "rust-process-interpreter-command"],
    ] as const;
    for (const [program, flag, kind] of commands) {
      const found = records(
        axum(
          `    Command::new(${program}).arg(${flag}).arg(input.value).status();`,
        ),
      );
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.sink.kind).toBe(kind);
    }
  });

  test("tracks args arrays and a mutable builder through actual execution", () => {
    const array = records(
      axum('    Command::new("sh").args(["-c", &input.value]).output();'),
    );
    expect(array).toHaveLength(1);
    expect(array[0]?.frameworkModel.sink.symbol).toContain("argument=2");

    const builder = records(
      axum(`    let command_line = format!("printf {}", input.value);
    let mut process = Command::new("sh");
    process.arg("-c");
    process.arg(command_line);
    let _result = process.spawn();`),
    );
    expect(builder).toHaveLength(1);
    expect(builder[0]?.frameworkModel.sink).toMatchObject({
      kind: "rust-process-shell-command",
      symbol: "std::process::Command;method=spawn;argument=2",
    });
  });

  test("recognizes executable selection, raw command lines, and Windows batch consumers", () => {
    const selected = records(axum("    Command::new(input.program).status();"));
    expect(selected).toHaveLength(1);
    expect(selected[0]?.frameworkModel.sink.kind).toBe(
      "rust-process-executable-selection",
    );

    const raw = records(
      axum(
        '    Command::new("cmd.exe").raw_arg(input.value).status();',
        "Query(input): Query<Payload>",
        "Query",
        "use std::os::windows::process::CommandExt;\nuse std::process::Command;",
      ),
    );
    expect(raw).toHaveLength(1);
    expect(raw[0]?.frameworkModel.sink.kind).toBe(
      "rust-process-raw-command-line",
    );

    const batch = records(
      axum('    Command::new("trusted.cmd").arg(input.value).output();'),
    );
    expect(batch).toHaveLength(1);
    expect(batch[0]?.frameworkModel.sink.kind).toBe(
      "rust-process-shell-command",
    );
  });

  test("accepts full and module-qualified std identities", () => {
    expect(
      records(`use axum::extract::Path;
async fn handler(Path(input): Path<String>) {
    std::process::Command::new("sh").arg("-c").arg(input).output();
}
`),
    ).toHaveLength(1);
    expect(
      records(`use axum::extract::Path;
use std::process as process_api;
async fn handler(Path(input): Path<String>) {
    process_api::Command::new("sh").arg("-c").arg(input).status();
}
`),
    ).toHaveLength(1);
    expect(
      records(`use axum::extract::Path;
use std::{io, process::{Command as ProcessCommand, Stdio}};
async fn handler(Path(input): Path<String>) {
    ProcessCommand::new("sh").arg("-c").arg(input).status();
}
`),
    ).toHaveLength(1);
    expect(
      records(
        axum(`    let shell = String::from("sh");
    let code_flag = "-c";
    Command::new(shell).arg(code_flag).arg(input.value).status();`),
      ),
    ).toHaveLength(1);
  });

  test("rejects literal argv data, inert builders, numeric normalization, and reassignment", () => {
    const safeBodies = [
      '    Command::new("printf").arg("%s").arg(input.value).output();',
      "    let _process = Command::new(input.value);",
      `    let number = input.value.parse::<u32>().unwrap();
    let command_line = format!("printf {}", number);
    Command::new("sh").arg("-c").arg(command_line).status();`,
      `    let mut process = Command::new("sh");
    process.arg("-c").arg(input.value);
    process = Command::new("printf");
    process.arg(input.value).output();`,
    ];
    for (const body of safeBodies) expect(records(axum(body))).toEqual([]);
    expect(
      records(
        axum('    Command::new("cmd.exe").raw_arg(input.value).status();'),
      ),
    ).toEqual([]);
  });

  test("retains escape, allowlist, regex, and deadline candidates for validation", () => {
    const found = records(
      axum(`    let escaped = shell_escape::escape(input.value.into());
    let command_line = format!("printf {}", escaped);
    let _allowed = matches!(command_line.as_str(), "fixed");
    let _pattern = regex::Regex::new("^[a-z]+$");
    Command::new("sh").arg("-c").arg(command_line).status();`),
    );
    expect(found).toHaveLength(1);
    expect(
      found[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("rust-shell-escape-candidate");
    expect(
      found[0]?.frameworkModel.candidateControls.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "shell-argument-escape-candidate",
        "process-input-literal-selection",
        "process-input-regex",
      ]),
    );
  });

  test("is CRLF-stable, bounded, and rejects malformed or non-production input", () => {
    const source = axum(
      '    Command::new("sh").arg("-c").arg(input.value).output();',
    );
    expect(records(source.replace(/\n/gu, "\r\n"))[0]).toMatchObject({
      line: 5,
      frameworkModel: { source: { line: 4 }, sink: { line: 5 } },
    });
    expect(records(source, "tests/handler.rs")).toEqual([]);
    expect(records(source, "src/handler_test.rs")).toEqual([]);
    expect(records(source.replace("}\n", ""))).toEqual([]);
    expect(records(`${source}\n/* unterminated`)).toEqual([]);
    const oversized = `${source}\n${"let bounded_name = 1;\n".repeat(40_000)}`;
    expect(records(oversized)).toEqual([]);
  });

  test("feeds residual correction with Rust-specific proof obligations", async () => {
    const inventory = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", caseIds[0]),
    );
    expect(inventory).toContain('"id":"rust-web-command-injection"');
    expect(inventory).toContain('"kind":"rust-http-extractor"');
    expect(inventory).toContain('"kind":"rust-process-shell-command"');
    const prompt = scanQualityGatePrompt(inventory);
    expect(prompt).toContain("For rust-web-command-injection rows");
    expect(prompt).toContain(
      "Rust passes ordinary arg and args values literally",
    );
    expect(prompt).toContain("Windows .bat/.cmd consumers");
    expect(prompt).toContain(
      "explicitly restate the concrete extractor binding and request field or expression",
    );
    expect(prompt).toContain(
      "explicitly carry that same named query, path, form, or JSON request value",
    );
    expect(prompt).toContain(
      "command stdout or stderr is returned in the HTTP response",
    );
    expect(prompt).toContain("bounded harmless marker");
  });

  test("forces incomplete Rust evidence fields through host-audited correction", async () => {
    const repository = join(benchmarkRoot, "fixtures", caseIds[0]);
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-rust-quality-"),
    );
    try {
      const finding = {
        findingId: "occ_rust_quality",
        taxonomy: { cwe: ["CWE-78", "CWE-88"] },
        locations: [
          {
            path: handlerPath,
            startLine: 6,
            endLine: 8,
            role: "source",
          },
          {
            path: handlerPath,
            startLine: 12,
            endLine: 15,
            role: "sink",
          },
        ],
        codeEvidence: [
          {
            id: "rust-source",
            path: handlerPath,
            startLine: 5,
            endLine: 8,
            role: "source",
            code: [
              "#[derive(Deserialize)]",
              "pub struct DiagnosticQuery {",
              "    target: String,",
              "}",
            ].join("\n"),
            explanation:
              "The endpoint binds an externally controlled diagnostic field.",
          },
          {
            id: "rust-sink",
            path: handlerPath,
            startLine: 12,
            endLine: 15,
            role: "sink",
            code: [
              '    let output = Command::new("sh")',
              '        .arg("-c")',
              "        .arg(command_line)",
              "        .output()",
            ].join("\n"),
            explanation:
              "The externally influenced value reaches an executed process boundary.",
          },
        ],
        validation: {
          method: "static_source_trace",
          summary:
            "Repository source establishes an externally controlled value reaching execution.",
          exploitWitness:
            "A bounded inert marker demonstrates the dangerous interpretation boundary.",
          negativeControl:
            "A separate data-only invocation provides the non-executing comparison.",
          evidence: ["rust-source", "rust-sink"],
          counterEvidence:
            "No dominating source-backed control was established for this path.",
          remainingUncertainty:
            "Deployment routing and operating-system process privileges remain unknown.",
        },
        attackPath: {
          summary:
            "An external caller controls a value that reaches a dangerous execution boundary.",
          dataflow: {
            source: "The remote endpoint supplies an untrusted field.",
            sink: "The field reaches the recorded execution boundary.",
            outcome:
              "The child execution can affect service-process integrity.",
          },
          reachability: {
            attacker: "An unauthenticated remote network caller.",
            entrypoint: "The diagnostics HTTP handler.",
            outcome: "A child process can execute in the service context.",
          },
          brokenControls: ["No exact command and data separation"],
          evidenceRefs: ["rust-source", "rust-sink"],
        },
      };
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
      );
      const residualRiskInventory =
        await buildResidualRiskInventory(repository);

      const incomplete = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        residualRiskInventory,
      );
      const rows = incomplete.split("\n").map((line) => JSON.parse(line));
      expect(rows[1]).toMatchObject({
        findingId: "occ_rust_quality",
        frameworkModelId: "rust-web-command-injection",
        reasons: [
          "missing_model_specific_validation_evidence",
          "missing_model_specific_attack_path_evidence",
        ],
      });
      expect(rows[1]?.missingValidationTextAnyOf).toContainEqual([
        "format!",
        "command_line",
        "formatted",
      ]);
      expect(rows[1]?.missingAttackPathTextAnyOf).toContainEqual([
        "stdout",
        "response",
        "returned",
      ]);

      finding.validation.summary = [
        "The Axum Query request query binds input.target.",
        "format! assigns the formatted value to command_line.",
        "std::process::Command and Command::new execute it through sh -c shell grammar.",
      ].join(" ");
      finding.attackPath.summary = [
        "The input.target request value is the query value.",
        "format! places it in a command string with shell grammar.",
        "Command starts the sh process.",
        "The command stdout is returned in the HTTP response.",
      ].join(" ");
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
      );

      expect(
        await buildFindingQualityGapInventory(
          scanDirectory,
          repository,
          residualRiskInventory,
        ),
      ).toBe("");
    } finally {
      await rm(scanDirectory, { recursive: true, force: true });
    }
  });
});
