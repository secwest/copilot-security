import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import {
  rubyCommandInjectionRecords,
  type RubyCommandInjectionRecord,
} from "../src/ruby-command-risk.js";
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
      requiredValidationTextAnyOf?: string[][];
      requiredAttackPathTextAnyOf?: string[][];
      forbiddenText?: string[];
    }>;
  }>;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const caseIds = [
  "ruby-rails-open3-shell-injection",
  "ruby-rails-open3-argv-command",
] as const;
const controllerPath = "app/controllers/checks_controller.rb";

function records(
  source: string,
  path = controllerPath,
): RubyCommandInjectionRecord[] {
  return rubyCommandInjectionRecords(path, source.split(/\r?\n/u), source);
}

function controller(body: string, imports = ""): string {
  return `${imports}class ChecksController < ActionController::Base
  def show
${body}
  end
end
`;
}

async function fixtureRecords(
  id: (typeof caseIds)[number],
): Promise<RubyCommandInjectionRecord[]> {
  const inventory = await buildResidualRiskInventory(
    join(benchmarkRoot, "fixtures", id),
  );
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as RubyCommandInjectionRecord)
    .filter(
      (record) => record.frameworkModel?.id === "ruby-rails-command-injection",
    );
}

describe("Ruby on Rails command-injection model benchmark", () => {
  test("keeps shell grammar and argv data under perfect gates", async () => {
    const benchmark = JSON.parse(
      await readFile(
        join(benchmarkRoot, "ruby-rails-command-injection-manifest.json"),
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

  test("preserves exact Rails source, assignment, interpolation, and Open3 sink", async () => {
    const vulnerable = await fixtureRecords(caseIds[0]);
    const safe = await fixtureRecords(caseIds[1]);
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "src/app/controllers/diagnostics_controller.rb",
      line: 6,
      categories: ["ruby-rails-command-injection"],
      frameworkModel: {
        schemaVersion: "1.2",
        id: "ruby-rails-command-injection",
        language: "ruby",
        scope: "same-file",
        source: {
          kind: "rails-request-parameter",
          path: "src/app/controllers/diagnostics_controller.rb",
          line: 5,
          symbol: "params[target]",
        },
        sink: {
          kind: "ruby-shell-command-string",
          path: "src/app/controllers/diagnostics_controller.rb",
          line: 6,
          symbol: "receiver=Open3;method=capture2e",
          cweIds: ["CWE-78", "CWE-88"],
        },
        candidateControls: [],
      },
    });
    expect(
      vulnerable[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual(["ruby-local-assignment", "ruby-string-interpolation"]);
    const vulnerableSource = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[0],
        "src",
        "app",
        "controllers",
        "diagnostics_controller.rb",
      ),
      "utf8",
    );
    expect(
      records(
        vulnerableSource.replace(/\r?\n/gu, "\r\n"),
        "src/app/controllers/diagnostics_controller.rb",
      )[0],
    ).toMatchObject({
      line: 6,
      frameworkModel: { source: { line: 5 }, sink: { line: 6 } },
    });
    expect(safe).toEqual([]);
  });

  test("keeps pair topology identical apart from the command boundary", async () => {
    const vulnerable = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[0],
        "src",
        "app",
        "controllers",
        "diagnostics_controller.rb",
      ),
      "utf8",
    );
    const safe = await readFile(
      join(
        benchmarkRoot,
        "fixtures",
        caseIds[1],
        "src",
        "app",
        "controllers",
        "diagnostics_controller.rb",
      ),
      "utf8",
    );
    expect(
      vulnerable.replace(
        'Open3.capture2e("printf diagnostic; #{target}")',
        'Open3.capture2e("printf", "%s", target)',
      ),
    ).toBe(safe);
  });

  test("keeps harmless executable witnesses and a dedicated hosted gate", async () => {
    const vulnerable = await readFile(
      join(benchmarkRoot, "fixtures", caseIds[0], "witness.rb"),
      "utf8",
    );
    const safe = await readFile(
      join(benchmarkRoot, "fixtures", caseIds[1], "witness.rb"),
      "utf8",
    );
    for (const witness of [vulnerable, safe]) {
      expect(witness).toContain("ruby-shell-expanded");
      expect(witness).toContain(`; printf \"$RUBY_COMMAND_MARKER\"`);
      expect(witness).not.toContain("File.");
      expect(witness).not.toContain("Net::");
    }
    expect(vulnerable).toContain('"printf diagnostic#{payload}"');
    expect(safe).toContain('"printf",\n  "%s",\n  payload');

    const workflow = await readFile(
      resolve(
        benchmarkRoot,
        "..",
        ".github",
        "workflows",
        "ruby-fixture-ci.yml",
      ),
      "utf8",
    );
    expect(workflow).toContain("permissions:\n  contents: read");
    expect(workflow).toContain(
      "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
    );
    expect(workflow).toContain("persist-credentials: false");
    expect(workflow).toContain(
      "apt-get install --no-install-recommends -y ruby",
    );
    expect(workflow).toContain(
      'test "$vulnerable" = "shell_expanded_marker=1"',
    );
    expect(workflow).toContain('test "$control" = "shell_expanded_marker=0"');
  });

  test("recognizes Kernel, Process, IO, and required Open3 call forms", () => {
    const cases = [
      ['    system("printf #{params[:target]}")', "Kernel", "system"],
      ['    Kernel.exec "printf #{params[:target]}"', "Kernel", "exec"],
      ['    Process.spawn("printf #{params[:target]}")', "Process", "spawn"],
      ['    IO.popen "printf #{params[:target]}"', "IO", "popen"],
      ['    Open3.capture3 "printf #{params[:target]}"', "Open3", "capture3"],
    ] as const;
    for (const [body, receiver, method] of cases) {
      const found = records(
        controller(body, receiver === "Open3" ? 'require "open3"\n' : ""),
      );
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.sink.symbol).toBe(
        `receiver=${receiver};method=${method}`,
      );
    }
    expect(
      records(controller('    Open3.capture3("printf #{params[:target]}")')),
    ).toEqual([]);
  });

  test("recognizes explicit POSIX, CMD, and PowerShell command strings", () => {
    const commands = [
      ['"/bin/sh", "-c"', "system"],
      ['"bash", "-c"', "exec"],
      ['"cmd.exe", "/c"', "spawn"],
      ['"powershell.exe", "-Command"', "system"],
      ['"pwsh", "-c"', "system"],
    ] as const;
    for (const [prefix, method] of commands) {
      const found = records(
        controller(`    ${method}(${prefix}, \"printf #{params[:target]}\")`),
      );
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.sink.kind).toBe(
        "ruby-explicit-shell-command",
      );
    }
  });

  test("distinguishes backticks and percent-x command expressions", () => {
    const backtick = records(
      controller("    output = `printf #{params[:target]}`"),
    );
    expect(backtick).toHaveLength(1);
    expect(backtick[0]?.frameworkModel.sink).toMatchObject({
      kind: "ruby-backtick-shell-command",
      symbol: "receiver=Kernel;method=`",
    });

    const percentX = records(
      controller("    output = %x(printf #{params[:target]})"),
    );
    expect(percentX).toHaveLength(1);
    expect(percentX[0]?.frameworkModel.sink.symbol).toBe(
      "receiver=Kernel;method=%x",
    );
    expect(
      records(controller("    output = %q(printf #{params[:target]})")),
    ).toEqual([]);
  });

  test("tracks Rails parameter APIs, request maps, and local propagation", () => {
    const sources = [
      ["params.require(:target)", "params.require(target)"],
      ['params.fetch("target")', "params.fetch(target)"],
      ["params.dig(:target)", "params.dig(target)"],
      ["request.query_parameters[:target]", "request.query_parameters[target]"],
      [
        "request.request_parameters[:target]",
        "request.request_parameters[target]",
      ],
      ["request.path_parameters[:target]", "request.path_parameters[target]"],
    ] as const;
    for (const [source, symbol] of sources) {
      const found = records(
        controller(
          `    value = ${source}\n    command = \"printf #{value}\"\n    system(command)`,
        ),
      );
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.source.symbol).toBe(symbol);
      expect(
        found[0]?.frameworkModel.propagators.map(({ kind }) => kind),
      ).toContain("ruby-string-interpolation");
    }

    const appended = records(
      controller(
        '    command = "printf "\n    command << params[:target]\n    system(command)',
      ),
    );
    expect(appended).toHaveLength(1);
    expect(
      appended[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("ruby-string-concatenation");
  });

  test("rejects fixed argv, numeric conversion, reassignment, and scope confusion", () => {
    const controls = [
      controller(
        '    value = params[:target]\n    system("printf", "%s", value)',
      ),
      controller(
        '    value = Integer(params[:target])\n    system("printf #{value}")',
      ),
      controller(
        '    value = params[:target].to_i\n    system("printf #{value}")',
      ),
      controller(
        '    value = params[:target]\n    value = "fixed"\n    system("printf #{value}")',
      ),
      controller('    system("printf fixed")'),
      `class PlainService\n  def show\n    system("printf #{params[:target]}")\n  end\nend\n`,
      controller(
        '    system("printf #{params[:target]}")\n\n  def system(command)\n    command\n  end',
      ),
    ];
    for (const control of controls) expect(records(control)).toEqual([]);
    expect(
      records(controls[0]!, "test/controllers/checks_controller.rb"),
    ).toEqual([]);
    expect(
      records(controls[0]!, "app/controllers/checks_controller.txt"),
    ).toEqual([]);
  });

  test("retains Shellwords escaping as shell-specific validation evidence", () => {
    const found = records(
      controller(
        '    escaped = Shellwords.escape(params[:target])\n    system("printf #{escaped}")',
        'require "shellwords"\n',
      ),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.candidateControls).toEqual([
      {
        kind: "bourne-shell-argument-escaping",
        path: controllerPath,
        line: 4,
      },
    ]);
    expect(
      found[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("ruby-shell-escaping");
  });

  test("fails closed on malformed or excessive input and bounds output", () => {
    expect(records(controller('    system("unterminated)'))).toEqual([]);
    expect(
      records("class ChecksController < ActionController::Base\n  def show\n"),
    ).toEqual([]);
    expect(
      records(
        controller(
          `    value = ${"(".repeat(129)}params[:target]${")".repeat(129)}\n    system(value)`,
        ),
      ),
    ).toEqual([]);
    expect(
      records(
        `class ChecksController < ActionController::Base\n${"value = 0\n".repeat(40_000)}end\n`,
      ),
    ).toEqual([]);

    const calls = Array.from(
      { length: 70 },
      (_, index) => `    system("printf #{params[:target${index}]} ")`,
    ).join("\n");
    const capped = records(controller(calls));
    expect(capped).toHaveLength(64);
    expect(new Set(capped.map(({ line }) => line)).size).toBe(64);

    const long = records(
      controller(`    system("${"a".repeat(5_000)}#{params[:target]}")`),
    );
    expect(long).toHaveLength(1);
    expect(long[0]?.excerpt).toContain("…[truncated]");
    expect(long[0]?.excerpt.length).toBeLessThan(2_300);
  });

  test("gives correction turns Ruby-specific validation boundaries", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"ruby-rails-command-injection"}}',
    );
    expect(prompt).toContain("For ruby-rails-command-injection rows");
    expect(prompt).toContain("Open3");
    expect(prompt).toContain("fixed executable");
    expect(prompt).toContain("separate argument");
    expect(prompt).toContain("Shellwords.escape");
    expect(prompt).toContain("not public reachability");
    expect(prompt).toContain("CWE-78 and CWE-88");
  });
});
