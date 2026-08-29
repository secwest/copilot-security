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
  nodeMcpToolRiskRecords,
  type NodeMcpToolRiskRecord,
} from "../src/node-mcp-tool-risk.js";

const sourcePath = "src/server.ts";
const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

function v2(body: string, input = "command: z.string()") {
  return `import { McpServer } from "@modelcontextprotocol/server";
import { exec, execFile, spawn } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import * as https from "node:https";
import axios from "axios";
import { z } from "zod";

const server = new McpServer({ name: "tools", version: "1.0.0" });
server.registerTool(
  "operate",
  { inputSchema: z.object({ ${input} }) },
  async ({ command, url, pattern, text }) => {
${body}
    return { content: [] };
  },
);
`;
}

function sqliteV2(
  body: string,
  sqliteImport = 'import { DatabaseSync } from "node:sqlite";',
  database = 'const database = new DatabaseSync(":memory:");',
) {
  return `${sqliteImport}\n${database}\n${v2(body)}`;
}

function records(source: string, path = sourcePath): NodeMcpToolRiskRecord[] {
  return nodeMcpToolRiskRecords(path, source.split(/\r?\n/u), source);
}

describe("Node MCP tool-input security model", () => {
  test("keeps all executable exploit/control pairs under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-mcp-tool-security-manifest.json"),
        "utf8",
      ),
    ) as {
      schemaVersion: string;
      thresholds: Record<string, number>;
      cases: Array<{
        id: string;
        expected: Array<{
          path: string;
          line: number;
          lineTolerance?: number;
        }>;
      }>;
    };
    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-mcp-v2-command-injection",
      "node-mcp-v2-command-argv",
      "node-mcp-v2-argument-injection",
      "node-mcp-v2-argument-data",
      "node-mcp-v2-code-injection",
      "node-mcp-v2-arithmetic-parser",
      "node-mcp-v2-function-constructor",
      "node-mcp-v2-function-fixed-grammar",
      "node-mcp-v2-worker-eval-injection",
      "node-mcp-v2-worker-data-boundary",
      "node-mcp-v2-sqlite-sql-injection",
      "node-mcp-v2-sqlite-bound-parameters",
      "node-mcp-v2-sqlite-prepared-sql-injection",
      "node-mcp-v2-sqlite-prepared-bound-parameters",
      "node-mcp-v2-regex-injection",
      "node-mcp-v2-fixed-patterns",
      "node-mcp-v2-ssrf",
      "node-mcp-v2-fixed-destination",
      "node-mcp-v2-path-traversal",
      "node-mcp-v2-fixed-file",
      "node-mcp-v2-runtime-alias-argument-injection",
      "node-mcp-v2-runtime-alias-argument-data",
      "node-mcp-v2-imported-runtime-argument-injection",
      "node-mcp-v2-imported-runtime-argument-data",
      "node-mcp-v2-fork-exec-argv-injection",
      "node-mcp-v2-fork-argument-data",
    ]);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(manifest.cases[2]?.expected).toHaveLength(1);
    expect(manifest.cases[3]?.expected).toEqual([]);
    expect(manifest.cases[4]?.expected).toHaveLength(1);
    expect(manifest.cases[5]?.expected).toEqual([]);
    expect(manifest.cases[6]?.expected).toHaveLength(1);
    expect(manifest.cases[6]?.expected[0]).toMatchObject({
      path: "src/server.mjs",
      line: 8,
      lineTolerance: 1,
    });
    expect(manifest.cases[7]?.expected).toEqual([]);
    expect(manifest.cases[8]?.expected).toHaveLength(1);
    expect(manifest.cases[8]?.expected[0]).toMatchObject({
      cwe: ["CWE-94", "CWE-95"],
      acceptableSeverities: ["critical", "high"],
      path: "src/server.mjs",
      line: 12,
      lineTolerance: 1,
    });
    expect(manifest.cases[9]?.expected).toEqual([]);
    expect(manifest.cases[10]?.expected).toHaveLength(1);
    expect(manifest.cases[10]?.expected[0]).toMatchObject({
      cwe: ["CWE-89"],
      acceptableSeverities: ["critical", "high"],
      path: "src/server.mjs",
      line: 19,
      lineTolerance: 1,
    });
    expect(manifest.cases[11]?.expected).toEqual([]);
    expect(manifest.cases[12]?.expected).toHaveLength(1);
    expect(manifest.cases[12]?.expected[0]).toMatchObject({
      cwe: ["CWE-89"],
      acceptableSeverities: ["critical", "high"],
      path: "src/server.mjs",
      line: 20,
      lineTolerance: 1,
    });
    expect(manifest.cases[13]?.expected).toEqual([]);
    expect(manifest.cases[14]?.expected).toHaveLength(1);
    expect(manifest.cases[14]?.expected[0]).toMatchObject({
      cwe: ["CWE-400", "CWE-730", "CWE-1333"],
      acceptableSeverities: ["critical", "high", "medium"],
      path: "src/server.mjs",
      line: 8,
    });
    expect(manifest.cases[15]?.expected).toEqual([]);
    expect(manifest.cases[16]?.expected).toHaveLength(1);
    expect(manifest.cases[17]?.expected).toEqual([]);
    expect(manifest.cases[18]?.expected).toHaveLength(1);
    expect(manifest.cases[19]?.expected).toEqual([]);
    expect(manifest.cases[20]?.expected).toHaveLength(1);
    expect(manifest.cases[20]?.expected[0]).toMatchObject({
      cwe: ["CWE-88", "CWE-94"],
      acceptableSeverities: ["critical", "high"],
      path: "src/server.mjs",
      line: 11,
      lineTolerance: 1,
    });
    expect(manifest.cases[21]?.expected).toEqual([]);
    expect(manifest.cases[22]?.expected).toHaveLength(1);
    expect(manifest.cases[22]?.expected[0]).toMatchObject({
      cwe: ["CWE-88", "CWE-94"],
      acceptableSeverities: ["critical", "high"],
      path: "src/server.mjs",
      line: 12,
      lineTolerance: 1,
    });
    expect(manifest.cases[23]?.expected).toEqual([]);
    expect(manifest.cases[24]?.expected).toHaveLength(1);
    expect(manifest.cases[24]?.expected[0]).toMatchObject({
      cwe: ["CWE-88", "CWE-94"],
      acceptableSeverities: ["critical", "high"],
      path: "src/server.mjs",
      line: 11,
      lineTolerance: 1,
    });
    expect(manifest.cases[25]?.expected).toEqual([]);

    const canonical = JSON.parse(
      await readFile(join(benchmarkRoot, "manifest.json"), "utf8"),
    ) as {
      cases: Array<{
        id: string;
        expected: Array<{
          locations?: Array<{
            path: string;
            startLine: number;
            endLine: number;
            lineTolerance?: number;
          }>;
        }>;
      }>;
    };
    for (const index of [8, 10, 12, 20, 22, 24]) {
      const specializedCase = manifest.cases[index]!;
      const canonicalCase = canonical.cases.find(
        ({ id }) => id === specializedCase.id,
      );
      expect(canonicalCase?.expected[0]?.locations?.[0]).toEqual({
        path: specializedCase.expected[0]!.path,
        startLine: specializedCase.expected[0]!.line,
        endLine: specializedCase.expected[0]!.line,
        lineTolerance: specializedCase.expected[0]!.lineTolerance,
      });
    }

    for (const index of [6, 7, 8, 9, 10, 11, 12, 13, 20, 21, 22, 23, 24, 25]) {
      const fixture = join(
        benchmarkRoot,
        "fixtures",
        manifest.cases[index]!.id,
      );
      const packageJson = JSON.parse(
        await readFile(join(fixture, "package.json"), "utf8"),
      ) as { scripts?: { start?: string } };
      expect(packageJson.scripts?.start).toBe("node src/stdio.mjs");
      expect(await readFile(join(fixture, "src", "stdio.mjs"), "utf8")).toBe(
        'import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";\n' +
          'import { server } from "./server.mjs";\n\n' +
          "await server.connect(new StdioServerTransport());\n",
      );
    }

    for (const [index, modelId] of [
      [0, "node-mcp-tool-command-injection"],
      [2, "node-mcp-tool-argument-injection"],
      [4, "node-mcp-tool-code-injection"],
      [6, "node-mcp-tool-code-injection"],
      [8, "node-mcp-tool-code-injection"],
      [10, "node-mcp-tool-sql-injection"],
      [12, "node-mcp-tool-sql-injection"],
      [14, "node-mcp-tool-regex-injection"],
      [16, "node-mcp-tool-ssrf"],
      [18, "node-mcp-tool-path-traversal"],
      [20, "node-mcp-tool-argument-injection"],
      [22, "node-mcp-tool-argument-injection"],
      [24, "node-mcp-tool-argument-injection"],
    ] as const) {
      const vulnerable = await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", manifest.cases[index]!.id),
      );
      expect(vulnerable).toContain(`\"id\":\"${modelId}\"`);
      expect(vulnerable).toContain("mcp-tool-helper-call");
      if (index === 6) {
        expect(vulnerable).toContain("mcp-tool-code-construction");
        expect(vulnerable).toContain("Function:code[0]");
      }
      if (index === 8) {
        expect(vulnerable).toContain("mcp-tool-worker-code-evaluation");
        expect(vulnerable).toContain("mcp-tool-worker-startup");
        expect(vulnerable).toContain("Worker:eval:true");
        const workerRecord = vulnerable
          .split(/\r?\n/u)
          .filter(Boolean)
          .map((line) => JSON.parse(line) as NodeMcpToolRiskRecord)
          .find(
            (record) =>
              record.frameworkModel.sink.kind ===
              "mcp-tool-worker-code-evaluation",
          );
        expect(workerRecord?.frameworkModel.sink).toMatchObject({
          path: manifest.cases[index]!.expected[0]!.path,
          line: manifest.cases[index]!.expected[0]!.line,
        });
      }
      if (index === 10 || index === 12) {
        expect(vulnerable).toContain("mcp-tool-sql-query");
        expect(vulnerable).toContain("mcp-tool-sqlite-database");
        if (index === 12) {
          expect(vulnerable).toContain("mcp-tool-sql-preparation");
          expect(vulnerable).toContain("statement.get:prepared-sql[0]");
        }
        const sqlRecord = vulnerable
          .split(/\r?\n/u)
          .filter(Boolean)
          .map((line) => JSON.parse(line) as NodeMcpToolRiskRecord)
          .find(
            (record) =>
              record.frameworkModel.sink.kind === "mcp-tool-sql-query",
          );
        expect(sqlRecord?.frameworkModel.sink).toMatchObject({
          path: manifest.cases[index]!.expected[0]!.path,
          line: manifest.cases[index]!.expected[0]!.line,
        });
      }
      if (index === 22) {
        expect(vulnerable).toContain("mcp-tool-node-process-binding");
        expect(vulnerable).toContain("nodeProcess<-node:process");
        expect(vulnerable).toContain("runtime=nodeProcess.execPath");
      }
      if (index === 24) {
        expect(vulnerable).toContain("mcp-tool-fork-exec-argv");
        expect(vulnerable).toContain("fork:options.execArgv[0]");
        expect(vulnerable).toContain("fork:options.execArgv");
      }
      const control = await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", manifest.cases[index + 1]!.id),
      );
      expect(control).not.toContain("node-mcp-tool-");
    }
  });

  test("detects v2 MCP tool input reaching a shell command", () => {
    const found = records(
      v2("    const script = `printf %s ${command}`;\n    await exec(script);"),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.id).toBe("node-mcp-tool-command-injection");
    expect(found[0]?.frameworkModel.source.kind).toBe("mcp-tool-input");
    expect(found[0]?.frameworkModel.sink.kind).toBe("mcp-tool-shell-command");
    expect(found[0]?.frameworkModel.sink.symbol).toBe("exec");
    expect(found[0]?.frameworkModel.sink.cweIds).toEqual(["CWE-78", "CWE-88"]);
    expect(
      found[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual(["mcp-tool-registration", "mcp-tool-local-assignment"]);
  });

  test("detects Node interpreter-option injection before end-of-options", () => {
    const found = records(
      v2(
        '    return execFile(process.execPath, ["-e", "process.stdout.write(process.argv[1])", command]);',
      ),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.id).toBe(
      "node-mcp-tool-argument-injection",
    );
    expect(found[0]?.frameworkModel.sink.kind).toBe(
      "mcp-tool-interpreter-option",
    );
    expect(found[0]?.frameworkModel.sink.symbol).toBe("execFile:argv[2]");
    expect(found[0]?.frameworkModel.sink.cweIds).toEqual(["CWE-88", "CWE-94"]);
    expect(found[0]?.categories).toContain(
      "broken-control:mcp-tool-interpreter-end-of-options-missing",
    );
  });

  test("distinguishes fork execArgv injection from ordinary child arguments", () => {
    const imported = (body: string) =>
      v2(body).replace(
        'import { exec, execFile, spawn } from "node:child_process";',
        'import { exec, execFile, fork, spawn } from "node:child_process";',
      );
    const vulnerable = records(
      imported(
        '    return fork(new URL("./child.mjs", import.meta.url), [], { execArgv: [command], silent: true });',
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel.id).toBe(
      "node-mcp-tool-argument-injection",
    );
    expect(vulnerable[0]?.frameworkModel.sink.kind).toBe(
      "mcp-tool-fork-exec-argv",
    );
    expect(vulnerable[0]?.frameworkModel.sink.symbol).toBe(
      "fork:options.execArgv[0]",
    );
    expect(vulnerable[0]?.frameworkModel.sink.cweIds).toEqual([
      "CWE-88",
      "CWE-94",
    ]);

    expect(
      records(
        imported(
          '    return fork(new URL("./child.mjs", import.meta.url), [command], { execArgv: [], silent: true });',
        ),
      ),
    ).toEqual([]);
  });

  test("supports exact fork overloads and fails closed on ambiguous execArgv", () => {
    const direct = (body: string) =>
      v2(body).replace(
        'import { exec, execFile, spawn } from "node:child_process";',
        'import { fork } from "node:child_process";',
      );
    const positives = [
      direct(
        '    return fork(new URL("./child.mjs", import.meta.url), { execArgv: [command] });',
      ),
      direct(
        '    const option = command;\n    return fork(new URL("./child.mjs", import.meta.url), [], { execArgv: ["--", option] });',
      ),
      v2(
        '    return cp.fork(new URL("./child.mjs", import.meta.url), [], { "execArgv": [command] });',
      ).replace(
        'import { exec, execFile, spawn } from "node:child_process";',
        'import * as cp from "node:child_process";',
      ),
      v2(
        '    return cp.fork(new URL("./child.mjs", import.meta.url), { execArgv: [command] });',
      ).replace(
        'import { exec, execFile, spawn } from "node:child_process";',
        'const cp = require("node:child_process");',
      ),
    ];
    for (const source of positives) {
      const found = records(source);
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.sink.kind).toBe(
        "mcp-tool-fork-exec-argv",
      );
      expect(found[0]?.frameworkModel.propagators).toContainEqual(
        expect.objectContaining({
          kind: "mcp-tool-fork-exec-argv",
          symbol: expect.stringContaining("options.execArgv"),
        }),
      );
    }

    const rejected = [
      direct(
        '    return fork(new URL("./child.mjs", import.meta.url), [command], { execArgv: [] });',
      ),
      direct(
        '    return fork(new URL("./child.mjs", import.meta.url), [], { execArgv: ["--no-warnings"] });',
      ),
      direct(
        '    const options = { execArgv: [command] };\n    return fork(new URL("./child.mjs", import.meta.url), [], options);',
      ),
      direct(
        '    return fork(new URL("./child.mjs", import.meta.url), [], { ...options, execArgv: [command] });',
      ),
      direct(
        '    return fork(new URL("./child.mjs", import.meta.url), [], { execArgv: [command], /* later override */ ...options });',
      ),
      direct(
        '    return fork(new URL("./child.mjs", import.meta.url), [], { ["execArgv"]: [command] });',
      ),
      direct(
        '    return fork(new URL("./child.mjs", import.meta.url), [], { execArgv: [command], /* ambiguous */ [property]: fixed });',
      ),
      direct(
        '    return fork(new URL("./child.mjs", import.meta.url), [], { execArgv: [], execArgv: [command] });',
      ),
      direct(
        '    return fork(new URL("./child.mjs", import.meta.url), [], { execArgv: command });',
      ),
      direct(
        '    fork = safeFork;\n    return fork(new URL("./child.mjs", import.meta.url), [], { execArgv: [command] });',
      ),
      direct(
        '    const fork = safeFork;\n    return fork(new URL("./child.mjs", import.meta.url), [], { execArgv: [command] });',
      ),
      v2(
        '    cp.fork = safeFork;\n    return cp.fork(new URL("./child.mjs", import.meta.url), [], { execArgv: [command] });',
      ).replace(
        'import { exec, execFile, spawn } from "node:child_process";',
        'import * as cp from "node:child_process";',
      ),
      v2(
        '    return fork(new URL("./child.mjs", import.meta.url), [], { execArgv: [command] });',
      ).replace(
        'import { exec, execFile, spawn } from "node:child_process";',
        'import { fork } from "./child_process.js";',
      ),
    ];
    for (const source of rejected) expect(records(source)).toEqual([]);
  });

  test("preserves Node interpreter-option injection through a stable runtime alias", () => {
    const found = records(
      v2(
        '    const runtime = process.execPath;\n    return execFile(runtime, ["-e", "process.stdout.write(process.argv[1])", command]);',
      ),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.id).toBe(
      "node-mcp-tool-argument-injection",
    );
    expect(found[0]?.frameworkModel.sink.symbol).toBe("execFile:argv[2]");
    expect(found[0]?.frameworkModel.propagators).toContainEqual(
      expect.objectContaining({
        kind: "mcp-tool-node-runtime",
        symbol: "runtime=process.execPath",
      }),
    );
  });

  test("preserves Node interpreter-option injection through the official process module", () => {
    const source = v2(
      '    const runtime = nodeProcess.execPath;\n    return execFile(runtime, ["-e", "process.stdout.write(process.argv[1])", command]);',
    ).replace(
      'import { exec, execFile, spawn } from "node:child_process";',
      'import { exec, execFile, spawn } from "node:child_process";\nimport nodeProcess from "node:process";',
    );
    const found = records(source);
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.id).toBe(
      "node-mcp-tool-argument-injection",
    );
    expect(found[0]?.frameworkModel.propagators).toContainEqual(
      expect.objectContaining({
        kind: "mcp-tool-node-process-binding",
        symbol: "nodeProcess<-node:process",
      }),
    );
    expect(found[0]?.frameworkModel.propagators).toContainEqual(
      expect.objectContaining({
        kind: "mcp-tool-node-runtime",
        symbol: "runtime=nodeProcess.execPath",
      }),
    );
  });

  test("supports exact official node:process ESM, CommonJS, and TypeScript bindings", () => {
    const args = '["-e", "process.stdout.write(process.argv[1])", command]';
    const cases = [
      {
        declaration: 'import process from "node:process";',
        body: `    return execFile(process.execPath, ${args});`,
        binding: "process<-node:process",
      },
      {
        declaration: 'import * as nodeProcess from "node:process";',
        body: `    return execFile(nodeProcess.execPath, ${args});`,
        binding: "nodeProcess<-node:process",
      },
      {
        declaration:
          'import { execPath as importedRuntime } from "node:process";',
        body: `    return execFile(importedRuntime, ${args});`,
        binding: "importedRuntime<-node:process.execPath",
      },
      {
        declaration:
          'import nodeProcess, { execPath as importedRuntime } from "node:process";',
        body: `    return execFile(importedRuntime, ${args});`,
        binding: "importedRuntime<-node:process.execPath",
      },
      {
        declaration:
          'import nodeProcess, * as processNamespace from "node:process";',
        body: `    return execFile(processNamespace.execPath, ${args});`,
        binding: "processNamespace<-node:process",
      },
      {
        declaration: 'const nodeProcess = require("node:process");',
        body: `    const runtime = nodeProcess.execPath;\n    return execFile(runtime, ${args});`,
        binding: "nodeProcess<-node:process",
      },
      {
        declaration:
          'const { execPath: importedRuntime } = require("node:process");',
        body: `    return execFile(importedRuntime, ${args});`,
        binding: "importedRuntime<-node:process.execPath",
      },
      {
        declaration: 'import nodeProcess = require("node:process");',
        body: `    const runtime: string = nodeProcess.execPath;\n    return spawn(runtime, ${args});`,
        binding: "nodeProcess<-node:process",
      },
    ];
    for (const { declaration, body, binding } of cases) {
      const source = v2(body).replace(
        'import { exec, execFile, spawn } from "node:child_process";',
        `import { exec, execFile, spawn } from "node:child_process";\n${declaration}`,
      );
      const found = records(source);
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.id).toBe(
        "node-mcp-tool-argument-injection",
      );
      expect(found[0]?.frameworkModel.propagators).toContainEqual(
        expect.objectContaining({
          kind: "mcp-tool-node-process-binding",
          symbol: binding,
        }),
      );
    }
  });

  test("requires a live exact node:process binding and end-of-options boundary", () => {
    const args = '["-e", "process.stdout.write(process.argv[1])", command]';
    const source = (declaration: string, body: string) =>
      v2(body).replace(
        'import { exec, execFile, spawn } from "node:child_process";',
        `import { exec, execFile, spawn } from "node:child_process";\n${declaration}`,
      );
    const rejected = [
      source(
        'import nodeProcess from "process";',
        `    return execFile(nodeProcess.execPath, ${args});`,
      ),
      source(
        'import nodeProcess from "process-polyfill";',
        `    return execFile(nodeProcess.execPath, ${args});`,
      ),
      source(
        'import nodeProcess from "node:process";',
        `    const nodeProcess = { execPath: "node" };\n    return execFile(nodeProcess.execPath, ${args});`,
      ),
      source(
        'let nodeProcess = require("node:process");',
        `    nodeProcess = { execPath: "node" };\n    return execFile(nodeProcess.execPath, ${args});`,
      ),
      source(
        'const nodeProcess = require("node:process");',
        `    nodeProcess.execPath = "node";\n    return execFile(nodeProcess.execPath, ${args});`,
      ),
      source(
        'let nodeProcess = require("node:process");',
        `    [nodeProcess] = [{ execPath: "node" }];\n    return execFile(nodeProcess.execPath, ${args});`,
      ),
      source(
        'const nodeProcess = require("node:process");',
        `    nodeProcess["execPath"] = "node";\n    return execFile(nodeProcess.execPath, ${args});`,
      ),
      source(
        'const nodeProcess = require("node:process");',
        `    delete nodeProcess.execPath;\n    return execFile(nodeProcess.execPath, ${args});`,
      ),
      source(
        'const nodeProcess = require("node:process");',
        `    Object.defineProperty(nodeProcess, "execPath", { value: "node" });\n    return execFile(nodeProcess.execPath, ${args});`,
      ),
      source(
        'const nodeProcess = require("node:process");',
        `    Object.assign(nodeProcess, { execPath: "node" });\n    return execFile(nodeProcess.execPath, ${args});`,
      ),
      source(
        'let { execPath: importedRuntime } = require("node:process");',
        `    [importedRuntime] = ["node"];\n    return execFile(importedRuntime, ${args});`,
      ),
      source(
        'import nodeProcess from "node:process";',
        `    const runtime = nodeProcess["execPath"];\n    return execFile(runtime, ${args});`,
      ),
      source(
        'import nodeProcess from "node:process";',
        `    const runtime = nodeProcess.execPath;\n    const forwarded = runtime;\n    return execFile(forwarded, ${args});`,
      ),
      source(
        'import nodeProcess from "node:process";',
        `    return execFile(nodeProcess.execPath, ["-e", "process.stdout.write(process.argv[1])", "--", command]);`,
      ),
    ];
    for (const candidate of rejected) expect(records(candidate)).toEqual([]);
  });

  test("supports module-scope and typed Node runtime aliases", () => {
    const moduleAlias = v2(
      '    return execFile(runtime, ["-e", "process.stdout.write(process.argv[1])", command]);',
    ).replace(
      "const server =",
      "const runtime = process.execPath;\n\nconst server =",
    );
    const typedAlias = v2(
      '    const runtime: string = process.execPath;\n    return spawn(runtime, ["-e", "process.stdout.write(process.argv[1])", command]);',
    );
    for (const source of [moduleAlias, typedAlias]) {
      const found = records(source);
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.id).toBe(
        "node-mcp-tool-argument-injection",
      );
      expect(
        found[0]?.frameworkModel.propagators.some(
          ({ kind, symbol }) =>
            kind === "mcp-tool-node-runtime" &&
            symbol === "runtime=process.execPath",
        ),
      ).toBeTrue();
    }
  });

  test("requires an exact live Node runtime alias and end-of-options boundary", () => {
    const args = '["-e", "process.stdout.write(process.argv[1])", command]';
    const rejected = [
      `    let runtime = process.execPath;\n    runtime = "node";\n    return execFile(runtime, ${args});`,
      `    const runtime = process.execPath;\n    const forwarded = runtime;\n    return execFile(forwarded, ${args});`,
      `    const process = { execPath: "node" };\n    return execFile(process.execPath, ${args});`,
      `    process.execPath = "node";\n    return execFile(process.execPath, ${args});`,
      `    let runtime = process.execPath;\n    [runtime] = ["node"];\n    return execFile(runtime, ${args});`,
      `    delete process.execPath;\n    return execFile(process.execPath, ${args});`,
      `    Object.defineProperty(process, "execPath", { value: "node" });\n    return execFile(process.execPath, ${args});`,
      `    Object.assign(process, { execPath: "node" });\n    return execFile(process.execPath, ${args});`,
      `    const runtime = globalThis.process.execPath;\n    return execFile(runtime, ${args});`,
    ];
    for (const body of rejected) expect(records(v2(body))).toEqual([]);
    expect(
      records(
        v2(
          '    const runtime = process.execPath;\n    return execFile(runtime, ["-e", "process.stdout.write(process.argv[1])", "--", command]);',
        ),
      ),
    ).toEqual([]);
  });

  test("treats an exact Node end-of-options element as a strong control", () => {
    const found = records(
      v2(
        '    return execFile(process.execPath, ["-e", "process.stdout.write(process.argv[1])", "--", command]);',
      ),
    );
    expect(found).toEqual([]);
  });

  test("detects MCP tool input reaching direct JavaScript evaluation", () => {
    const found = records(v2("    return eval(command);"));
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.id).toBe("node-mcp-tool-code-injection");
    expect(found[0]?.frameworkModel.sink.kind).toBe("mcp-tool-code-evaluation");
    expect(found[0]?.frameworkModel.sink.symbol).toBe("eval:code[0]");
    expect(found[0]?.frameworkModel.sink.cweIds).toEqual(["CWE-94", "CWE-95"]);
    expect(found[0]?.categories).toContain(
      "broken-control:mcp-tool-code-data-boundary",
    );
  });

  test("supports exact Node VM immediate evaluator bindings", () => {
    const cases = [
      [
        'import { runInThisContext as execute } from "node:vm";\n',
        "    return execute(command);",
        "execute:code[0]",
      ],
      [
        'import * as vm from "node:vm";\n',
        "    return vm.runInNewContext(command, {}, { timeout: 50 });",
        "vm.runInNewContext:code[0]",
      ],
      [
        'import vm from "node:vm";\n',
        "    return vm.runInContext(command, vm.createContext({}), { timeout: 50 });",
        "vm.runInContext:code[0]",
      ],
      [
        'const vm = require("vm");\n',
        "    return vm.runInThisContext(command, { timeout: 50 });",
        "vm.runInThisContext:code[0]",
      ],
      [
        'import vm = require("node:vm");\n',
        "    return vm.runInNewContext(command, {}, { timeout: 50 });",
        "vm.runInNewContext:code[0]",
      ],
    ] as const;
    for (const [binding, body, symbol] of cases) {
      const found = records(`${binding}${v2(body)}`);
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.id).toBe("node-mcp-tool-code-injection");
      expect(found[0]?.frameworkModel.sink.symbol).toBe(symbol);
    }
  });

  test("requires evaluation rather than inert code construction", () => {
    const source = `${'import vm from "node:vm";\n'}${v2(`
    new Function(command);
    vm.compileFunction(command);
    new vm.Script(command);
    new vm.SourceTextModule(command);
    return eval("6 * 7");`)}`;
    expect(records(source)).toEqual([]);
  });

  test("detects global Function source only when the compiled function runs", () => {
    const assigned = records(
      v2(
        '    const calculate = new Function("value", command);\n    return calculate(42);',
      ),
    );
    expect(assigned).toHaveLength(1);
    expect(assigned[0]?.frameworkModel.sink.symbol).toBe("calculate():code[1]");
    expect(assigned[0]?.frameworkModel.propagators).toContainEqual(
      expect.objectContaining({
        kind: "mcp-tool-code-construction",
        symbol: "Function:code[1]",
      }),
    );

    for (const body of [
      "    return new Function(command)();",
      "    return Function(command).call(undefined);",
      "    return globalThis.Function(command).apply(undefined, []);",
    ]) {
      const found = records(v2(body));
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.id).toBe("node-mcp-tool-code-injection");
    }
  });

  test("detects exact vm.compileFunction results that are later invoked", () => {
    const cases = [
      [
        'import { compileFunction as compile } from "node:vm";\n',
        "    const operation = compile(command);\n    return operation();",
        "operation():code[0]",
      ],
      [
        'import * as vm from "node:vm";\n',
        "    return vm.compileFunction(command)();",
        "vm.compileFunction():code[0]",
      ],
      [
        'const vm = require("vm");\n',
        "    const operation = vm.compileFunction(command);\n    return operation.call(undefined);",
        "operation.call:code[0]",
      ],
    ] as const;
    for (const [binding, body, symbol] of cases) {
      const found = records(`${binding}${v2(body)}`);
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.sink.symbol).toBe(symbol);
      expect(found[0]?.frameworkModel.propagators).toContainEqual(
        expect.objectContaining({ kind: "mcp-tool-code-construction" }),
      );
    }
  });

  test("detects exact vm.Script source only when the same script runs", () => {
    const cases = [
      [
        'import { Script as VmScript } from "node:vm";\n',
        "    const script = new VmScript(command);\n    return script.runInThisContext();",
        "script.runInThisContext:code[0]",
      ],
      [
        'import vm from "node:vm";\n',
        "    return new vm.Script(command).runInNewContext({});",
        "runInNewContext:code[0]",
      ],
      [
        'import vm = require("node:vm");\n',
        "    const script = new vm.Script(command);\n    return script.runInContext(vm.createContext({}));",
        "script.runInContext:code[0]",
      ],
    ] as const;
    for (const [binding, body, symbol] of cases) {
      const found = records(`${binding}${v2(body)}`);
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.sink.symbol).toBe(symbol);
    }
  });

  test("requires a complete SourceTextModule link and evaluation lifecycle", () => {
    const modern = records(
      `${'import * as vm from "node:vm";\n'}${v2(`
    const module = new vm.SourceTextModule(command);
    module.linkRequests([]);
    module.instantiate();
    return module.evaluate();`)}`,
    );
    expect(modern).toHaveLength(1);
    expect(modern[0]?.frameworkModel.sink.symbol).toBe(
      "module.evaluate:code[0]",
    );
    expect(
      modern[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("mcp-tool-code-instantiation");

    const legacy = records(
      `${'import { SourceTextModule } from "node:vm";\n'}${v2(`
    const module = new SourceTextModule(command);
    await module.link(async () => { throw new Error("no imports"); });
    return module.evaluate();`)}`,
    );
    expect(legacy).toHaveLength(1);
    expect(legacy[0]?.frameworkModel.propagators).toContainEqual(
      expect.objectContaining({ kind: "mcp-tool-code-linking" }),
    );

    for (const body of [
      "    const module = new vm.SourceTextModule(command);\n    return module.evaluate();",
      "    const module = new vm.SourceTextModule(command);\n    module.linkRequests([]);\n    return module.evaluate();",
      "    const module = new vm.SourceTextModule(command);\n    module.instantiate();\n    return module.evaluate();",
      "    const module = new vm.SourceTextModule(command);\n    module.link(() => {});\n    return module.evaluate();",
    ]) {
      expect(
        records(`${'import * as vm from "node:vm";\n'}${v2(body)}`),
      ).toEqual([]);
    }
  });

  test("detects exact worker_threads eval source at worker startup", () => {
    const cases = [
      [
        'import { Worker as ThreadWorker } from "node:worker_threads";\n',
        "    return new ThreadWorker(command, { eval: true });",
        "ThreadWorker:code[0]",
      ],
      [
        'import * as threads from "node:worker_threads";\n',
        '    return new threads.Worker(command, { name: "bounded", eval: true });',
        "threads.Worker:code[0]",
      ],
      [
        'const { Worker: ThreadWorker } = require("worker_threads");\n',
        "    return new ThreadWorker(command, { eval: true });",
        "ThreadWorker:code[0]",
      ],
      [
        'import threads = require("node:worker_threads");\n',
        "    return new threads.Worker(command, { eval: true });",
        "threads.Worker:code[0]",
      ],
      [
        'import { Worker } from "node:worker_threads";\n',
        '    return new Worker(command, { "eval": true });',
        "Worker:code[0]",
      ],
    ] as const;
    for (const [binding, body, symbol] of cases) {
      const found = records(`${binding}${v2(body)}`);
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.id).toBe("node-mcp-tool-code-injection");
      expect(found[0]?.frameworkModel.sink.kind).toBe(
        "mcp-tool-worker-code-evaluation",
      );
      expect(found[0]?.frameworkModel.sink.symbol).toBe(symbol);
      expect(found[0]?.frameworkModel.propagators).toContainEqual(
        expect.objectContaining({
          kind: "mcp-tool-code-construction",
          symbol: expect.stringContaining("new "),
        }),
      );
      expect(found[0]?.frameworkModel.propagators).toContainEqual(
        expect.objectContaining({
          kind: "mcp-tool-worker-startup",
          symbol: expect.stringContaining("eval:true"),
        }),
      );
    }
  });

  test("follows MCP input through a same-file worker eval helper", () => {
    const found = records(
      `${'import { Worker } from "node:worker_threads";\n'}${v2(`
    return runWorker(command);`)}
function runWorker(source) {
  return new Worker(source, { eval: true });
}`,
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.sink.kind).toBe(
      "mcp-tool-worker-code-evaluation",
    );
    expect(
      found[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual([
      "mcp-tool-registration",
      "mcp-tool-code-construction",
      "mcp-tool-worker-startup",
      "mcp-tool-helper-call",
    ]);
  });

  test("keeps workerData as data and fails closed on ambiguous Worker options", () => {
    const cases = [
      "    return new Worker(command);",
      "    return new Worker(command, { eval: false });",
      "    return new Worker(command, { eval });",
      "    return Worker(command, { eval: true });",
      '    return new Worker("const { workerData } = require(\\"node:worker_threads\\");", { eval: true, workerData: command });',
      "    return new Worker(command, { eval: true, eval: false });",
      "    return new Worker(command, { ...options, eval: true });",
      '    return new Worker(command, { ["eval"]: true });',
    ];
    for (const body of cases) {
      expect(
        records(
          `${'import { Worker } from "node:worker_threads";\n'}${v2(body)}`,
        ),
      ).toEqual([]);
    }
  });

  test("rejects replaced, shadowed, and lookalike Worker capabilities", () => {
    const cases = [
      `${'import { Worker } from "node:worker_threads";\n'}${v2(
        "    Worker = SafeWorker;\n    return new Worker(command, { eval: true });",
      )}`,
      `${'import * as threads from "node:worker_threads";\n'}${v2(
        "    threads.Worker = SafeWorker;\n    return new threads.Worker(command, { eval: true });",
      )}`,
      `${'import { Worker } from "node:worker_threads";\n'}${v2(
        "    const Worker = SafeWorker;\n    return new Worker(command, { eval: true });",
      )}`,
      `${'import { Worker } from "worker-pool";\n'}${v2(
        "    return new Worker(command, { eval: true });",
      )}`,
    ];
    for (const source of cases) expect(records(source)).toEqual([]);
  });

  test("rejects replaced code constructors, compiled values, and lifecycle methods", () => {
    const cases = [
      `globalThis.Function = safeFactory;\n${v2(
        "    const operation = new Function(command);\n    return operation();",
      )}`,
      v2(
        "    let operation = new Function(command);\n    operation = safeOperation;\n    return operation();",
      ),
      v2(
        "    const operation = new Function(command);\n    operation.call = safeOperation;\n    return operation.call(undefined);",
      ),
      `${'import * as vm from "node:vm";\n'}${v2(
        "    vm.compileFunction = safeCompile;\n    return vm.compileFunction(command)();",
      )}`,
      `${'import * as vm from "node:vm";\n'}${v2(
        '    let script = new vm.Script(command);\n    script = new vm.Script("6 * 7");\n    return script.runInThisContext();',
      )}`,
      `import * as vm from "node:vm";\nvm.Script.prototype.runInThisContext = safeOperation;\n${v2(
        "    const script = new vm.Script(command);\n    return script.runInThisContext();",
      )}`,
      `${'import * as vm from "node:vm";\n'}${v2(
        "    const module = new vm.SourceTextModule(command);\n    module.linkRequests = safeLink;\n    module.linkRequests([]);\n    module.instantiate();\n    return module.evaluate();",
      )}`,
    ];
    for (const source of cases) expect(records(source)).toEqual([]);
  });

  test("rejects replaced and shadowed immediate vm evaluator bindings", () => {
    const cases = [
      `${'import * as vm from "node:vm";\n'}${v2(
        "    vm.runInThisContext = safeOperation;\n    return vm.runInThisContext(command);",
      )}`,
      `${'import * as vm from "node:vm";\n'}${v2(
        "    const vm = safeVm;\n    return vm.runInThisContext(command);",
      )}`,
      `${'import { runInThisContext as execute } from "node:vm";\n'}${v2(
        "    execute = safeOperation;\n    return execute(command);",
      )}`,
    ];
    for (const source of cases) expect(records(source)).toEqual([]);
  });

  test("detects MCP tool input compiled and executed as a regular expression", () => {
    const found = records(
      v2(
        '    const expression = new RegExp(pattern, "u");\n    return expression.test("fixed diagnostic text");',
        "pattern: z.string()",
      ),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.id).toBe("node-mcp-tool-regex-injection");
    expect(found[0]?.frameworkModel.sink.kind).toBe(
      "mcp-tool-regular-expression",
    );
    expect(found[0]?.frameworkModel.sink.symbol).toBe("RegExp.test:pattern[0]");
    expect(found[0]?.frameworkModel.sink.cweIds).toEqual([
      "CWE-400",
      "CWE-730",
    ]);
    expect(
      found[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual(["mcp-tool-registration", "mcp-tool-regex-construction"]);
    expect(found[0]?.categories).toContain(
      "broken-control:mcp-tool-regex-pattern-boundary",
    );
  });

  test("supports immediate callable RegExp execution", () => {
    for (const body of [
      '    return new RegExp(pattern, "u").test("fixed diagnostic text");',
      '    return RegExp(pattern, "u").exec("fixed diagnostic text");',
    ]) {
      const found = records(v2(body, "pattern: z.string()"));
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.id).toBe("node-mcp-tool-regex-injection");
    }
  });

  test("requires regex execution and keeps tool input in the pattern role", () => {
    expect(
      records(
        v2('    return new RegExp(pattern, "u");', "pattern: z.string()"),
      ),
    ).toEqual([]);
    expect(
      records(
        v2(
          "    const expression = /error/u;\n    return expression.test(pattern);",
          "pattern: z.string()",
        ),
      ),
    ).toEqual([]);
    expect(
      records(
        v2(
          '    const expression = new RegExp("error", pattern);\n    return expression.test("fixed diagnostic text");',
          "pattern: z.string()",
        ),
      ),
    ).toEqual([]);
  });

  test("rejects shadowed, replaced, and invalidated RegExp capabilities", () => {
    const localConstructor = `${v2(
      '    const expression = new RegExp(pattern);\n    return expression.test("fixed");',
      "pattern: z.string()",
    )}
function RegExp(value: string) { return { test: () => value.length > 0 }; }
`;
    expect(records(localConstructor)).toEqual([]);
    expect(
      records(
        `globalThis.RegExp = customConstructor;\n${v2(
          '    const expression = new RegExp(pattern);\n    return expression.test("fixed");',
          "pattern: z.string()",
        )}`,
      ),
    ).toEqual([]);
    expect(
      records(
        `RegExp.prototype.test = () => true;\n${v2(
          '    const expression = new RegExp(pattern);\n    return expression.test("fixed");',
          "pattern: z.string()",
        )}`,
      ),
    ).toEqual([]);
    expect(
      records(
        v2(
          '    RegExp = customConstructor;\n    const expression = new RegExp(pattern);\n    return expression.test("fixed");',
          "pattern: z.string()",
        ),
      ),
    ).toEqual([]);
    expect(
      records(
        v2(
          '    let expression = new RegExp(pattern);\n    expression = /fixed/u;\n    return expression.test("fixed");',
          "pattern: z.string()",
        ),
      ),
    ).toEqual([]);
    expect(
      records(
        v2(
          '    const expression = new RegExp(pattern);\n    expression.test = () => true;\n    return expression.test("fixed");',
          "pattern: z.string()",
        ),
      ),
    ).toEqual([]);
  });

  test("detects MCP tool input executed as SQL by node:sqlite", () => {
    const found = records(
      sqliteV2(
        "    const sql = `SELECT role FROM users WHERE name = '${command}'`;\n    return database.exec(sql);",
      ),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.id).toBe("node-mcp-tool-sql-injection");
    expect(found[0]?.frameworkModel.source).toMatchObject({
      kind: "mcp-tool-input",
      symbol: "sql",
    });
    expect(found[0]?.frameworkModel.sink).toMatchObject({
      kind: "mcp-tool-sql-query",
      symbol: "database.exec:sql[0]",
      cweIds: ["CWE-89"],
    });
    expect(
      found[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual([
      "mcp-tool-registration",
      "mcp-tool-local-assignment",
      "mcp-tool-sqlite-database",
      "mcp-tool-sql-execution",
    ]);
  });

  test("detects MCP tool input prepared and executed by node:sqlite", () => {
    const found = records(
      sqliteV2(
        "    const statement = database.prepare(`SELECT role FROM users WHERE name = '${command}'`);\n    return statement.get();",
      ),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.id).toBe("node-mcp-tool-sql-injection");
    expect(found[0]?.frameworkModel.source).toMatchObject({
      kind: "mcp-tool-input",
      symbol: "command",
    });
    expect(found[0]?.frameworkModel.sink).toMatchObject({
      kind: "mcp-tool-sql-query",
      symbol: "statement.get:prepared-sql[0]",
      cweIds: ["CWE-89"],
    });
    expect(
      found[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual([
      "mcp-tool-registration",
      "mcp-tool-sqlite-database",
      "mcp-tool-sql-preparation",
      "mcp-tool-sql-execution",
    ]);
  });

  test("covers every StatementSync execution form after tainted preparation", () => {
    for (const method of ["all", "get", "iterate", "run"] as const) {
      const assigned = records(
        sqliteV2(
          `    const statement = database.prepare(command);\n    return statement.${method}();`,
        ),
      );
      expect(assigned).toHaveLength(1);
      expect(assigned[0]?.frameworkModel.sink.symbol).toBe(
        `statement.${method}:prepared-sql[0]`,
      );

      const immediate = records(
        sqliteV2(`    return database.prepare(command).${method}();`),
      );
      expect(immediate).toHaveLength(1);
      expect(immediate[0]?.frameworkModel.sink.symbol).toBe(
        `database.prepare().${method}:prepared-sql[0]`,
      );
    }
  });

  test("supports using declarations, a stable statement alias, and a same-file helper", () => {
    for (const declaration of ["using", "await using"] as const) {
      const found = records(
        sqliteV2(
          `    ${declaration} statement = database.prepare(command);\n    return statement.get();`,
        ),
      );
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.sink.symbol).toBe(
        "statement.get:prepared-sql[0]",
      );
    }

    const assigned = records(
      sqliteV2(
        "    let statement;\n    statement = database.prepare(command);\n    return statement.run();",
      ),
    );
    expect(assigned).toHaveLength(1);
    expect(assigned[0]?.frameworkModel.sink.symbol).toBe(
      "statement.run:prepared-sql[0]",
    );

    const alias = records(
      sqliteV2(
        "    const statement = database.prepare(command);\n    const auditStatement = statement;\n    return auditStatement.all();",
      ),
    );
    expect(alias).toHaveLength(1);
    expect(alias[0]?.frameworkModel.sink.symbol).toBe(
      "auditStatement.all:prepared-sql[0]",
    );

    const helper = records(
      sqliteV2(
        "    return runPrepared(command);",
        'import { DatabaseSync } from "node:sqlite";\nfunction runPrepared(sql) {\n  const statement = database.prepare(sql);\n  return statement.get();\n}',
      ),
    );
    expect(helper).toHaveLength(1);
    expect(helper[0]?.frameworkModel.propagators.at(-1)?.kind).toBe(
      "mcp-tool-helper-call",
    );
  });

  test("requires live prepared-statement execution and fails closed on replacement or finalization", () => {
    const controls = [
      sqliteV2("    return database.prepare(command);"),
      sqliteV2(
        "    const statement = database.prepare(command);\n    return statement.getColumnMetadata();",
      ),
      sqliteV2(
        '    const statement = database.prepare("SELECT role FROM users WHERE name = ?");\n    return statement.get(command);',
      ),
      sqliteV2(
        "    let statement = database.prepare(command);\n    statement = replacement;\n    return statement.get();",
      ),
      sqliteV2(
        "    const statement = database.prepare(command);\n    statement.get = safeGet;\n    return statement.get();",
      ),
      sqliteV2(
        "    const statement = database.prepare(command);\n    statement.close();\n    return statement.get();",
      ),
      sqliteV2(
        "    const statement = database.prepare(command);\n    statement[Symbol.dispose]();\n    return statement.get();",
      ),
      sqliteV2(
        "    const statement = database.prepare(command);\n    database.close();\n    return statement.get();",
      ),
      sqliteV2(
        "    const statement = database.prepare(command);\n    database[Symbol.dispose]();\n    return statement.get();",
      ),
      sqliteV2(
        "    const statement = database.prepare(command);\n    return statement.get();",
        'import { DatabaseSync } from "node:sqlite";\nDatabaseSync.prototype.prepare = safePrepare;',
      ),
      sqliteV2(
        "    const statement = database.prepare(command);\n    return statement.get();",
        'import { DatabaseSync, StatementSync } from "node:sqlite";\nStatementSync.prototype.get = safeGet;',
      ),
      sqliteV2(
        "    const statement = database.prepare(command);\n    return statement.get();",
        'import * as sqlite from "node:sqlite";\nsqlite.StatementSync.prototype.get = safeGet;',
        'const database = new sqlite.DatabaseSync(":memory:");',
      ),
    ];
    for (const control of controls) expect(records(control)).toEqual([]);
  });

  test("supports official node:sqlite bindings and a stable database alias", () => {
    for (const [sqliteImport, database, receiver] of [
      [
        'import { DatabaseSync as DB } from "node:sqlite";',
        'const database = new DB(":memory:");',
        "database",
      ],
      [
        'import * as sqlite from "node:sqlite";',
        'const database = new sqlite.DatabaseSync(":memory:");',
        "database",
      ],
      [
        'import sqlite from "node:sqlite";',
        'const database = new sqlite.DatabaseSync(":memory:");',
        "database",
      ],
      [
        'const { DatabaseSync: DB } = require("node:sqlite");',
        'const database = new DB(":memory:");',
        "database",
      ],
      [
        'const sqlite = require("node:sqlite");',
        'const database = new sqlite.DatabaseSync(":memory:");',
        "database",
      ],
      [
        'import sqlite = require("node:sqlite");',
        'const database = new sqlite.DatabaseSync(":memory:");\nconst auditDatabase = database;',
        "auditDatabase",
      ],
    ] as const) {
      const found = records(
        sqliteV2(
          `    return ${receiver}.exec(command);`,
          sqliteImport,
          database,
        ),
      );
      expect(found).toHaveLength(1);
      expect(found[0]?.frameworkModel.sink.kind).toBe("mcp-tool-sql-query");
    }
  });

  test("isolates distinct database lifecycles and preserves alias closure", () => {
    const separate = records(
      sqliteV2(
        "    const statement = database.prepare(command);\n    return statement.get();",
        'import { DatabaseSync } from "node:sqlite";',
        'const database = new DatabaseSync(":memory:");\nconst retiredDatabase = new DatabaseSync(":memory:");\nretiredDatabase.close();',
      ),
    );
    expect(separate).toHaveLength(1);

    const closedAlias = records(
      sqliteV2(
        "    auditDatabase.close();\n    const statement = database.prepare(command);\n    return statement.get();",
        'import { DatabaseSync } from "node:sqlite";',
        'const database = new DatabaseSync(":memory:");\nconst auditDatabase = database;',
      ),
    );
    expect(closedAlias).toEqual([]);
  });

  test("keeps bound parameters as data and rejects unproved SQLite identity", () => {
    const controls = [
      sqliteV2(
        '    const statement = database.prepare("SELECT role FROM users WHERE name = ?");\n    return statement.get(command);',
      ),
      sqliteV2(
        '    database.exec("SELECT role FROM users");\n    return command;',
      ),
      sqliteV2(
        "    const database = { exec: customExec };\n    return database.exec(command);",
      ),
      sqliteV2(
        "    return database.exec(command);",
        'import { DatabaseSync } from "sqlite3";',
      ),
      sqliteV2(
        "    return database.exec(command);",
        "class DatabaseSync { exec(value) { return value; } }",
      ),
      sqliteV2(
        "    return database.exec(command);",
        'import { DatabaseSync } from "node:sqlite";',
        'const database = new DatabaseSync(":memory:", options);',
      ),
      sqliteV2(
        "    return database.exec(command);",
        'import { DatabaseSync } from "node:sqlite";\nDatabaseSync.prototype.exec = customExec;',
      ),
      sqliteV2(
        "    return database.exec(command);",
        'import { DatabaseSync } from "node:sqlite";',
        'let database = new DatabaseSync(":memory:");\ndatabase = replacement;',
      ),
      sqliteV2(
        "    return database.exec(command);",
        'import { DatabaseSync } from "node:sqlite";',
        'const database = new DatabaseSync(":memory:");\ndatabase.exec = customExec;',
      ),
      sqliteV2("    database.close();\n    return database.exec(command);"),
      sqliteV2(
        "    return database.exec(command);",
        'import { DatabaseSync } from "node:sqlite";',
        'const database = new DatabaseSync(":memory:");\ndatabase.close();',
      ),
      `${sqliteV2("    return database.exec(command);")}\ndatabase.close();`,
    ];
    for (const control of controls) expect(records(control)).toEqual([]);
  });

  test("follows MCP SQL text through a same-file helper", () => {
    const found = records(
      sqliteV2(
        "    return runQuery(command);",
        'import { DatabaseSync } from "node:sqlite";\nfunction runQuery(sql) {\n  return database.exec(sql);\n}',
      ),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.id).toBe("node-mcp-tool-sql-injection");
    expect(
      found[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toEqual([
      "mcp-tool-registration",
      "mcp-tool-sqlite-database",
      "mcp-tool-sql-execution",
      "mcp-tool-helper-call",
    ]);
  });

  test("rejects shadowed and lookalike JavaScript evaluators", () => {
    const localEval = `${v2("    return eval(command);")}
function eval(value: string) { return value; }
`;
    expect(records(localEval)).toEqual([]);

    const helperParameter = `${v2("    return evaluate(command, JSON.parse);")}
function evaluate(code: string, eval: (value: string) => unknown) {
  return eval(code);
}
`;
    expect(records(helperParameter)).toEqual([]);

    const lookalike = `${'import * as vm from "./vm.js";\n'}${v2(
      "    return vm.runInNewContext(command, {});",
    )}`;
    expect(records(lookalike)).toEqual([]);

    const borrowedDirectName = `${'import { runInThisContext as execute } from "node:vm";\n'}${v2(`
    const local = { execute(value: string) { return value; } };
    return local.execute(command);`)}`;
    expect(records(borrowedDirectName)).toEqual([]);

    const borrowedNamespaceName = `${'import * as vm from "node:vm";\n'}${v2(`
    const local = { vm: { runInNewContext(value: string) { return value; } } };
    return local.vm.runInNewContext(command);`)}`;
    expect(records(borrowedNamespaceName)).toEqual([]);
  });

  test("detects stable-v2 SSRF through global fetch and local propagation", () => {
    const found = records(
      v2(
        "    const target = new URL(url);\n    return fetch(target);",
        "url: z.string().url()",
      ),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.id).toBe("node-mcp-tool-ssrf");
    expect(found[0]?.frameworkModel.sink.kind).toBe(
      "mcp-tool-network-destination",
    );
    expect(found[0]?.frameworkModel.sink.symbol).toBe("fetch");
    expect(found[0]?.frameworkModel.sink.cweIds).toEqual(["CWE-918"]);
  });

  test("detects stable-v2 filesystem authority through a path argument", () => {
    const found = records(
      v2(
        '    const target = command;\n    return readFile(target, "utf8");',
        "command: z.string().min(1)",
      ),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.id).toBe("node-mcp-tool-path-traversal");
    expect(found[0]?.frameworkModel.sink.kind).toBe("mcp-tool-filesystem-path");
    expect(found[0]?.frameworkModel.sink.symbol).toBe("readFile:path[0]");
    expect(found[0]?.frameworkModel.sink.cweIds).toEqual(["CWE-22", "CWE-73"]);
    expect(found[0]?.categories).toContain(
      "broken-control:mcp-tool-filesystem-path-not-confined",
    );
  });

  test("supports v1 tool registration, import aliases, and server aliases", () => {
    const source = `import { McpServer as Server } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync as run } from "child_process";
const root = new Server({ name: "legacy", version: "1.0.0" });
const tools = root;
tools.tool("run", { command: z.string() }, async ({ command: script }) => {
  run("printf ok; " + script);
  return { content: [] };
});
`;
    const found = records(source);
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.sink.symbol).toBe("run");
    expect(found[0]?.frameworkModel.source.symbol).toBe("script");
    expect(found[0]?.frameworkModel.propagators[0]?.symbol).toBe(
      "tools.tool:run",
    );
  });

  test("supports CommonJS MCP and child-process namespaces", () => {
    const source = `const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const cp = require("node:child_process");
const server = new McpServer({ name: "legacy", version: "1.0.0" });
server.tool("run", { program: z.string() }, async (args) => {
  cp.spawn(args.program, []);
  return { content: [] };
});
`;
    const found = records(source);
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel.sink.kind).toBe(
      "mcp-tool-executable-selection",
    );
    expect(found[0]?.frameworkModel.sink.symbol).toBe("cp.spawn");
  });

  test("supports Node fs namespace, promises, default, and import-equals bindings", () => {
    const namespace = `import { McpServer } from "@modelcontextprotocol/server";
import * as fs from "node:fs";
const server = new McpServer({ name: "files", version: "1.0.0" });
server.registerTool("read", { inputSchema: schema }, async ({ path }) => {
  return fs.promises.readFile(path, "utf8");
});
`;
    expect(records(namespace)[0]?.frameworkModel.sink.symbol).toBe(
      "fs.promises.readFile:path[0]",
    );

    const defaultBinding = `import { McpServer } from "@modelcontextprotocol/server";
import fs from "node:fs";
const server = new McpServer({ name: "files", version: "1.0.0" });
server.registerTool("read", { inputSchema: schema }, async ({ path }) => {
  return fs.readFileSync(path, "utf8");
});
`;
    expect(records(defaultBinding)[0]?.frameworkModel.sink.symbol).toBe(
      "fs.readFileSync:path[0]",
    );

    const importEquals = `import mcp = require("@modelcontextprotocol/sdk/server/mcp.js");
import fs = require("node:fs");
const server = new mcp.McpServer({ name: "files", version: "1.0.0" });
server.tool("read", { path: schema }, async (input) => fs.readFileSync(input.path));
`;
    expect(records(importEquals)[0]?.frameworkModel.sink.symbol).toBe(
      "fs.readFileSync:path[0]",
    );

    const commonJs = `const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const fsp = require("node:fs/promises");
const server = new McpServer({ name: "files", version: "1.0.0" });
server.tool("remove", { path: schema }, async (input) => fsp.rm(input.path));
`;
    expect(records(commonJs)[0]?.frameworkModel.sink.symbol).toBe(
      "fsp.rm:path[0]",
    );
  });

  test("tracks every filesystem path position but not write contents", () => {
    const secondPath = `import { McpServer } from "@modelcontextprotocol/server";
import { rename } from "node:fs/promises";
const server = new McpServer({ name: "files", version: "1.0.0" });
server.registerTool("move", { inputSchema: schema }, async ({ path }) => {
  return rename("operator-source.txt", path);
});
`;
    expect(records(secondPath)[0]?.frameworkModel.sink.symbol).toBe(
      "rename:path[1]",
    );
    expect(
      records(
        v2('    return writeFile("operator-fixed.txt", command, "utf8");'),
      ),
    ).toEqual([]);
  });

  test("covers the complete Node filesystem path-method table", () => {
    const cases: Array<[string, string, number]> = [
      ["access", "path", 0],
      ["accessSync", "path", 0],
      ["appendFile", 'path, "data"', 0],
      ["appendFileSync", 'path, "data"', 0],
      ["chmod", "path, 0o600", 0],
      ["chmodSync", "path, 0o600", 0],
      ["chown", "path, 1, 1", 0],
      ["chownSync", "path, 1, 1", 0],
      ["copyFile", 'path, "fixed"', 0],
      ["copyFile", '"fixed", path', 1],
      ["copyFileSync", 'path, "fixed"', 0],
      ["copyFileSync", '"fixed", path', 1],
      ["cp", 'path, "fixed"', 0],
      ["cp", '"fixed", path', 1],
      ["cpSync", 'path, "fixed"', 0],
      ["cpSync", '"fixed", path', 1],
      ["createReadStream", "path", 0],
      ["createWriteStream", "path", 0],
      ["existsSync", "path", 0],
      ["lchmod", "path, 0o600", 0],
      ["lchmodSync", "path, 0o600", 0],
      ["lchown", "path, 1, 1", 0],
      ["lchownSync", "path, 1, 1", 0],
      ["link", 'path, "fixed"', 0],
      ["link", '"fixed", path', 1],
      ["linkSync", 'path, "fixed"', 0],
      ["linkSync", '"fixed", path', 1],
      ["lstat", "path", 0],
      ["lstatSync", "path", 0],
      ["lutimes", "path, new Date(), new Date()", 0],
      ["lutimesSync", "path, new Date(), new Date()", 0],
      ["mkdir", "path", 0],
      ["mkdirSync", "path", 0],
      ["mkdtemp", "path", 0],
      ["mkdtempSync", "path", 0],
      ["open", 'path, "r"', 0],
      ["openAsBlob", "path", 0],
      ["openSync", 'path, "r"', 0],
      ["opendir", "path", 0],
      ["opendirSync", "path", 0],
      ["readdir", "path", 0],
      ["readdirSync", "path", 0],
      ["readFile", "path", 0],
      ["readFileSync", "path", 0],
      ["readlink", "path", 0],
      ["readlinkSync", "path", 0],
      ["realpath", "path", 0],
      ["realpathSync", "path", 0],
      ["rename", 'path, "fixed"', 0],
      ["rename", '"fixed", path', 1],
      ["renameSync", 'path, "fixed"', 0],
      ["renameSync", '"fixed", path', 1],
      ["rm", "path", 0],
      ["rmSync", "path", 0],
      ["rmdir", "path", 0],
      ["rmdirSync", "path", 0],
      ["stat", "path", 0],
      ["statSync", "path", 0],
      ["statfs", "path", 0],
      ["statfsSync", "path", 0],
      ["symlink", 'path, "fixed"', 0],
      ["symlink", '"fixed", path', 1],
      ["symlinkSync", 'path, "fixed"', 0],
      ["symlinkSync", '"fixed", path', 1],
      ["truncate", "path, 0", 0],
      ["truncateSync", "path, 0", 0],
      ["unlink", "path", 0],
      ["unlinkSync", "path", 0],
      ["unwatchFile", "path", 0],
      ["utimes", "path, new Date(), new Date()", 0],
      ["utimesSync", "path, new Date(), new Date()", 0],
      ["watch", "path", 0],
      ["watchFile", "path", 0],
      ["writeFile", 'path, "data"', 0],
      ["writeFileSync", 'path, "data"', 0],
    ];
    for (const [method, arguments_, position] of cases) {
      const source = `import { McpServer } from "@modelcontextprotocol/server";
import { ${method} } from "node:fs";
const server = new McpServer({ name: "files", version: "1.0.0" });
server.registerTool("operate", { inputSchema: schema }, async ({ path }) => {
  return ${method}(${arguments_});
});
`;
      const found = records(source);
      expect(found, `${method} path argument ${position}`).toHaveLength(1);
      expect(found[0]?.frameworkModel.sink.symbol).toBe(
        `${method}:path[${position}]`,
      );
    }
  });

  test("does not confuse filesystem data, flags, modes, or encodings with paths", () => {
    const controls = [
      ["writeFile", '"fixed.txt", path'],
      ["appendFile", '"fixed.txt", path'],
      ["open", '"fixed.txt", path'],
      ["readFile", '"fixed.txt", path'],
      ["chmod", '"fixed.txt", path'],
      ["chown", '"fixed.txt", path, 1'],
      ["utimes", '"fixed.txt", path, new Date()'],
    ];
    for (const [method, arguments_] of controls) {
      const source = `import { McpServer } from "@modelcontextprotocol/server";
import { ${method} } from "node:fs";
const server = new McpServer({ name: "files", version: "1.0.0" });
server.registerTool("operate", { inputSchema: schema }, async ({ path }) => {
  return ${method}(${arguments_});
});
`;
      expect(records(source), method).toEqual([]);
    }
  });

  test("treats join and resolve as construction rather than confinement", () => {
    const source = `import { McpServer } from "@modelcontextprotocol/server";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
const server = new McpServer({ name: "files", version: "1.0.0" });
server.registerTool("read", { inputSchema: schema }, async ({ path }) => {
  return readFile(resolve("operator-root", path), "utf8");
});
`;
    expect(records(source)[0]?.frameworkModel.id).toBe(
      "node-mcp-tool-path-traversal",
    );
  });

  test("supports multiline imports and TypeScript import-equals namespaces", () => {
    const multiline = `import {
  McpServer,
  type RegisteredTool,
} from "@modelcontextprotocol/server";
import {
  exec as run,
} from "node:child_process";
const server = new McpServer({ name: "tools", version: "1.0.0" });
server.registerTool("run", { inputSchema: schema }, async ({ command }) => {
  run(command);
  return { content: [] };
});
`;
    expect(records(multiline)[0]?.frameworkModel.sink.symbol).toBe("run");

    const importEquals = `import mcp = require("@modelcontextprotocol/sdk/server/mcp.js");
import cp = require("node:child_process");
const server = new mcp.McpServer({ name: "tools", version: "1.0.0" });
server.tool("run", { command: schema }, async (input) => {
  cp.exec(input.command);
  return { content: [] };
});
`;
    expect(records(importEquals)[0]?.frameworkModel.sink.symbol).toBe(
      "cp.exec",
    );
  });

  test("models shell-enabled spawn and shell interpreter arguments", () => {
    const shellEnabled = records(
      v2('    spawn("printf", [command], { shell: true });'),
    );
    expect(shellEnabled[0]?.frameworkModel.sink.kind).toBe(
      "mcp-tool-shell-enabled-spawn",
    );

    const interpreter = records(v2('    spawn("sh", ["-c", command]);'));
    expect(interpreter[0]?.frameworkModel.sink.kind).toBe(
      "mcp-tool-shell-command",
    );
  });

  test("models exact http and imported fetch network clients", () => {
    const http = records(
      v2("    return https.request(url);", "url: z.string()"),
    );
    expect(http[0]?.frameworkModel.sink.symbol).toBe("https.request");

    const imported = `import { McpServer } from "@modelcontextprotocol/server";
import { fetch as request } from "undici";
const server = new McpServer({ name: "net", version: "1.0.0" });
server.registerTool("get", { inputSchema: schema }, async ({ url }) => request(url));
`;
    expect(records(imported)[0]?.frameworkModel.sink.symbol).toBe("request");
  });

  test("isolates axios and Node request destinations from request data", () => {
    const axiosTarget = records(
      v2("    return axios.get(url);", "url: z.string()"),
    );
    expect(axiosTarget[0]?.frameworkModel.sink.symbol).toBe("axios.get");

    const axiosConfig = records(
      v2(
        '    return axios.request({ method: "GET", url });',
        "url: z.string()",
      ),
    );
    expect(axiosConfig[0]?.frameworkModel.sink.symbol).toBe("axios.request");

    expect(
      records(
        v2(
          '    return axios.request({ url: "https://api.example.test/v1", data: url });',
          "url: z.string()",
        ),
      ),
    ).toEqual([]);
    expect(
      records(
        v2(
          '    return https.request({ hostname: "api.example.test", path: url });',
          "url: z.string()",
        ),
      ),
    ).toEqual([]);
  });

  test("treats fixed executable argv and fixed network destinations as controls", () => {
    expect(records(v2('    execFile("printf", ["%s", command]);'))).toEqual([]);
    expect(
      records(v2('    spawn("printf", ["%s", command], { shell: false });')),
    ).toEqual([]);
    expect(
      records(
        v2(
          '    return fetch("https://api.example.test/v1/messages", { method: "POST", body: url });',
          "url: z.string()",
        ),
      ),
    ).toEqual([]);
  });

  test("rejects schema-less v2 context callbacks and inert registrations", () => {
    const schemaLess = `import { McpServer } from "@modelcontextprotocol/server";
import { exec } from "node:child_process";
const server = new McpServer({ name: "tools", version: "1.0.0" });
server.registerTool("ping", { description: "ping" }, async (ctx) => {
  exec(ctx.requestId);
  return { content: [] };
});
`;
    expect(records(schemaLess)).toEqual([]);
    expect(records(v2("    const unused = command;"))).toEqual([]);

    const legacySchemaLess = `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec } from "node:child_process";
const server = new McpServer({ name: "tools", version: "1.0.0" });
server.tool("ping", "no input", async (extra) => exec(extra.requestId));
`;
    expect(records(legacySchemaLess)).toEqual([]);
  });

  test("supports TypeScript callback annotations and shorthand inputSchema", () => {
    const source = `import { McpServer } from "@modelcontextprotocol/server";
import { exec } from "node:child_process";
const inputSchema = schema;
const server = new McpServer({ name: "tools", version: "1.0.0" });
server.registerTool("run", { inputSchema }, async ({ command }: { command: string }) => {
  exec(command);
  return { content: [] };
});
`;
    expect(records(source)).toHaveLength(1);
  });

  test("kills taint after a fixed overwrite before a sink", () => {
    expect(
      records(
        v2(
          '    let script = command;\n    script = "printf fixed";\n    exec(script);',
        ),
      ),
    ).toEqual([]);
    expect(
      records(v2('    command = "printf fixed";\n    exec(command);')),
    ).toEqual([]);
    expect(
      records(
        v2(
          '    let input = { command };\n    input = { command: "printf fixed" };\n    exec(input.command);',
        ),
      ),
    ).toEqual([]);
  });

  test("follows MCP input through same-file command and network helpers", () => {
    const command = `${v2("    return runCommand(command);")}
function runCommand(script: string) {
  return exec(script);
}
`;
    const commandRows = records(command);
    expect(commandRows).toHaveLength(1);
    expect(commandRows[0]?.frameworkModel.scope).toBe("same-file");
    expect(
      commandRows[0]?.frameworkModel.propagators.map(({ kind }) => kind),
    ).toContain("mcp-tool-helper-call");

    const network = `${v2("    return loadUrl(url);", "url: z.string()")}
async function loadUrl(target: string) {
  return fetch(target);
}
`;
    const networkRows = records(network);
    expect(networkRows).toHaveLength(1);
    expect(networkRows[0]?.frameworkModel.id).toBe("node-mcp-tool-ssrf");
    expect(networkRows[0]?.frameworkModel.scope).toBe("same-file");

    const evaluation = `${v2("    return evaluateExpression(command);")}
function evaluateExpression(expression: string) {
  return eval(expression);
}
`;
    const evaluationRows = records(evaluation);
    expect(evaluationRows).toHaveLength(1);
    expect(evaluationRows[0]?.frameworkModel.id).toBe(
      "node-mcp-tool-code-injection",
    );
    expect(evaluationRows[0]?.frameworkModel.propagators).toContainEqual(
      expect.objectContaining({
        kind: "mcp-tool-helper-call",
        symbol: "evaluateExpression",
      }),
    );
  });

  test("follows tool input through arrow and function-expression helpers", () => {
    const arrow = `${v2("    return runCommand(command);")}
const runCommand = async (script: string) => {
  return exec(script);
};
`;
    expect(records(arrow)[0]?.frameworkModel.propagators).toContainEqual(
      expect.objectContaining({ kind: "mcp-tool-helper-call" }),
    );

    const expression = `${v2("    return loadUrl(url);", "url: z.string()")}
const loadUrl = function (target: string) {
  return fetch(target);
};
`;
    expect(records(expression)[0]?.frameworkModel.id).toBe(
      "node-mcp-tool-ssrf",
    );
  });

  test("does not taint a helper sink through an unrelated argument", () => {
    const source = `${v2('    return runCommand("printf fixed", command);')}
function runCommand(script: string, data: string) {
  return exec(script);
}
`;
    expect(records(source)).toEqual([]);
  });

  test("rejects SDK, server, process, filesystem, and network lookalikes", () => {
    const wrongSdk = v2("    exec(command);").replace(
      "@modelcontextprotocol/server",
      "@example/modelcontextprotocol-server",
    );
    expect(records(wrongSdk)).toEqual([]);

    const wrongProcess = v2("    exec(command);").replace(
      '"node:child_process"',
      '"./child_process.js"',
    );
    expect(records(wrongProcess)).toEqual([]);

    const wrongFilesystem = v2("    return readFile(command);").replace(
      '"node:fs/promises"',
      '"./fs.js"',
    );
    expect(records(wrongFilesystem)).toEqual([]);

    const wrongServer = v2("    exec(command);").replace(
      "const server = new McpServer",
      "const server = new LocalServer",
    );
    expect(records(wrongServer)).toEqual([]);

    const shadowedFetch = `${v2("    return fetch(url);", "url: z.string()")}
function fetch(value) { return value; }
`;
    expect(records(shadowedFetch)).toEqual([]);
  });

  test("ignores comments, strings, tests, and unsupported callback references", () => {
    const inert = `import { McpServer } from "@modelcontextprotocol/server";
import { exec } from "node:child_process";
const server = new McpServer({ name: "tools", version: "1.0.0" });
// server.registerTool("run", { inputSchema: schema }, ({ command }) => exec(command));
const example = "server.registerTool('run', { inputSchema: schema }, ({ command }) => exec(command))";
`;
    expect(records(inert)).toEqual([]);
    expect(records(v2("    exec(command);"), "tests/server.ts")).toEqual([]);
    expect(records(v2("    exec(command);"), "src/server.test.ts")).toEqual([]);
  });

  test("integrates exact framework rows into the residual inventory", async () => {
    const root = await mkdtemp(join(tmpdir(), "copilot-security-node-mcp-"));
    try {
      await writeFile(
        join(root, "server.ts"),
        v2("    exec(command);"),
        "utf8",
      );
      const inventory = await buildResidualRiskInventory(root);
      const modelRows = inventory
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line) as NodeMcpToolRiskRecord)
        .filter(
          ({ frameworkModel }) =>
            frameworkModel?.id === "node-mcp-tool-command-injection",
        );
      expect(modelRows).toHaveLength(1);
      expect(modelRows[0]?.path).toBe("server.ts");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("requires model-specific MCP validation and attack-path closure", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-node-mcp-quality-repository-"),
    );
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-node-mcp-quality-scan-"),
    );
    try {
      const application = v2("    exec(command);");
      await writeFile(join(repository, "server.ts"), application, "utf8");
      const sinkLine =
        application
          .split(/\r?\n/u)
          .findIndex((line) => line.includes("exec(command)")) + 1;
      const finding = {
        occurrenceId: "occ_node_mcp_quality",
        taxonomy: { cwe: ["CWE-78"] },
        locations: [{ path: "server.ts", startLine: sinkLine, role: "sink" }],
        codeEvidence: [
          {
            id: "mcp-sink",
            path: "server.ts",
            startLine: sinkLine,
            code: "    exec(command);",
            explanation:
              "The registered tool callback passes its command value to a process API.",
            role: "sink",
          },
        ],
        validation: {
          summary: "Static review confirms a process call in the handler.",
          method: "source review and bounded negative control",
          exploitWitness: "An inert marker reaches the reviewed call boundary.",
          negativeControl: "A fixed literal does not carry client data.",
          evidence: ["mcp-sink"],
          counterEvidence: "Authentication and deployment remain unknown.",
          remainingUncertainty: "Runtime exposure was not established.",
        },
        attackPath: {
          summary: "An untrusted value may reach process execution.",
          dataflow: {
            source: "mcp-sink",
            sink: "mcp-sink",
            outcome: "process execution",
          },
          reachability: {
            attacker: "remote client",
            entrypoint: "tool invocation",
            outcome: "process execution",
          },
          brokenControls: ["Unrestricted shell command construction"],
          evidenceRefs: ["mcp-sink"],
        },
      };
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      const inventory = await buildResidualRiskInventory(repository);
      const incomplete = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      );
      const rows = incomplete.split("\n").map((line) => JSON.parse(line));
      expect(rows[1]).toMatchObject({
        findingId: "occ_node_mcp_quality",
        frameworkModelId: "node-mcp-tool-command-injection",
      });
      expect(rows[1]?.reasons).toContain(
        "missing_model_specific_validation_evidence",
      );
      expect(rows[1]?.reasons).toContain(
        "missing_model_specific_attack_path_evidence",
      );

      const closure = [
        "The MCP tool registerTool callback receives client-controlled tool input.",
        "That callback passes the value to node:child_process exec as a shell command.",
        "The bounded negative control uses a fixed executable with separate argv data.",
        "Authentication, transport exposure, and deployment reachability remain unknown.",
      ].join(" ");
      finding.validation.summary = closure;
      finding.attackPath.summary = closure;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      expect(
        await buildFindingQualityGapInventory(
          scanDirectory,
          repository,
          inventory,
        ),
      ).toBe("");
    } finally {
      await rm(repository, { recursive: true, force: true });
      await rm(scanDirectory, { recursive: true, force: true });
    }
  });

  test("requires filesystem-specific validation and attack-path closure", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-node-mcp-path-quality-repository-"),
    );
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-node-mcp-path-quality-scan-"),
    );
    try {
      const application = v2(
        '    return writeFile(command, "synthetic marker", "utf8");',
      );
      await writeFile(join(repository, "server.ts"), application, "utf8");
      const sinkLine =
        application
          .split(/\r?\n/u)
          .findIndex((line) => line.includes("writeFile(command")) + 1;
      const finding = {
        occurrenceId: "occ_node_mcp_path_quality",
        taxonomy: { cwe: ["CWE-22", "CWE-73"] },
        locations: [{ path: "server.ts", startLine: sinkLine, role: "sink" }],
        codeEvidence: [
          {
            id: "mcp-path-sink",
            path: "server.ts",
            startLine: sinkLine,
            code: '    return writeFile(command, "synthetic marker", "utf8");',
            explanation:
              "The registered tool callback passes its command value as the file path.",
            role: "sink",
          },
        ],
        validation: {
          summary: "Static review confirms a filesystem call in the handler.",
          method: "source review and bounded negative control",
          exploitWitness: "Synthetic data reaches the reviewed call boundary.",
          negativeControl: "A fixed literal does not carry client data.",
          evidence: ["mcp-path-sink"],
          counterEvidence: "Authentication and deployment remain unknown.",
          remainingUncertainty: "Runtime exposure was not established.",
        },
        attackPath: {
          summary: "An untrusted value may reach a filesystem operation.",
          dataflow: {
            source: "mcp-path-sink",
            sink: "mcp-path-sink",
            outcome: "file write",
          },
          reachability: {
            attacker: "MCP client",
            entrypoint: "tool invocation",
            outcome: "file write",
          },
          brokenControls: ["Unrestricted path selection"],
          evidenceRefs: ["mcp-path-sink"],
        },
      };
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      const inventory = await buildResidualRiskInventory(repository);
      const incomplete = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      );
      const rows = incomplete.split("\n").map((line) => JSON.parse(line));
      expect(rows[1]).toMatchObject({
        findingId: "occ_node_mcp_path_quality",
        frameworkModelId: "node-mcp-tool-path-traversal",
      });
      expect(rows[1]?.reasons).toContain(
        "missing_model_specific_validation_evidence",
      );
      expect(rows[1]?.reasons).toContain(
        "missing_model_specific_attack_path_evidence",
      );

      const closure = [
        "The MCP tool registerTool callback receives client-controlled tool input.",
        "node:fs writeFile consumes that input as its filesystem path argument.",
        "Path traversal can escape because no safe-root path confinement is present.",
        "The negative control fixes the operator path and uses tool input only as file contents.",
      ].join(" ");
      finding.validation.summary = closure;
      finding.attackPath.summary = closure;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      expect(
        await buildFindingQualityGapInventory(
          scanDirectory,
          repository,
          inventory,
        ),
      ).toBe("");
    } finally {
      await rm(repository, { recursive: true, force: true });
      await rm(scanDirectory, { recursive: true, force: true });
    }
  });

  test("requires interpreter-option validation and attack-path closure", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-node-mcp-argument-quality-repository-"),
    );
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-node-mcp-argument-quality-scan-"),
    );
    try {
      const application = `${v2("    return runCommand(command);").replace(
        'import { exec, execFile, spawn } from "node:child_process";',
        'import { exec, execFile, spawn } from "node:child_process";\nimport nodeProcess from "node:process";',
      )}
const runtime = nodeProcess.execPath;
function runCommand(value: string) {
  return execFile(runtime, ["-e", "process.stdout.write(process.argv[1])", value]);
}
`;
      await writeFile(join(repository, "server.ts"), application, "utf8");
      const sinkLine =
        application
          .split(/\r?\n/u)
          .findIndex((line) => line.includes("execFile(runtime")) + 1;
      const finding = {
        occurrenceId: "occ_node_mcp_argument_quality",
        taxonomy: { cwe: ["CWE-88", "CWE-94"] },
        locations: [{ path: "server.ts", startLine: sinkLine, role: "sink" }],
        codeEvidence: [
          {
            id: "mcp-argument-sink",
            path: "server.ts",
            startLine: sinkLine,
            code: application.split(/\r?\n/u)[sinkLine - 1],
            explanation:
              "The registered tool callback places command before an end-of-options boundary.",
            role: "sink",
          },
        ],
        validation: {
          summary: "Static review confirms a process call in the handler.",
          method: "source review and bounded inert option witness",
          exploitWitness: "The inert --version option reaches Node.",
          negativeControl: "An exact -- keeps the same value as data.",
          evidence: ["mcp-argument-sink"],
          counterEvidence: "The executable is fixed.",
          remainingUncertainty: "Deployment exposure was not established.",
        },
        attackPath: {
          summary: "An untrusted value may reach process execution.",
          dataflow: {
            source: "mcp-argument-sink",
            sink: "mcp-argument-sink",
            outcome: "interpreter option",
          },
          reachability: {
            attacker: "MCP client",
            entrypoint: "tool invocation",
            outcome: "code execution",
          },
          brokenControls: ["Missing end-of-options boundary"],
          evidenceRefs: ["mcp-argument-sink"],
        },
      };
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      const inventory = await buildResidualRiskInventory(repository);
      const incomplete = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      );
      const rows = incomplete.split("\n").map((line) => JSON.parse(line));
      expect(rows[1]).toMatchObject({
        findingId: "occ_node_mcp_argument_quality",
        frameworkModelId: "node-mcp-tool-argument-injection",
      });
      expect(rows[1]?.reasons).toContain(
        "missing_model_specific_validation_evidence",
      );
      expect(rows[1]?.reasons).toContain(
        "missing_model_specific_attack_path_evidence",
      );

      const closure = [
        "The MCP tool registerTool callback receives client-controlled tool input.",
        "execFile launches process.execPath as the Node interpreter.",
        "No -- end-of-options token precedes input in the option region, enabling argument injection.",
        "CWE-88 and CWE-94 describe the interpreter-option code execution boundary.",
      ].join(" ");
      finding.validation.summary = closure;
      finding.attackPath.summary = closure;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      const missingHelper = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      );
      const helperRows = missingHelper
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line));
      expect(helperRows[1]?.missingValidationTextAnyOf).toContainEqual([
        "runCommand",
        "same-file helper",
        "helper call",
      ]);
      expect(helperRows[1]?.missingAttackPathTextAnyOf).toContainEqual([
        "runCommand",
        "same-file helper",
        "helper call",
      ]);
      expect(helperRows[1]?.missingValidationTextAnyOf).toContainEqual([
        "runtime=nodeProcess.execPath",
        "stable runtime alias",
        "process.execPath alias",
      ]);
      expect(helperRows[1]?.missingAttackPathTextAnyOf).toContainEqual([
        "runtime=nodeProcess.execPath",
        "stable runtime alias",
        "process.execPath alias",
      ]);
      expect(helperRows[1]?.missingValidationTextAnyOf).toContainEqual([
        "nodeProcess<-node:process",
        "node:process binding",
        "official process module",
      ]);
      expect(helperRows[1]?.missingAttackPathTextAnyOf).toContainEqual([
        "nodeProcess<-node:process",
        "node:process binding",
        "official process module",
      ]);

      const helperClosure = `${closure} The same-file helper call runCommand carries the value to the sink.`;
      finding.validation.summary = helperClosure;
      finding.attackPath.summary = helperClosure;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      const missingRuntimeAlias = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      );
      expect(missingRuntimeAlias).toContain("runtime=nodeProcess.execPath");
      expect(missingRuntimeAlias).toContain("nodeProcess<-node:process");

      const runtimeClosure = `${helperClosure} The stable runtime alias runtime=nodeProcess.execPath preserves the exact Node executable identity.`;
      finding.validation.summary = runtimeClosure;
      finding.attackPath.summary = runtimeClosure;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      const missingProcessBinding = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      );
      expect(missingProcessBinding).toContain("nodeProcess<-node:process");

      const completeClosure = `${runtimeClosure} The exact binding nodeProcess<-node:process comes from the official process module.`;
      finding.validation.summary = completeClosure;
      finding.attackPath.summary = completeClosure;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      expect(
        await buildFindingQualityGapInventory(
          scanDirectory,
          repository,
          inventory,
        ),
      ).toBe("");
    } finally {
      await rm(repository, { recursive: true, force: true });
      await rm(scanDirectory, { recursive: true, force: true });
    }
  });

  test("requires fork execArgv boundary and matched-control closure", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-node-mcp-fork-quality-repository-"),
    );
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-node-mcp-fork-quality-scan-"),
    );
    try {
      const application = `${v2("    return runFork(command);").replace(
        'import { exec, execFile, spawn } from "node:child_process";',
        'import { fork } from "node:child_process";',
      )}
function runFork(option: string) {
  return fork(new URL("./child.mjs", import.meta.url), [], { execArgv: [option] });
}
`;
      await writeFile(join(repository, "server.ts"), application, "utf8");
      const sourceLines = application.split(/\r?\n/u);
      const sinkLine =
        sourceLines.findIndex((line) => line.includes("return fork(")) + 1;
      const finding = {
        occurrenceId: "occ_node_mcp_fork_quality",
        taxonomy: { cwe: ["CWE-88", "CWE-94"] },
        locations: [{ path: "server.ts", startLine: sinkLine, role: "sink" }],
        codeEvidence: [
          {
            id: "mcp-fork-sink",
            path: "server.ts",
            startLine: sinkLine,
            code: sourceLines[sinkLine - 1],
            explanation:
              "The same-file helper places tool input in fork options.",
            role: "sink",
          },
        ],
        validation: {
          summary:
            "An MCP tool callback carries client-controlled tool input through runFork into child_process fork execArgv, enabling Node interpreter argument injection and CWE-88/CWE-94 code execution risk.",
          method: "source review and bounded inert runtime-option witness",
          exploitWitness: "A fixed option changes the child's stack limit.",
          negativeControl: "The same value is kept outside Node options.",
          evidence: ["mcp-fork-sink"],
          counterEvidence: "The forked module path remains fixed.",
          remainingUncertainty: "Deployment reachability remains unproved.",
        },
        attackPath: {
          summary:
            "An MCP tool callback carries client-controlled tool input through runFork into child_process fork execArgv, enabling Node interpreter argument injection and CWE-88/CWE-94 code execution risk.",
          dataflow: {
            source: "mcp-fork-sink",
            sink: "mcp-fork-sink",
            outcome: "Node interpreter option",
          },
          reachability: {
            attacker: "MCP client",
            entrypoint: "tool invocation",
            outcome: "code execution",
          },
          brokenControls: ["Tool input enters execArgv"],
          evidenceRefs: ["mcp-fork-sink"],
        },
      };
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      const inventory = await buildResidualRiskInventory(repository);
      const incomplete = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      );
      expect(incomplete).toContain("fork:options.execArgv");
      expect(incomplete).toContain("fixed execArgv");
      expect(incomplete).toContain(
        "missing_model_specific_validation_evidence",
      );
      expect(incomplete).toContain(
        "missing_model_specific_attack_path_evidence",
      );

      const closure =
        " The exact fork:options.execArgv edge places the value in options.execArgv. The matched control keeps fixed execArgv and passes the same value only as an ordinary child module argument.";
      finding.validation.summary += closure;
      finding.attackPath.summary += closure;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      expect(
        await buildFindingQualityGapInventory(
          scanDirectory,
          repository,
          inventory,
        ),
      ).toBe("");
    } finally {
      await rm(repository, { recursive: true, force: true });
      await rm(scanDirectory, { recursive: true, force: true });
    }
  });

  test("requires code-evaluation validation and attack-path closure", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-node-mcp-code-quality-repository-"),
    );
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-node-mcp-code-quality-scan-"),
    );
    try {
      const application = v2("    return eval(command);");
      await writeFile(join(repository, "server.ts"), application, "utf8");
      const sourceLines = application.split(/\r?\n/u);
      const sinkLine =
        sourceLines.findIndex((line) => line.includes("eval(command)")) + 1;
      const finding = {
        occurrenceId: "occ_node_mcp_code_quality",
        taxonomy: { cwe: ["CWE-94", "CWE-95"] },
        locations: [{ path: "server.ts", startLine: sinkLine, role: "sink" }],
        codeEvidence: [
          {
            id: "mcp-code-sink",
            path: "server.ts",
            startLine: sinkLine,
            code: sourceLines[sinkLine - 1],
            explanation:
              "The registered tool callback passes its command string to direct evaluation.",
            role: "sink",
          },
        ],
        validation: {
          summary: "Static review confirms an evaluation call in the handler.",
          method: "source review and bounded arithmetic witness",
          exploitWitness: "The fixed expression 6 * 7 evaluates to 42.",
          negativeControl: "A fixed arithmetic parser never evaluates source.",
          evidence: ["mcp-code-sink"],
          counterEvidence: "Deployment exposure remains unknown.",
          remainingUncertainty: "Runtime privileges were not established.",
        },
        attackPath: {
          summary: "An untrusted string may reach evaluation.",
          dataflow: {
            source: "mcp-code-sink",
            sink: "mcp-code-sink",
            outcome: "dynamic evaluation",
          },
          reachability: {
            attacker: "MCP client",
            entrypoint: "tool invocation",
            outcome: "in-process code execution",
          },
          brokenControls: ["No code/data boundary"],
          evidenceRefs: ["mcp-code-sink"],
        },
      };
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      const inventory = await buildResidualRiskInventory(repository);
      const incomplete = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      );
      const rows = incomplete
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line));
      expect(rows[1]).toMatchObject({
        findingId: "occ_node_mcp_code_quality",
        frameworkModelId: "node-mcp-tool-code-injection",
      });
      expect(rows[1]?.reasons).toContain(
        "missing_model_specific_validation_evidence",
      );
      expect(rows[1]?.reasons).toContain(
        "missing_model_specific_attack_path_evidence",
      );

      const closure = [
        "An MCP tool registerTool callback receives client-controlled tool input from a model invocation.",
        "Its inputSchema string schema proves shape and length but not an allowed arithmetic grammar.",
        "The live global eval treats the string as dynamic JavaScript source during code evaluation.",
        "CWE-94 and CWE-95 describe the resulting in-process code injection and code execution boundary.",
      ].join(" ");
      finding.validation.summary = closure;
      finding.attackPath.summary = closure;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      expect(
        await buildFindingQualityGapInventory(
          scanDirectory,
          repository,
          inventory,
        ),
      ).toBe("");

      const compiledApplication = v2(
        "    const operation = new Function(command);\n    return operation();",
      );
      await writeFile(
        join(repository, "server.ts"),
        compiledApplication,
        "utf8",
      );
      const compiledLines = compiledApplication.split(/\r?\n/u);
      const executionLine =
        compiledLines.findIndex((line) => line.includes("return operation()")) +
        1;
      finding.locations = [
        { path: "server.ts", startLine: executionLine, role: "sink" },
      ];
      finding.codeEvidence = [
        {
          id: "mcp-code-sink",
          path: "server.ts",
          startLine: executionLine,
          code: compiledLines[executionLine - 1] ?? "",
          explanation:
            "The registered tool invokes the Function compiled from its input.",
          role: "sink",
        },
      ];
      finding.validation.summary = closure;
      finding.attackPath.summary = closure;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      const compiledInventory = await buildResidualRiskInventory(repository);
      const missingLifecycle = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        compiledInventory,
      );
      expect(missingLifecycle).toContain(
        "missing_model_specific_validation_evidence",
      );
      expect(missingLifecycle).toContain(
        "missing_model_specific_attack_path_evidence",
      );

      const lifecycleClosure = [
        "An MCP tool registerTool callback receives client-controlled tool input from a model invocation.",
        "Its inputSchema string schema proves shape but not an allowed arithmetic grammar.",
        "The live global Function constructor compiles that dynamic JavaScript source.",
        "The explicit operation call is an invoked compiled function execution step.",
        "CWE-94 and CWE-95 describe the in-process code injection and code execution boundary.",
      ].join(" ");
      finding.validation.summary = lifecycleClosure;
      finding.attackPath.summary = lifecycleClosure;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      expect(
        await buildFindingQualityGapInventory(
          scanDirectory,
          repository,
          compiledInventory,
        ),
      ).toBe("");

      const workerApplication = `${'import { Worker } from "node:worker_threads";\n'}${v2(
        "    return new Worker(command, { eval: true });",
      )}`;
      await writeFile(join(repository, "server.ts"), workerApplication, "utf8");
      const workerLines = workerApplication.split(/\r?\n/u);
      const workerLine =
        workerLines.findIndex((line) => line.includes("new Worker(command")) +
        1;
      finding.locations = [
        { path: "server.ts", startLine: workerLine, role: "sink" },
      ];
      finding.codeEvidence = [
        {
          id: "mcp-code-sink",
          path: "server.ts",
          startLine: workerLine,
          code: workerLines[workerLine - 1] ?? "",
          explanation:
            "The registered tool starts a worker whose source is its input.",
          role: "sink",
        },
      ];
      finding.validation.summary = lifecycleClosure;
      finding.attackPath.summary = lifecycleClosure;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      const workerInventory = await buildResidualRiskInventory(repository);
      const missingWorkerLifecycle = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        workerInventory,
      );
      expect(missingWorkerLifecycle).toContain(
        "missing_model_specific_validation_evidence",
      );
      expect(missingWorkerLifecycle).toContain(
        "missing_model_specific_attack_path_evidence",
      );

      finding.validation.summary = [
        "An MCP tool registerTool callback receives client-controlled tool input from a model invocation through an inputSchema string schema.",
        "Worker eval mode starts JavaScript source code evaluation once the worker is online and reaches code injection.",
        "The same-file evaluateExpression helper call preserves the input.",
      ].join(" ");
      finding.attackPath.summary = [
        "An MCP tool registerTool callback receives client-controlled tool input from a model invocation through an inputSchema string schema.",
        "The live node:worker_threads new Worker constructor receives the JavaScript source through the same-file evaluateExpression helper call.",
        "Literal eval: true causes worker startup code evaluation once the worker is online at an explicit execution step (CWE-94).",
      ].join(" ");
      finding.attackPath.reachability.outcome = "dynamic evaluation";
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      const missingWorkerBindingAndImpact =
        await buildFindingQualityGapInventory(
          scanDirectory,
          repository,
          workerInventory,
        );
      expect(missingWorkerBindingAndImpact).toContain(
        "missing_model_specific_validation_evidence",
      );
      expect(missingWorkerBindingAndImpact).toContain(
        '"worker_threads","Worker constructor","new Worker"',
      );
      expect(missingWorkerBindingAndImpact).toContain(
        "missing_model_specific_attack_path_evidence",
      );
      expect(missingWorkerBindingAndImpact).toContain(
        '"code execution","code injection"',
      );

      const workerClosure = [
        "An MCP tool registerTool callback receives client-controlled tool input from a model invocation.",
        "Its inputSchema string schema proves shape but not an allowed arithmetic grammar.",
        "The live node:worker_threads new Worker constructor receives that input as argument-zero JavaScript source with literal eval: true.",
        "Worker eval mode starts code evaluation once the worker is online, providing the explicit worker startup execution step.",
        "CWE-94 and CWE-95 describe the resulting in-process code injection and code execution boundary.",
      ].join(" ");
      finding.validation.summary = workerClosure;
      finding.attackPath.summary = workerClosure;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      expect(
        await buildFindingQualityGapInventory(
          scanDirectory,
          repository,
          workerInventory,
        ),
      ).toBe("");
    } finally {
      await rm(repository, { recursive: true, force: true });
      await rm(scanDirectory, { recursive: true, force: true });
    }
  });

  test("requires built-in SQLite validation and attack-path closure", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-node-mcp-sql-quality-repository-"),
    );
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-node-mcp-sql-quality-scan-"),
    );
    try {
      const application = sqliteV2(
        "    return recordLookup(command);",
        'import { DatabaseSync } from "node:sqlite";\nfunction recordLookup(sql) {\n  return database.exec(sql);\n}',
      );
      await writeFile(join(repository, "server.ts"), application, "utf8");
      const sourceLines = application.split(/\r?\n/u);
      const sinkLine =
        sourceLines.findIndex((line) => line.includes("database.exec(sql)")) +
        1;
      const finding = {
        occurrenceId: "occ_node_mcp_sql_quality",
        taxonomy: { cwe: ["CWE-89"] },
        locations: [{ path: "server.ts", startLine: sinkLine, role: "sink" }],
        codeEvidence: [
          {
            id: "mcp-sql-sink",
            path: "server.ts",
            startLine: sinkLine,
            code: sourceLines[sinkLine - 1],
            explanation: "The registered tool input reaches a database call.",
            role: "sink",
          },
        ],
        validation: {
          summary: "Static review confirms SQL execution in a helper.",
          method: "source review and bounded in-memory database witness",
          exploitWitness: "A fixed inert value changes the observed row count.",
          negativeControl: "A fixed query binds the same value separately.",
          evidence: ["mcp-sql-sink"],
          counterEvidence: "Deployment database privileges remain unknown.",
          remainingUncertainty: "Persistent deployment data was not tested.",
        },
        attackPath: {
          summary: "An untrusted value may reach a database operation.",
          dataflow: {
            source: "mcp-sql-sink",
            sink: "mcp-sql-sink",
            outcome: "database query execution",
          },
          reachability: {
            attacker: "MCP client",
            entrypoint: "tool invocation",
            outcome: "database integrity change",
          },
          brokenControls: ["No SQL grammar boundary"],
          evidenceRefs: ["mcp-sql-sink"],
        },
      };
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      const inventory = await buildResidualRiskInventory(repository);
      const incomplete = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      );
      expect(incomplete).toContain("occ_node_mcp_sql_quality");
      expect(incomplete).toContain("node-mcp-tool-sql-injection");
      expect(incomplete).toContain(
        "missing_model_specific_validation_evidence",
      );
      expect(incomplete).toContain(
        "missing_model_specific_attack_path_evidence",
      );

      const closure = [
        "An MCP tool registerTool callback receives client-controlled tool input from a model tool invocation.",
        "Its inputSchema string schema proves shape but does not constrain SQL grammar or query structure.",
        "The term crosses the same-file recordLookup helper into the official node:sqlite built-in SQLite DatabaseSync instance database=new DatabaseSync.",
        "DatabaseSync.exec executes database.exec:sql[0] SQL text in argument zero, where interpolation permits SQL injection.",
        "A fixed prepared statement placeholder with a bound parameter is the matched negative control.",
        "CWE-89 describes the resulting database integrity risk while deployment confidentiality and privileges remain unproved.",
      ].join(" ");
      finding.validation.summary = closure;
      finding.attackPath.summary = closure;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      expect(
        await buildFindingQualityGapInventory(
          scanDirectory,
          repository,
          inventory,
        ),
      ).toBe("");

      const preparedApplication = sqliteV2(
        "    return runPrepared(command);",
        'import { DatabaseSync } from "node:sqlite";\nfunction runPrepared(sql) {\n  const statement = database.prepare(sql);\n  return statement.get();\n}',
      );
      await writeFile(
        join(repository, "server.ts"),
        preparedApplication,
        "utf8",
      );
      const preparedLines = preparedApplication.split(/\r?\n/u);
      const preparedSinkLine =
        preparedLines.findIndex((line) => line.includes("statement.get()")) + 1;
      finding.occurrenceId = "occ_node_mcp_prepared_sql_quality";
      finding.locations[0]!.startLine = preparedSinkLine;
      finding.codeEvidence[0]!.startLine = preparedSinkLine;
      finding.codeEvidence[0]!.code = preparedLines[preparedSinkLine - 1];
      finding.validation.summary =
        "Static review confirms preparation and later statement execution.";
      finding.attackPath.summary =
        "An untrusted value may reach a prepared database operation.";
      const preparedInventory = await buildResidualRiskInventory(repository);
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      const preparedIncomplete = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        preparedInventory,
      );
      expect(preparedIncomplete).toContain("occ_node_mcp_prepared_sql_quality");
      expect(preparedIncomplete).toContain("database.prepare:sql[0]");
      expect(preparedIncomplete).toContain("statement.get:prepared-sql[0]");

      const preparedClosure = [
        "An MCP tool registerTool callback receives client-controlled tool input from a model tool invocation.",
        "Its inputSchema string schema proves shape but does not constrain SQL grammar or query structure.",
        "The command crosses the same-file runPrepared helper into the official node:sqlite built-in SQLite DatabaseSync instance database=new DatabaseSync.",
        "DatabaseSync.prepare receives database.prepare:sql[0] SQL text in argument zero, where interpolation changes query structure.",
        "The exact returned StatementSync executes through StatementSync.get at statement.get:prepared-sql[0].",
        "A fixed prepared statement placeholder with a bound parameter is the matched negative control.",
        "CWE-89 describes an unauthorized database confidentiality read while deployment privileges remain unproved.",
      ].join(" ");
      finding.validation.summary = preparedClosure;
      finding.attackPath.summary = preparedClosure;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      expect(
        await buildFindingQualityGapInventory(
          scanDirectory,
          repository,
          preparedInventory,
        ),
      ).toBe("");
    } finally {
      await rm(repository, { recursive: true, force: true });
      await rm(scanDirectory, { recursive: true, force: true });
    }
  });

  test("requires regular-expression validation and attack-path closure", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-node-mcp-regex-quality-repository-"),
    );
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "copilot-security-node-mcp-regex-quality-scan-"),
    );
    try {
      const application = v2(
        '    const expression = new RegExp(pattern, "u");\n    return expression.test(text);',
        "pattern: z.string().min(1).max(64), text: z.string().max(4096)",
      );
      await writeFile(join(repository, "server.ts"), application, "utf8");
      const sourceLines = application.split(/\r?\n/u);
      const sinkLine =
        sourceLines.findIndex((line) => line.includes("expression.test")) + 1;
      const finding = {
        occurrenceId: "occ_node_mcp_regex_quality",
        taxonomy: { cwe: ["CWE-400", "CWE-730"] },
        locations: [{ path: "server.ts", startLine: sinkLine, role: "sink" }],
        codeEvidence: [
          {
            id: "mcp-regex-sink",
            path: "server.ts",
            startLine: sinkLine,
            code: sourceLines[sinkLine - 1],
            explanation:
              "The registered tool callback executes a constructed expression.",
            role: "sink",
          },
        ],
        validation: {
          summary:
            "Static review confirms a regular expression in the handler.",
          method: "source review and bounded metacharacter witness",
          exploitWitness:
            "A short alternation changes the selected diagnostics.",
          negativeControl: "A fixed-pattern map accepts only operator names.",
          evidence: ["mcp-regex-sink"],
          counterEvidence: "Deployment exposure remains unknown.",
          remainingUncertainty: "Runtime concurrency was not established.",
        },
        attackPath: {
          summary: "An untrusted pattern may reach expression execution.",
          dataflow: {
            source: "mcp-regex-sink",
            sink: "mcp-regex-sink",
            outcome: "regular-expression evaluation",
          },
          reachability: {
            attacker: "MCP client",
            entrypoint: "tool invocation",
            outcome: "synchronous denial of service",
          },
          brokenControls: ["No regular-expression grammar boundary"],
          evidenceRefs: ["mcp-regex-sink"],
        },
      };
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      const inventory = await buildResidualRiskInventory(repository);
      const incomplete = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      );
      const rows = incomplete
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line));
      expect(rows[1]).toMatchObject({
        findingId: "occ_node_mcp_regex_quality",
        frameworkModelId: "node-mcp-tool-regex-injection",
      });
      expect(rows[1]?.reasons).toContain(
        "missing_model_specific_validation_evidence",
      );
      expect(rows[1]?.reasons).toContain(
        "missing_model_specific_attack_path_evidence",
      );

      const closure = [
        "An MCP tool registerTool callback receives client-controlled tool input from a model invocation.",
        "Its inputSchema string schema proves shape and length but does not constrain regular-expression pattern grammar or metacharacters.",
        "The pattern property reaches global RegExp construction and actual test execution against the client-controlled text match subject.",
        "The subject input length permits meaningful nonlinear matching work on Node's shared event loop.",
        "CWE-400 and CWE-730 describe ReDoS and the resulting synchronous denial of service for other clients.",
      ].join(" ");
      finding.validation.summary = closure;
      finding.attackPath.summary = closure;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
        "utf8",
      );
      expect(
        await buildFindingQualityGapInventory(
          scanDirectory,
          repository,
          inventory,
        ),
      ).toBe("");
    } finally {
      await rm(repository, { recursive: true, force: true });
      await rm(scanDirectory, { recursive: true, force: true });
    }
  });

  test("gives validation exact MCP source and sink boundaries", () => {
    const prompt = scanQualityGatePrompt(
      "{}",
      JSON.stringify({
        frameworkModel: {
          id: "node-mcp-tool-command-injection",
          source: { kind: "mcp-tool-input" },
          sink: { kind: "mcp-tool-shell-command" },
        },
      }),
      "[]",
    );
    expect(prompt).toContain("For node-mcp-tool-command-injection");
    expect(prompt).toContain("node-mcp-tool-argument-injection");
    expect(prompt).toContain("node-mcp-tool-code-injection");
    expect(prompt).toContain("node-mcp-tool-sql-injection");
    expect(prompt).toContain("node-mcp-tool-regex-injection");
    expect(prompt).toContain("node-mcp-tool-path-traversal");
    expect(prompt).toContain("schema-less callback receives context");
    expect(prompt).toContain("fixed executable plus separate argv data");
    expect(prompt).toContain("process.execPath");
    expect(prompt).toContain("stable process.execPath alias");
    expect(prompt).toContain("runtime-alias symbol");
    expect(prompt).toContain("local process shadow");
    expect(prompt).toContain("mcp-tool-node-process-binding");
    expect(prompt).toContain("official node:process");
    expect(prompt).toContain("official process module");
    expect(prompt).toContain("exact binding symbol");
    expect(prompt).toContain("mcp-tool-fork-exec-argv");
    expect(prompt).toContain("object-literal options argument");
    expect(prompt).toContain("fork:options.execArgv symbol");
    expect(prompt).toContain("ordinary module arguments");
    expect(prompt).toContain("--stack-trace-limit=77");
    expect(prompt).toContain("end-of-options");
    expect(prompt).toContain("node:vm is not a security mechanism");
    expect(prompt).toContain("inert construction");
    expect(prompt).toContain("construction-lifecycle rows");
    expect(prompt).toContain("linkRequests then instantiate then evaluate");
    expect(prompt).toContain("unawaited legacy linking");
    expect(prompt).toContain("fixed side-effect-free arithmetic");
    expect(prompt).toContain("DatabaseSync.exec");
    expect(prompt).toContain("DatabaseSync.prepare plus execution");
    expect(prompt).toContain("preparation alone is not execution");
    expect(prompt).toContain("StatementSync run, get, all, or iterate");
    expect(prompt).toContain(
      "do not infer exec-style multi-statement behavior",
    );
    expect(prompt).toContain("disposable in-memory database");
    expect(prompt).toContain("actual test/exec execution");
    expect(prompt).toContain("inert constructor-only code");
    expect(prompt).toContain("small fixed server-owned string");
    expect(prompt).toContain("match-subject provenance and work bound");
    expect(prompt).toContain("fixed-pattern control");
    expect(prompt).toContain("never execute a catastrophic-backtracking");
    expect(prompt).toContain("path-bearing Node fs");
    expect(prompt).toContain("path.join or path.resolve alone");
    expect(prompt).toContain("request body or same-host path");
    expect(prompt).toContain("disposable temporary tree");
    expect(prompt).toContain("disposable loopback endpoint");
    expect(prompt).toContain("CWE-22/CWE-73");
    expect(prompt).toContain("CWE-88/CWE-94");
    expect(prompt).toContain("CWE-94/CWE-95");
    expect(prompt).toContain("CWE-400/CWE-730");
  });
});
