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
import * as https from "node:https";
import axios from "axios";
import { z } from "zod";

const server = new McpServer({ name: "tools", version: "1.0.0" });
server.registerTool(
  "operate",
  { inputSchema: z.object({ ${input} }) },
  async ({ command, url }) => {
${body}
    return { content: [] };
  },
);
`;
}

function records(source: string, path = sourcePath): NodeMcpToolRiskRecord[] {
  return nodeMcpToolRiskRecords(path, source.split(/\r?\n/u), source);
}

describe("Node MCP tool-input security model", () => {
  test("keeps both executable exploit/control pairs under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-mcp-tool-security-manifest.json"),
        "utf8",
      ),
    ) as {
      schemaVersion: string;
      thresholds: Record<string, number>;
      cases: Array<{ id: string; expected: unknown[] }>;
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
      "node-mcp-v2-ssrf",
      "node-mcp-v2-fixed-destination",
    ]);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(manifest.cases[2]?.expected).toHaveLength(1);
    expect(manifest.cases[3]?.expected).toEqual([]);

    for (const [index, modelId] of [
      [0, "node-mcp-tool-command-injection"],
      [2, "node-mcp-tool-ssrf"],
    ] as const) {
      const vulnerable = await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", manifest.cases[index]!.id),
      );
      expect(vulnerable).toContain(`\"id\":\"${modelId}\"`);
      expect(vulnerable).toContain("mcp-tool-helper-call");
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

  test("rejects SDK, server, process, and network lookalikes", () => {
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
    expect(prompt).toContain("schema-less callback receives context");
    expect(prompt).toContain("fixed executable plus separate argv data");
    expect(prompt).toContain("request body or same-host path");
    expect(prompt).toContain("disposable loopback endpoint");
  });
});
