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
    propagators: Array<{
      kind: string;
      path: string;
      line: number;
      symbol?: string;
    }>;
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

function promptRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-copilot-system-prompt-injection",
    );
}

async function fixtureRecords(id: string): Promise<FrameworkRecord[]> {
  return promptRecords(
    await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id)),
  );
}

async function repositoryRecords(
  files: Readonly<Record<string, string>>,
): Promise<FrameworkRecord[]> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-prompt-model-"),
  );
  temporaryPaths.push(repository);
  for (const [path, source] of Object.entries(files)) {
    const destination = join(repository, path);
    await mkdir(resolve(destination, ".."), { recursive: true });
    await writeFile(destination, source);
  }
  return promptRecords(await buildResidualRiskInventory(repository));
}

function sameFileSource(config: string, tail = ""): string {
  return `import { CopilotClient } from "@github/copilot-sdk";
const client = new CopilotClient();
export async function handle(request) {
  const persona = String(request.query.persona ?? "");
  const session = await client.createSession(${config});
  ${tail || 'return session.sendAndWait({ prompt: "hello" });'}
}
`;
}

describe("GitHub Copilot SDK system-prompt-injection model", () => {
  test("keeps the exploit and user-message control under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-copilot-prompt-injection-manifest.json"),
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
      "javascript-copilot-system-prompt-injection",
      "javascript-safe-copilot-user-message",
    ]);
    expect(manifest.cases[0]?.findingsPaths).toHaveLength(1);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-1427"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.findingsPaths).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves the exact two-hop trusted-instruction path", async () => {
    const vulnerable = await fixtureRecords(
      "javascript-copilot-system-prompt-injection",
    );
    const safe = await fixtureRecords("javascript-safe-copilot-user-message");
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      id: "node-copilot-system-prompt-injection",
      scope: "cross-file-multi-hop-wrapper",
      source: {
        kind: "http-request-field",
        path: "src/server.js",
        line: 4,
      },
      sink: {
        kind: "copilot-system-message-content",
        path: "src/session.js",
        line: 9,
        cweIds: ["CWE-1427"],
      },
      candidateControls: [],
    });
    expect(
      vulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "relative-module-import",
      "wrapper-call-argument",
      "wrapper-parameter",
      "relative-module-import",
      "wrapper-call-argument",
      "wrapper-parameter",
    ]);
    expect(safe).toEqual([]);
  });

  test("models every current trusted Copilot SDK instruction surface", async () => {
    const records = await repositoryRecords({
      "content.ts": sameFileSource(`{
    systemMessage: { mode: "append", content: \`Persona: \${persona}\` },
  }`),
      "section.ts": sameFileSource(`{
    systemMessage: {
      mode: "customize",
      sections: { guidelines: { action: "append", content: persona } },
    },
  }`),
      "transform.ts": sameFileSource(`{
    systemMessage: {
      mode: "customize",
      sections: { safety: { action: current => current + persona } },
    },
  }`),
      "agent-prompt.ts": sameFileSource(`{
    customAgents: [{ name: "worker", prompt: persona }],
  }`),
      "agent-description.ts": sameFileSource(`{
    customAgents: [{ name: "worker", description: persona, prompt: "Work safely." }],
  }`),
      "tool.ts": sameFileSource(`{
    tools: [{ name: "lookup", description: persona, handler: async () => "ok" }],
  }`),
      "unknown-section.ts": sameFileSource(`{
    systemMessage: {
      mode: "customize",
      sections: { future_section: { action: "append", content: persona } },
    },
  }`),
      "resume.ts": `import { CopilotClient } from "@github/copilot-sdk";
const client = new CopilotClient();
export async function handle(request) {
  const persona = request.query.persona;
  return client.resumeSession("workspace", {
    systemMessage: { mode: "replace", content: persona },
  });
}
`,
    });
    expect(records).toHaveLength(8);
    expect(
      records.map((record) => record.frameworkModel?.sink.kind).sort(),
    ).toEqual([
      "copilot-custom-agent-description",
      "copilot-custom-agent-prompt",
      "copilot-system-message-content",
      "copilot-system-message-content",
      "copilot-system-message-section-content",
      "copilot-system-message-section-content",
      "copilot-system-message-section-transform",
      "copilot-tool-description",
    ]);
    for (const record of records) {
      expect(record.frameworkModel).toMatchObject({
        id: "node-copilot-system-prompt-injection",
        scope: "same-file",
        sink: { cweIds: ["CWE-1427"] },
      });
    }
  });

  test("follows named configs, exact ESM and CommonJS bindings, and eight value aliases", async () => {
    const aliases = Array.from(
      { length: 8 },
      (_, index) =>
        `  const alias${index + 1} = ${index === 0 ? "persona" : `alias${index}`};`,
    ).join("\n");
    const records = await repositoryRecords({
      "aliases.ts": `import { CopilotClient as SecurityClient } from "@github/copilot-sdk";
const client = new SecurityClient();
export async function handle(request) {
  const persona = request.query.persona;
${aliases}
  const systemMessage = { mode: "append", content: alias8 };
  const config = { systemMessage };
  return client.createSession(config);
}
`,
      "commonjs.cjs": `const { CopilotClient: SecurityClient } = require("@github/copilot-sdk");
const client = new SecurityClient();
exports.handle = function handle(request) {
  return client.createSession({
    systemMessage: { mode: "append", content: request.query.persona },
  });
};
`,
    });
    expect(records).toHaveLength(2);
    expect(
      records.every(
        (record) =>
          record.frameworkModel?.sink.kind === "copilot-system-message-content",
      ),
    ).toBeTrue();
  });

  test("rejects a ninth alias and every unproven or user-message-only path", async () => {
    const records = await repositoryRecords({
      "user-message.ts": sameFileSource(
        `{
    systemMessage: { content: "Answer workspace questions without tools." },
  }`,
        "return session.sendAndWait({ prompt: persona });",
      ),
      "wrong-package.ts": `import { CopilotClient } from "example.com/copilot-sdk";
const client = new CopilotClient();
export function handle(request) {
  return client.createSession({ systemMessage: { content: request.query.persona } });
}
`,
      "default-import.ts": `import CopilotClient from "@github/copilot-sdk";
const client = new CopilotClient();
export function handle(request) {
  return client.createSession({ systemMessage: { content: request.query.persona } });
}
`,
      "namespace-import.ts": `import * as sdk from "@github/copilot-sdk";
const client = new sdk.CopilotClient();
export function handle(request) {
  return client.createSession({ systemMessage: { content: request.query.persona } });
}
`,
      "unrelated-client.ts": `import { CopilotClient } from "@github/copilot-sdk";
const actual = new CopilotClient();
const client = { createSession() {} };
export function handle(request) {
  return client.createSession({ systemMessage: { content: request.query.persona } });
}
`,
      "reassigned-client.ts": `import { CopilotClient } from "@github/copilot-sdk";
let client = new CopilotClient();
export function handle(request) {
  client = request.client;
  return client.createSession({ systemMessage: { content: request.query.persona } });
}
`,
      "unknown-remove.ts": sameFileSource(`{
    systemMessage: {
      mode: "customize",
      sections: { attackerChosen: { action: "remove", content: persona } },
    },
  }`),
      "known-remove.ts": sameFileSource(`{
    systemMessage: {
      mode: "customize",
      sections: { safety: { action: "remove", content: persona } },
    },
  }`),
      "known-preserve.ts": sameFileSource(`{
    systemMessage: {
      mode: "customize",
      sections: { safety: { action: "preserve", content: persona } },
    },
  }`),
      "named-remove.ts": `import { CopilotClient } from "@github/copilot-sdk";
const client = new CopilotClient();
const remove = "remove";
export function handle(request) {
  return client.createSession({
    systemMessage: {
      mode: "customize",
      sections: { safety: { action: remove, content: request.query.persona } },
    },
  });
}
`,
      "non-inferred-agent-description.ts": sameFileSource(`{
    customAgents: [{ name: "manual", description: persona, prompt: "Fixed.", infer: false }],
  }`),
      "named-non-inferred-agent-description.ts": `import { CopilotClient } from "@github/copilot-sdk";
const client = new CopilotClient();
const visibleToModel = false;
export function handle(request) {
  return client.createSession({
    customAgents: [{ name: "manual", description: request.query.persona, prompt: "Fixed.", infer: visibleToModel }],
  });
}
`,
      "command-description.ts": sameFileSource(`{
    commands: [{ name: "lookup", description: persona, handler: async () => "ok" }],
  }`),
      "agent-name.ts": sameFileSource(`{
    customAgents: [{ name: persona, prompt: "Review code safely." }],
  }`),
      "fixed-tool.ts": sameFileSource(`{
    tools: [{ name: "lookup", description: "Look up a record", handler: async () => persona }],
  }`),
      "ninth-alias.ts": `import { CopilotClient } from "@github/copilot-sdk";
const client = new CopilotClient();
export function handle(request) {
  const value0 = request.query.persona;
${Array.from({ length: 9 }, (_, index) => `  const value${index + 1} = value${index};`).join("\n")}
  return client.createSession({ systemMessage: { content: value9 } });
}
`,
      "pseudo-flow.ts": `import { CopilotClient } from "@github/copilot-sdk";
const client = new CopilotClient();
// client.createSession({ systemMessage: { content: request.query.persona } });
export function fixed(request) {
  const example = "client.createSession({ systemMessage: { content: request.query.persona } })";
  return client.createSession({ systemMessage: { content: "Fixed." }, metadata: example });
}
`,
    });
    expect(records).toEqual([]);
  });

  test("retains an exact fixed-value allowlist as reviewer counterevidence", async () => {
    const records = await repositoryRecords({
      "allowlist.ts": `import { CopilotClient } from "@github/copilot-sdk";
const client = new CopilotClient();
const allowedPrompts = { reviewer: "Review code.", teacher: "Explain code." };
export function handle(request) {
  const persona = request.query.persona;
  if (!Object.hasOwn(allowedPrompts, persona)) return undefined;
  const selected = allowedPrompts[persona];
  return client.createSession({ systemMessage: { content: selected } });
}
`,
    });
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "fixed-trusted-prompt-allowlist",
      path: "allowlist.ts",
      line: 6,
    });
  });

  test("gives the reviewer exact hierarchy and impact guidance", () => {
    const prompt = scanQualityGatePrompt("inventory-row");
    expect(prompt).toContain("For node-copilot-system-prompt-injection rows");
    expect(prompt).toContain("@github/copilot-sdk named CopilotClient import");
    expect(prompt).toContain("systemMessage.content");
    expect(prompt).toContain("customAgents prompt or description");
    expect(prompt).toContain("unknown customize-section names");
    expect(prompt).toContain("session.send or sendAndWait's prompt field");
    expect(prompt).toContain("CWE-1427");
    expect(prompt).toContain("MCP servers");
    expect(prompt).toContain(
      "command descriptions shown only in completion UI",
    );
  });
});
