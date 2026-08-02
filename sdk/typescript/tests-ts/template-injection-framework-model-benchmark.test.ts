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

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const caseIds = [
  "javascript-cross-file-template-injection",
  "javascript-cross-file-safe-template",
  "python-cross-file-template-injection",
  "python-cross-file-safe-template",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function parseRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord);
}

function templateRecord(
  inventory: string,
  scope: string,
): FrameworkRecord | undefined {
  return parseRecords(inventory).find((record) => {
    const model = record.frameworkModel;
    return (
      model !== undefined &&
      [
        "node-http-template-injection",
        "python-web-template-injection",
      ].includes(model.id) &&
      model.scope === scope
    );
  });
}

describe("template-injection framework-model effectiveness benchmark", () => {
  test("keeps paired Node and Python cases under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "template-injection-framework-manifest.json"),
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
        expect(expected.cwe).toEqual(["CWE-1336"]);
        expect(expected.requireValidation).toBeTrue();
        expect(expected.requireAttackPath).toBeTrue();
        expect(expected.requireCodeEvidence).toBeTrue();
      }
    }
  });

  test("distinguishes template source from escaped render data", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-template-argument-roles-"),
    );
    temporaryPaths.push(repository);
    await writeFile(
      join(repository, "vulnerable.js"),
      [
        'import pug from "pug";',
        "export function preview(request) {",
        "  const templateSource = request.body.template;",
        "  return pug.compile(templateSource)({});",
        "}",
        "",
      ].join("\n"),
    );
    await writeFile(
      join(repository, "safe.js"),
      [
        'import pug from "pug";',
        "export function preview(request) {",
        "  const name = request.body.name;",
        '  const render = pug.compile("p= name");',
        "  return render({ name });",
        "}",
        "",
      ].join("\n"),
    );
    await writeFile(
      join(repository, "vulnerable.py"),
      [
        "from flask import request, render_template_string",
        "",
        "def preview():",
        '    template_source = request.form.get("template", "")',
        "    return render_template_string(template_source)",
        "",
      ].join("\n"),
    );
    await writeFile(
      join(repository, "safe.py"),
      [
        "from flask import request, render_template_string",
        "",
        "def preview():",
        '    name = request.form.get("name", "")',
        '    return render_template_string("<p>{{ name }}</p>", name=name)',
        "",
      ].join("\n"),
    );
    await writeFile(
      join(repository, "dynamic-literal.js"),
      [
        'import pug from "pug";',
        "export function preview(request) {",
        "  const name = request.body.name;",
        "  return pug.compile(`p ${name}`)({});",
        "}",
        "",
      ].join("\n"),
    );
    await writeFile(
      join(repository, "dynamic_literal.py"),
      [
        "from flask import request, render_template_string",
        "",
        "def preview():",
        '    name = request.form.get("name", "")',
        '    return render_template_string(f"<p>{name}</p>")',
        "",
      ].join("\n"),
    );

    const inventory = await buildResidualRiskInventory(repository);
    const records = parseRecords(inventory).filter((record) =>
      record.frameworkModel?.id.endsWith("template-injection"),
    );
    expect(records).toHaveLength(6);

    const vulnerableJavascript = records.find(
      ({ path }) => path === "vulnerable.js",
    );
    expect(vulnerableJavascript?.frameworkModel).toMatchObject({
      id: "node-http-template-injection",
      source: { path: "vulnerable.js", line: 3 },
      sink: {
        path: "vulnerable.js",
        line: 4,
        cweIds: ["CWE-1336"],
      },
      candidateControls: [],
    });

    const safeJavascript = records.find(({ path }) => path === "safe.js");
    expect(safeJavascript?.frameworkModel?.candidateControls).toContainEqual({
      kind: "fixed-template-with-data-context",
      path: "safe.js",
      line: 4,
    });

    const vulnerablePython = records.find(
      ({ path }) => path === "vulnerable.py",
    );
    expect(vulnerablePython?.frameworkModel).toMatchObject({
      id: "python-web-template-injection",
      source: { path: "vulnerable.py", line: 4 },
      sink: {
        path: "vulnerable.py",
        line: 5,
        cweIds: ["CWE-1336"],
      },
      candidateControls: [],
    });

    const safePython = records.find(({ path }) => path === "safe.py");
    expect(safePython?.frameworkModel?.candidateControls).toContainEqual({
      kind: "fixed-template-with-data-context",
      path: "safe.py",
      line: 5,
    });

    const dynamicJavascript = records.find(
      ({ path }) => path === "dynamic-literal.js",
    );
    expect(dynamicJavascript?.frameworkModel?.candidateControls).toEqual([]);

    const dynamicPython = records.find(
      ({ path }) => path === "dynamic_literal.py",
    );
    expect(dynamicPython?.frameworkModel?.candidateControls).toEqual([]);

    const prompt = scanQualityGatePrompt(JSON.stringify(vulnerableJavascript));
    expect(prompt).toContain(
      "prove the exact attacker-controlled value becomes template source",
    );
    expect(prompt).toContain(
      "A fixed server-owned template with the attacker value supplied only through a named render-data or context field is strong counterevidence",
    );
    expect(prompt).toContain(
      "API-name co-occurrence, an untrusted render-context value, or a fixed template literal must not create a finding",
    );
    expect(prompt).toContain(
      "Classify proven template-source injection as CWE-1336; do not substitute generic CWE-94",
    );
    expect(prompt).toContain(
      "A directly reachable HTTP source flowing into unsandboxed general-purpose Pug or Jinja template-source compilation or rendering is high severity",
    );
    expect(prompt).toContain(
      "Do not lower it to medium solely for missing deployment evidence",
    );
    expect(prompt).toContain(
      "`select_autoescape` defaults `default_for_string` to true",
    );
    expect(prompt).toContain(
      "A fixed HTML template compiled under `Environment(autoescape=True)` or `select_autoescape(default_for_string=True)`, with the attacker value supplied only as a named render field, is strong XSS counterevidence",
    );
  });

  test("preserves exact Node and Python cross-file template paths", async () => {
    const inventories = new Map<string, string>();
    for (const id of caseIds) {
      inventories.set(
        id,
        await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id)),
      );
    }

    const javascript = templateRecord(
      inventories.get("javascript-cross-file-template-injection")!,
      "cross-file-wrapper",
    );
    expect(javascript?.frameworkModel).toMatchObject({
      id: "node-http-template-injection",
      source: { path: "src/server.js", line: 4 },
      sink: {
        path: "src/template.js",
        line: 4,
        cweIds: ["CWE-1336"],
      },
    });
    expect(
      javascript?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "relative-module-import",
      "wrapper-call-argument",
      "wrapper-parameter",
    ]);
    expect(
      templateRecord(
        inventories.get("javascript-cross-file-safe-template")!,
        "cross-file-wrapper",
      ),
    ).toBeUndefined();

    const python = templateRecord(
      inventories.get("python-cross-file-template-injection")!,
      "cross-file-wrapper",
    );
    expect(python?.frameworkModel).toMatchObject({
      id: "python-web-template-injection",
      source: { path: "src/server.py", line: 10 },
      sink: {
        path: "src/template.py",
        line: 5,
        cweIds: ["CWE-1336"],
      },
    });
    expect(python?.frameworkModel?.propagators.map(({ kind }) => kind)).toEqual(
      ["relative-python-import", "wrapper-call-argument", "wrapper-parameter"],
    );
    expect(
      templateRecord(
        inventories.get("python-cross-file-safe-template")!,
        "cross-file-wrapper",
      ),
    ).toBeUndefined();
  });

  test("carries template source through one explicit relay", async () => {
    const javascriptRoot = await mkdtemp(
      join(tmpdir(), "copilot-security-javascript-template-relay-"),
    );
    temporaryPaths.push(javascriptRoot);
    await mkdir(join(javascriptRoot, "src"), { recursive: true });
    await writeFile(
      join(javascriptRoot, "src", "template.js"),
      [
        'import pug from "pug";',
        "export function compileTemplate(source) {",
        "  return pug.compile(source)({});",
        "}",
        "",
      ].join("\n"),
    );
    await writeFile(
      join(javascriptRoot, "src", "service.js"),
      [
        'import { compileTemplate } from "./template.js";',
        "export function renderPreview(source) {",
        "  return compileTemplate(source);",
        "}",
        "",
      ].join("\n"),
    );
    await writeFile(
      join(javascriptRoot, "src", "server.js"),
      [
        'import { renderPreview } from "./service.js";',
        "export function preview(request) {",
        "  const source = request.body.template;",
        "  return renderPreview(source);",
        "}",
        "",
      ].join("\n"),
    );

    const javascript = templateRecord(
      await buildResidualRiskInventory(javascriptRoot),
      "cross-file-multi-hop-wrapper",
    );
    expect(javascript?.frameworkModel?.source.path).toBe("src/server.js");
    expect(javascript?.frameworkModel?.sink.path).toBe("src/template.js");
    expect(javascript?.frameworkModel?.propagators).toHaveLength(6);

    const pythonRoot = await mkdtemp(
      join(tmpdir(), "copilot-security-python-template-relay-"),
    );
    temporaryPaths.push(pythonRoot);
    await mkdir(join(pythonRoot, "src"), { recursive: true });
    await writeFile(join(pythonRoot, "src", "__init__.py"), "");
    await writeFile(
      join(pythonRoot, "src", "template.py"),
      "from flask import render_template_string\n\ndef compile_template(source):\n    return render_template_string(source)\n",
    );
    await writeFile(
      join(pythonRoot, "src", "service.py"),
      "from .template import compile_template\n\ndef render_preview(source):\n    return compile_template(source)\n",
    );
    await writeFile(
      join(pythonRoot, "src", "server.py"),
      'from flask import request\nfrom .service import render_preview\n\ndef preview():\n    source = request.form.get("template", "")\n    return render_preview(source)\n',
    );

    const python = templateRecord(
      await buildResidualRiskInventory(pythonRoot),
      "cross-file-multi-hop-wrapper",
    );
    expect(python?.frameworkModel?.source.path).toBe("src/server.py");
    expect(python?.frameworkModel?.sink.path).toBe("src/template.py");
    expect(python?.frameworkModel?.propagators).toHaveLength(6);
  });
});
