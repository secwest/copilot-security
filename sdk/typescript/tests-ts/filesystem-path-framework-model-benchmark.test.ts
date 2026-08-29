import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface FrameworkRecord {
  path: string;
  frameworkModel?: {
    id: string;
    language: string;
    scope: string;
    source: { kind: string; path: string; line: number };
    sink: { kind: string; path: string; line: number; cweIds: string[] };
    propagators: Array<{ kind: string; path: string; line: number }>;
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
      acceptableSeverities?: string[];
      requireValidation?: boolean;
      requireAttackPath?: boolean;
      requireCodeEvidence?: boolean;
    }>;
  }>;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const caseIds = [
  "javascript-multi-hop-path-traversal",
  "javascript-multi-hop-safe-path",
  "python-multi-hop-path-traversal",
  "python-multi-hop-safe-path",
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

function pathRecords(inventory: string): FrameworkRecord[] {
  return parseRecords(inventory).filter((record) =>
    ["node-http-path", "python-web-path"].includes(
      record.frameworkModel?.id ?? "",
    ),
  );
}

async function temporaryRepository(): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-node-python-path-"),
  );
  temporaryPaths.push(repository);
  return repository;
}

async function writeRepositoryFile(
  repository: string,
  relativePath: string,
  contents: string,
): Promise<void> {
  const path = join(repository, relativePath);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, contents);
}

describe("Node and Python filesystem-path framework models", () => {
  test("keeps both exploit/control pairs under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "filesystem-path-framework-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;

    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.thresholds["maxFalsePositivesPerRun"]).toBe(0);
    expect(manifest.cases.map(({ id }) => id)).toEqual([...caseIds]);
    expect(
      manifest.cases.filter(({ expected }) => expected.length > 0),
    ).toHaveLength(2);
    expect(
      manifest.cases.filter(({ expected }) => expected.length === 0),
    ).toHaveLength(2);
    for (const benchmarkCase of manifest.cases) {
      expect(benchmarkCase.findingsPaths).toHaveLength(1);
    }
    for (const benchmarkCase of manifest.cases.filter(
      ({ expected }) => expected.length > 0,
    )) {
      expect(benchmarkCase.expected[0]).toMatchObject({
        cwe: ["CWE-22"],
        acceptableSeverities: ["high", "medium"],
        requireValidation: true,
        requireAttackPath: true,
        requireCodeEvidence: true,
      });
    }
  });

  test("preserves three exact boundaries and fixed-map counterevidence", async () => {
    const inventories = new Map<string, FrameworkRecord[]>();
    for (const id of caseIds) {
      inventories.set(
        id,
        pathRecords(
          await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id)),
        ),
      );
    }

    const nodeVulnerable = inventories.get(caseIds[0])!;
    const nodeSafe = inventories.get(caseIds[1])!;
    const pythonVulnerable = inventories.get(caseIds[2])!;
    const pythonSafe = inventories.get(caseIds[3])!;

    expect(nodeVulnerable).toHaveLength(1);
    expect(nodeVulnerable[0]?.frameworkModel).toMatchObject({
      id: "node-http-path",
      language: "javascript-typescript",
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", kind: "http-request-field" },
      sink: {
        path: "src/storage.js",
        line: 7,
        kind: "filesystem-path",
        cweIds: ["CWE-22"],
      },
      candidateControls: [],
    });
    expect(
      nodeVulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "relative-module-import",
      "wrapper-call-argument",
      "wrapper-parameter",
      "relative-module-import",
      "wrapper-call-argument",
      "wrapper-parameter",
      "relative-module-import",
      "wrapper-call-argument",
      "wrapper-parameter",
    ]);
    expect(nodeSafe).toHaveLength(1);
    expect(nodeSafe[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "fixed-path-allowlist",
      path: "src/storage.js",
      line: 5,
    });

    expect(pythonVulnerable).toHaveLength(1);
    expect(pythonVulnerable[0]?.frameworkModel).toMatchObject({
      id: "python-web-path",
      language: "python",
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.py", kind: "framework-request-field" },
      sink: {
        path: "src/storage.py",
        line: 7,
        kind: "filesystem-path",
        cweIds: ["CWE-22"],
      },
      candidateControls: [],
    });
    expect(
      pythonVulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "relative-python-import",
      "wrapper-call-argument",
      "wrapper-parameter",
      "relative-python-import",
      "wrapper-call-argument",
      "wrapper-parameter",
      "relative-python-import",
      "wrapper-call-argument",
      "wrapper-parameter",
    ]);
    expect(pythonSafe).toHaveLength(1);
    expect(pythonSafe[0]?.frameworkModel?.candidateControls).toContainEqual({
      kind: "fixed-path-allowlist",
      path: "src/storage.py",
      line: 4,
    });
  });

  test("keeps the Sails Action2 exploit/control pair under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-sails-action2-path-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;
    expect(manifest.schemaVersion).toBe("1.0");
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-sails-action2-path-traversal",
      "node-sails-action2-fixed-thumbnail",
    ]);
    expect(manifest.cases[0]?.findingsPaths).toHaveLength(3);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-22"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);

    const vulnerable = pathRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-sails-action2-path-traversal"),
      ),
    );
    const control = pathRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-sails-action2-fixed-thumbnail"),
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      id: "node-http-path",
      scope: "same-file",
      source: {
        kind: "sails-action2-declared-input",
        path: "api/controllers/attachments/download-thumbnail.js",
        line: 13,
      },
      sink: {
        kind: "filesystem-path",
        path: "api/controllers/attachments/download-thumbnail.js",
        line: 15,
        cweIds: ["CWE-22"],
      },
      propagators: [
        {
          kind: "sails-action2-explicit-route",
          path: "config/routes.js",
          line: 2,
        },
      ],
      candidateControls: [],
    });
    expect(control).toEqual([]);
  });

  test("keeps the routed Sails Action2 wrapper pair under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-sails-action2-wrapper-path-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;
    expect(manifest.schemaVersion).toBe("1.0");
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-sails-action2-wrapper-path-traversal",
      "node-sails-action2-wrapper-fixed-thumbnail",
    ]);
    expect(manifest.cases[0]?.findingsPaths).toHaveLength(3);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-22"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);

    const vulnerable = pathRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-sails-action2-wrapper-path-traversal",
        ),
      ),
    );
    const control = pathRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-sails-action2-wrapper-fixed-thumbnail",
        ),
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      id: "node-http-path",
      scope: "cross-file-wrapper",
      source: {
        kind: "sails-action2-declared-input",
        path: "api/controllers/attachments/download-wrapped-thumbnail.js",
        line: 9,
      },
      sink: {
        kind: "filesystem-path",
        path: "services/thumbnail-reader.js",
        line: 10,
        cweIds: ["CWE-22"],
      },
      propagators: [
        {
          kind: "sails-action2-explicit-route",
          path: "config/routes.js",
          line: 2,
        },
        {
          kind: "relative-module-import",
          path: "api/controllers/attachments/download-wrapped-thumbnail.js",
          line: 1,
        },
        {
          kind: "wrapper-call-argument",
          path: "api/controllers/attachments/download-wrapped-thumbnail.js",
          line: 10,
        },
        {
          kind: "wrapper-parameter",
          path: "services/thumbnail-reader.js",
          line: 4,
        },
      ],
      candidateControls: [],
    });
    expect(control).toEqual([]);
  });

  test("accepts exact Node filesystem bindings and only path positions", async () => {
    const repository = await temporaryRepository();
    const cases: Array<[string, string]> = [
      [
        "named.mjs",
        'import { readFile as load } from "node:fs/promises";\nexport function handler(request) { return load(request.query.path, "utf8"); }\n',
      ],
      [
        "namespace.mjs",
        'import * as fs from "node:fs/promises";\nexport function handler(request) { return fs.readFile(request.query.path, "utf8"); }\n',
      ],
      [
        "default.mjs",
        'import fs from "node:fs";\nexport function handler(request) { return fs.readFileSync(request.query.path, "utf8"); }\n',
      ],
      [
        "commonjs.cjs",
        'const fs = require("node:fs");\nexports.handler = function handler(request) { return fs.readFileSync(request.query.path, "utf8"); };\n',
      ],
      [
        "destructured.cjs",
        'const { copyFileSync: copy } = require("node:fs");\nexports.handler = function handler(request) { return copy("fixed.txt", request.query.path); };\n',
      ],
      [
        "data-only.mjs",
        'import { writeFile } from "node:fs/promises";\nexport function handler(request) { return writeFile("fixed.txt", request.body); }\n',
      ],
      [
        "lookalike.mjs",
        "function readFile(path) { return path; }\nexport function handler(request) { return readFile(request.query.path); }\n",
      ],
    ];
    for (const [path, contents] of cases) {
      await writeRepositoryFile(repository, path, contents);
    }

    const records = pathRecords(await buildResidualRiskInventory(repository));
    expect(
      records.filter(
        (record) => record.frameworkModel?.id === "node-http-path",
      ),
    ).toHaveLength(5);
    expect(
      records.some((record) => record.path === "data-only.mjs"),
    ).toBeFalse();
    expect(
      records.some((record) => record.path === "lookalike.mjs"),
    ).toBeFalse();
  });

  test("accepts exact Python filesystem bindings and rejects shadows", async () => {
    const repository = await temporaryRepository();
    const cases: Array<[string, string]> = [
      [
        "builtin.py",
        'from flask import request\ndef handler():\n    return open(request.args.get("path"), encoding="utf-8").read()\n',
      ],
      [
        "module.py",
        'import builtins as trusted\nfrom flask import request\ndef handler():\n    return trusted.open(request.args.get("path"), encoding="utf-8").read()\n',
      ],
      [
        "named.py",
        'from builtins import open as load\nfrom flask import request\ndef handler():\n    return load(request.args.get("path"), encoding="utf-8").read()\n',
      ],
      [
        "os_alias.py",
        'import os as operating\nfrom flask import request\ndef handler():\n    return operating.remove(request.args.get("path"))\n',
      ],
      [
        "copy.py",
        'from shutil import copyfile as copy_path\nfrom flask import request\ndef handler():\n    return copy_path("fixed.txt", request.args.get("path"))\n',
      ],
      [
        "shadow.py",
        'from flask import request\ndef open(path, encoding=None):\n    return path\ndef handler():\n    return open(request.args.get("path"))\n',
      ],
      [
        "import_shadow.py",
        'from fake_files import open\nfrom flask import request\ndef handler():\n    return open(request.args.get("path"))\n',
      ],
    ];
    for (const [path, contents] of cases) {
      await writeRepositoryFile(repository, path, contents);
    }

    const records = pathRecords(await buildResidualRiskInventory(repository));
    expect(
      records.filter(
        (record) => record.frameworkModel?.id === "python-web-path",
      ),
    ).toHaveLength(5);
    expect(records.some((record) => record.path === "shadow.py")).toBeFalse();
    expect(
      records.some((record) => record.path === "import_shadow.py"),
    ).toBeFalse();
  });

  test("models only declared Sails Action2 controller inputs", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "config/routes.js",
      'module.exports.routes = {\n  "GET /direct": "attachments/direct",\n  "GET /assigned": "attachments/assigned",\n  "GET /destructured": "attachments/destructured",\n  "GET /arrow": "attachments/arrow",\n  "GET /undeclared": "attachments/undeclared",\n  "GET /reassigned": "attachments/reassigned",\n  "GET /fixed-map": "attachments/fixed-map",\n  "GET /string-lookalike": "attachments/string-lookalike",\n};\n',
    );
    const cases: Array<[string, string]> = [
      [
        "api/controllers/attachments/direct.js",
        'const fs = require("node:fs");\nconst path = require("node:path");\nmodule.exports = {\n  inputs: { filename: { type: "string", required: true } },\n  async fn(inputs, exits) {\n    const filePath = path.join("attachments", inputs.filename);\n    return exits.success(fs.readFileSync(filePath));\n  },\n};\n',
      ],
      [
        "api/controllers/attachments/assigned.js",
        'const fs = require("node:fs");\nconst action = {\n  inputs: { filename: { type: "string", required: true } },\n  fn(inputs, exits) {\n    const selected = inputs.filename;\n    const filePath = `attachments/${selected}`;\n    return exits.success(fs.readFileSync(filePath));\n  },\n};\nmodule.exports = action;\n',
      ],
      [
        "api/controllers/attachments/destructured.js",
        'import { readFileSync } from "node:fs";\nexport default {\n  inputs: { filename: { type: "string", required: true } },\n  async fn({ filename: selected }, exits) {\n    return exits.success(readFileSync(selected));\n  },\n};\n',
      ],
      [
        "api/controllers/attachments/arrow.js",
        'import { readFileSync } from "node:fs";\nmodule.exports = {\n  inputs: { filename: { type: "string", required: true } },\n  fn: async (inputs, exits) => {\n    return exits.success(readFileSync(inputs["filename"]));\n  },\n};\n',
      ],
      [
        "api/helpers/read-thumbnail.js",
        'const fs = require("node:fs");\nmodule.exports = { inputs: { filename: { type: "string" } }, fn(inputs) { return fs.readFileSync(inputs.filename); } };\n',
      ],
      [
        "api/controllers/attachments/undeclared.js",
        'const fs = require("node:fs");\nmodule.exports = { inputs: { id: { type: "string" } }, fn(inputs) { return fs.readFileSync(inputs.filename); } };\n',
      ],
      [
        "api/controllers/attachments/reassigned.js",
        'const fs = require("node:fs");\nmodule.exports = { inputs: { filename: { type: "string" } }, fn(inputs) { let selected = inputs.filename; selected = "welcome.txt"; return fs.readFileSync(selected); } };\n',
      ],
      [
        "api/controllers/attachments/fixed-map.js",
        'const fs = require("node:fs");\nmodule.exports = { inputs: { filename: { type: "string" } }, fn(inputs) { const selected = { welcome: "welcome.txt" }[inputs.filename]; return fs.readFileSync("welcome.txt"); } };\n',
      ],
      [
        "api/controllers/attachments/string-lookalike.js",
        'const fs = require("node:fs");\nmodule.exports = { inputs: { filename: { type: "string" } }, fn(inputs) { return fs.readFileSync("inputs.filename"); } };\n',
      ],
      [
        "api/controllers/attachments/unexposed.js",
        'const fs = require("node:fs");\nmodule.exports = { inputs: { filename: { type: "string" } }, fn(inputs) { return fs.readFileSync(inputs.filename); } };\n',
      ],
      [
        "lib/machine.js",
        'const fs = require("node:fs");\nmodule.exports = { inputs: { filename: { type: "string" } }, fn(inputs) { return fs.readFileSync(inputs.filename); } };\n',
      ],
    ];
    for (const [path, contents] of cases) {
      await writeRepositoryFile(repository, path, contents);
    }

    const records = pathRecords(await buildResidualRiskInventory(repository));
    const sails = records.filter(
      (record) =>
        record.frameworkModel?.source.kind === "sails-action2-declared-input",
    );
    expect(sails.map(({ path }) => path).sort()).toEqual([
      "api/controllers/attachments/arrow.js",
      "api/controllers/attachments/assigned.js",
      "api/controllers/attachments/destructured.js",
      "api/controllers/attachments/direct.js",
    ]);
    expect(
      sails.every(
        (record) =>
          record.frameworkModel?.id === "node-http-path" &&
          record.frameworkModel.scope === "same-file" &&
          record.frameworkModel.sink.cweIds.join() === "CWE-22",
      ),
    ).toBeTrue();
  });

  test("requires exact Sails route exposure and preserves two relative relays", async () => {
    const repository = await temporaryRepository();
    const sink =
      'import fs from "node:fs";\nexport function readPath(filename) { return fs.readFileSync(filename); }\n';
    const controller = (importPath: string, imported = "readPath") =>
      `import { ${imported} } from "${importPath}";\nexport default {\n  inputs: { filename: { type: "string", required: true } },\n  async fn(inputs, exits) { return exits.success(${imported}(inputs.filename)); },\n};\n`;

    await writeRepositoryFile(
      repository,
      "explicit/config/routes.js",
      'module.exports = { routes: {\n  "GET /direct/:filename": "direct",\n  "GET /object/:filename": { action: "object-route" },\n} };\n',
    );
    await writeRepositoryFile(
      repository,
      "explicit/api/controllers/direct.js",
      controller("../../services/read.js"),
    );
    await writeRepositoryFile(
      repository,
      "explicit/api/controllers/object-route.js",
      controller("../../services/read.js"),
    );
    await writeRepositoryFile(
      repository,
      "explicit/api/controllers/unexposed.js",
      controller("../../services/read.js"),
    );
    await writeRepositoryFile(repository, "explicit/services/read.js", sink);

    await writeRepositoryFile(
      repository,
      "blueprint/config/blueprints.js",
      "module.exports.blueprints = { actions: true };\n",
    );
    await writeRepositoryFile(
      repository,
      "blueprint/api/controllers/download.js",
      controller("../../services/read.js"),
    );
    await writeRepositoryFile(repository, "blueprint/services/read.js", sink);

    await writeRepositoryFile(
      repository,
      "disabled/config/blueprints.js",
      "module.exports.blueprints = { actions: false };\n",
    );
    await writeRepositoryFile(
      repository,
      "disabled/api/controllers/download.js",
      controller("../../services/read.js"),
    );
    await writeRepositoryFile(repository, "disabled/services/read.js", sink);

    await writeRepositoryFile(
      repository,
      "dynamic/config/blueprints.js",
      "module.exports.blueprints = { actions: process.env.ACTION_ROUTES };\n",
    );
    await writeRepositoryFile(
      repository,
      "dynamic/api/controllers/download.js",
      controller("../../services/read.js"),
    );
    await writeRepositoryFile(repository, "dynamic/services/read.js", sink);

    await writeRepositoryFile(
      repository,
      "ambiguous/config/routes.js",
      'module.exports.routes = { "GET /download/:filename": "download" };\n',
    );
    await writeRepositoryFile(
      repository,
      "ambiguous/config/routes.cjs",
      'module.exports.routes = { "GET /download/:filename": "download" };\n',
    );
    await writeRepositoryFile(
      repository,
      "ambiguous/api/controllers/download.js",
      controller("../../services/read.js"),
    );
    await writeRepositoryFile(repository, "ambiguous/services/read.js", sink);

    await writeRepositoryFile(
      repository,
      "helper/config/routes.js",
      'module.exports.routes = { "GET /helper/:filename": "read" };\n',
    );
    await writeRepositoryFile(
      repository,
      "helper/api/helpers/read.js",
      controller("../../services/read.js"),
    );
    await writeRepositoryFile(repository, "helper/services/read.js", sink);

    await writeRepositoryFile(
      repository,
      "multihop/config/routes.js",
      'module.exports.routes = { "GET /multi/:filename": "download" };\n',
    );
    await writeRepositoryFile(
      repository,
      "multihop/api/controllers/download.js",
      controller("../../lib/first.js", "first"),
    );
    await writeRepositoryFile(
      repository,
      "multihop/lib/first.js",
      'import { second } from "./second.js";\nexport function first(value) {\n  return second(value);\n}\n',
    );
    await writeRepositoryFile(
      repository,
      "multihop/lib/second.js",
      'import { readPath } from "../services/read.js";\nexport function second(value) {\n  return readPath(value);\n}\n',
    );
    await writeRepositoryFile(repository, "multihop/services/read.js", sink);

    const records = pathRecords(await buildResidualRiskInventory(repository));
    const sails = records.filter(
      (record) =>
        record.frameworkModel?.source.kind === "sails-action2-declared-input",
    );
    expect(
      sails
        .map((record) => ({
          path: record.frameworkModel?.source.path,
          scope: record.frameworkModel?.scope,
          route: record.frameworkModel?.propagators[0]?.kind,
        }))
        .sort((left, right) => left.path!.localeCompare(right.path!)),
    ).toEqual([
      {
        path: "blueprint/api/controllers/download.js",
        scope: "cross-file-wrapper",
        route: "sails-action2-blueprint-action-route",
      },
      {
        path: "explicit/api/controllers/direct.js",
        scope: "cross-file-wrapper",
        route: "sails-action2-explicit-route",
      },
      {
        path: "explicit/api/controllers/object-route.js",
        scope: "cross-file-wrapper",
        route: "sails-action2-explicit-route",
      },
      {
        path: "multihop/api/controllers/download.js",
        scope: "cross-file-multi-hop-wrapper",
        route: "sails-action2-explicit-route",
      },
    ]);
    expect(
      sails.some((record) =>
        record.frameworkModel?.propagators.some(
          (propagator) =>
            propagator.kind === "wrapper-call-argument" &&
            propagator.path === "multihop/lib/second.js",
        ),
      ),
    ).toBeTrue();
  });

  test("teaches exact path arguments and containment limits", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({ frameworkModel: { id: "node-http-path" } }),
    );
    expect(prompt).toContain("For node-http-path and python-web-path rows");
    expect(prompt).toContain("sails-action2-declared-input");
    expect(prompt).toContain("helper/machine modules");
    expect(prompt).toContain("sails-action2-explicit-route");
    expect(prompt).toContain("sails-action2-blueprint-action-route");
    expect(prompt).toContain("documented default is false");
    expect(prompt).toContain("Relative wrapper and multi-hop rows");
    expect(prompt).toContain("file contents or encoding arguments");
    expect(prompt).toContain("path.isAbsolute alone");
    expect(prompt).toContain("os.path.commonprefix is not component-aware");
  });
});
