import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface SunEditorRecord {
  path: string;
  line: number;
  frameworkModel?: {
    id: string;
    source: { kind: string; path: string; line: number };
    sink: { kind: string; path: string; line: number; cweIds: string[] };
    propagators: Array<{ kind: string; symbol?: string }>;
  };
}

interface CaseOptions {
  declaration?: string;
  dependencySection?: "dependencies" | "devDependencies";
  lock?: boolean;
  lockedVersion?: string;
  packageName?: string;
  source?: string;
}

const temporaryPaths: string[] = [];
const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

const defaultSource = `import SUNEDITOR from "suneditor";
import { embed } from "suneditor/plugins";

export function mountEditor(request) {
  return SUNEDITOR.create("editor", {
    plugins: { embed },
    buttonList: [["embed"]],
    value: request.body.html,
  });
}
`;

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function sunEditorRecords(inventory: string): SunEditorRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as SunEditorRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-suneditor-embed-external-script-xss",
    );
}

async function temporaryRepository(label: string): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), `copilot-security-suneditor-${label}-`),
  );
  temporaryPaths.push(repository);
  return repository;
}

async function writeCase(
  repository: string,
  id: string,
  options: CaseOptions = {},
): Promise<void> {
  const root = join(repository, id);
  const declaration = options.declaration ?? "3.1.3";
  const dependencySection = options.dependencySection ?? "dependencies";
  const packageName = options.packageName ?? "suneditor";
  await mkdir(join(root, "src"), { recursive: true });
  await writeFile(
    join(root, "package.json"),
    JSON.stringify(
      {
        name: id,
        private: true,
        [dependencySection]: { [packageName]: declaration },
      },
      null,
      2,
    ),
  );
  if (options.lock === true) {
    await writeFile(
      join(root, "package-lock.json"),
      JSON.stringify(
        {
          name: id,
          lockfileVersion: 3,
          packages: {
            "": { [dependencySection]: { [packageName]: declaration } },
            "node_modules/suneditor": {
              version: options.lockedVersion ?? "3.1.3",
            },
          },
        },
        null,
        2,
      ),
    );
  }
  await writeFile(
    join(root, "src", "editor.js"),
    options.source ?? defaultSource,
  );
}

describe("SunEditor Embed external-script XSS model", () => {
  test("keeps a strict affected and repaired source-identical benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-suneditor-embed-xss-manifest.json"),
        "utf8",
      ),
    ) as {
      schemaVersion: string;
      thresholds: Record<string, number>;
      cases: Array<{
        id: string;
        expected: Array<{
          cwe?: string[];
          acceptableSeverities?: string[];
          locations?: Array<{ startLine: number; endLine: number }>;
        }>;
      }>;
    };
    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBe(true);
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-suneditor-embed-external-script-xss",
      "node-suneditor-embed-external-script-blocked",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-79"],
      acceptableSeverities: ["high"],
      locations: [{ startLine: 5, endLine: 5 }],
    });
    expect(manifest.cases[1]?.expected).toEqual([]);

    const affectedRoot = join(
      benchmarkRoot,
      "fixtures",
      "node-suneditor-embed-external-script-xss",
    );
    const repairedRoot = join(
      benchmarkRoot,
      "fixtures",
      "node-suneditor-embed-external-script-blocked",
    );
    expect(
      sunEditorRecords(await buildResidualRiskInventory(affectedRoot)),
    ).toHaveLength(1);
    expect(
      sunEditorRecords(await buildResidualRiskInventory(repairedRoot)),
    ).toEqual([]);
    for (const path of [
      join("src", "editor.js"),
      "witness.test.mjs",
      "runtime-witness.html",
      "runtime-server.mjs",
      "README.md",
    ]) {
      expect(await readFile(join(affectedRoot, path), "utf8"), path).toBe(
        await readFile(join(repairedRoot, path), "utf8"),
      );
    }
    const affectedPackage = JSON.parse(
      await readFile(join(affectedRoot, "package.json"), "utf8"),
    ) as { dependencies: Record<string, string> };
    const repairedPackage = JSON.parse(
      await readFile(join(repairedRoot, "package.json"), "utf8"),
    ) as { dependencies: Record<string, string> };
    expect(affectedPackage.dependencies.suneditor).toBe("3.1.3");
    expect(repairedPackage.dependencies.suneditor).toBe("3.1.4");
  });

  test("emits exact source, plugin, toolbar, sink, and dependency evidence", async () => {
    const repository = await temporaryRepository("topology");
    await writeCase(repository, "affected");
    const records = sunEditorRecords(
      await buildResidualRiskInventory(join(repository, "affected")),
    );
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      path: "src/editor.js",
      line: 5,
      frameworkModel: {
        id: "node-suneditor-embed-external-script-xss",
        source: { kind: "remote-request-body", line: 8 },
        sink: {
          kind: "vulnerable-suneditor-embed-external-script-dom-append",
          line: 5,
          cweIds: ["CWE-79"],
        },
      },
    });
    expect(
      records[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "remote-stored-editor-content",
      "official-suneditor-create-binding",
      "enabled-suneditor-embed-plugin",
      "enabled-suneditor-embed-button",
      "suneditor-runtime-dependency",
    ]);
  });

  test("honors affected boundaries and fresh exact lock provenance", async () => {
    const repository = await temporaryRepository("versions");
    for (const version of ["1.0.0", "2.47.8", "3.0.6", "3.1.3"]) {
      await writeCase(repository, `affected-${version}`, {
        declaration: version,
      });
    }
    await writeCase(repository, "locked", {
      declaration: "^3.1.0",
      lock: true,
      lockedVersion: "3.1.3",
    });
    for (const version of ["3.1.4", "3.2.0", "4.0.0", "3.1.4-beta.0"]) {
      await writeCase(repository, `repaired-${version}`, {
        declaration: version,
      });
    }
    await writeCase(repository, "unlocked-range", { declaration: "^3.1.0" });
    for (const version of ["1.0.0", "2.47.8", "3.0.6", "3.1.3"]) {
      expect(
        sunEditorRecords(
          await buildResidualRiskInventory(
            join(repository, `affected-${version}`),
          ),
        ),
      ).toHaveLength(1);
    }
    const locked = sunEditorRecords(
      await buildResidualRiskInventory(join(repository, "locked")),
    );
    expect(locked).toHaveLength(1);
    expect(locked[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-suneditor-embed-external-script-dom-append",
    );
    for (const id of [
      "repaired-3.1.4",
      "repaired-3.2.0",
      "repaired-4.0.0",
      "repaired-3.1.4-beta.0",
      "unlocked-range",
    ]) {
      expect(
        sunEditorRecords(
          await buildResidualRiskInventory(join(repository, id)),
        ),
        id,
      ).toEqual([]);
    }
  });

  test("accepts official aliases, aggregate receivers, direct modal imports, and CommonJS", async () => {
    const repository = await temporaryRepository("bindings");
    const sources = [
      `import Editor from "suneditor";
import { embed as rawEmbed } from "suneditor/plugins";
export function mount(request) { return Editor.create("editor", { plugins: { embed: rawEmbed }, buttonList: [["embed"]], value: request.body.html }); }
`,
      `import * as Editor from "suneditor";
import * as plugins from "suneditor/src/plugins/index.js";
export function mount(request) { return Editor.create("editor", { plugins, buttonList: [["embed"]], value: request.query.html }); }
`,
      `import Editor from "suneditor";
import rawEmbed from "suneditor/src/plugins/modal/embed.js";
export function mount(request) { return Editor.create("editor", { plugins: { embed: rawEmbed }, buttonList: [["embed"]], value: request.params.html }); }
`,
      `const Editor = require("suneditor");
const { embed: rawEmbed } = require("suneditor/plugins");
exports.mount = function(request) { return Editor.create("editor", { plugins: { embed: rawEmbed }, buttonList: [["embed"]], value: request.headers.html }); };
`,
      `const { create: makeEditor } = require("suneditor");
const rawEmbed = require("suneditor/plugins").embed;
exports.mount = function(request) { return makeEditor("editor", { plugins: { embed: rawEmbed }, buttonList: [["embed"]], value: request.body.html }); };
`,
    ];
    for (const [index, source] of sources.entries()) {
      await writeCase(repository, `shape-${index}`, { source });
      expect(
        sunEditorRecords(
          await buildResidualRiskInventory(join(repository, `shape-${index}`)),
        ),
        `shape-${index}`,
      ).toHaveLength(1);
    }
  });

  test("models remote setContents on the stable configured editor instance", async () => {
    const repository = await temporaryRepository("set-contents");
    await writeCase(repository, "affected", {
      source: `import SUNEDITOR from "suneditor";
import { embed } from "suneditor/src/plugins";
export function mountEditor(request) {
  const editor = SUNEDITOR.create("editor", {
    plugins: { embed },
    buttonList: [["embed"]],
  });
  editor.setContents(request.body.html);
  return editor;
}
`,
    });
    const records = sunEditorRecords(
      await buildResidualRiskInventory(join(repository, "affected")),
    );
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      line: 8,
      frameworkModel: {
        source: { kind: "remote-request-body", line: 8 },
        sink: { line: 8 },
      },
    });
    expect(records[0]?.frameworkModel?.propagators[0]?.symbol).toContain(
      "->setContents",
    );
  });

  test("fails closed on incomplete topology, trusted data, provenance gaps, and reassignment", async () => {
    const repository = await temporaryRepository("negative");
    const cases: Array<[string, CaseOptions]> = [
      ["repaired", { declaration: "3.1.4" }],
      ["wrong-package", { packageName: "suneditor-fork" }],
      ["development-only", { dependencySection: "devDependencies" }],
      [
        "plugin-not-enabled",
        { source: defaultSource.replace("plugins: { embed }", "plugins: {}") },
      ],
      [
        "unregistered-array-shape",
        {
          source: defaultSource.replace(
            "plugins: { embed }",
            "plugins: [embed]",
          ),
        },
      ],
      [
        "button-not-enabled",
        {
          source: defaultSource.replace(
            'buttonList: [["embed"]]',
            'buttonList: [["image"]]',
          ),
        },
      ],
      [
        "trusted-value",
        {
          source: defaultSource.replace(
            "value: request.body.html",
            'value: "<p>trusted</p>"',
          ),
        },
      ],
      [
        "unexported",
        { source: defaultSource.replace("export function", "function") },
      ],
      [
        "create-reassigned",
        {
          source: defaultSource.replace(
            "export function mountEditor(request)",
            "SUNEDITOR = localEditor;\nexport function mountEditor(request)",
          ),
        },
      ],
      [
        "embed-member-replaced",
        {
          source: `import SUNEDITOR from "suneditor";
import * as plugins from "suneditor/src/plugins";
plugins.embed = localEmbed;
export function mountEditor(request) { return SUNEDITOR.create("editor", { plugins, buttonList: [["embed"]], value: request.body.html }); }
`,
        },
      ],
      [
        "remote-outside-content",
        {
          source: defaultSource.replace(
            "value: request.body.html",
            'value: "<p>trusted</p>", placeholder: request.body.html',
          ),
        },
      ],
    ];
    for (const [id, options] of cases) await writeCase(repository, id, options);
    for (const [id] of cases) {
      expect(
        sunEditorRecords(
          await buildResidualRiskInventory(join(repository, id)),
        ),
        id,
      ).toEqual([]);
    }
  });

  test("quality gate requires a bounded browser differential and conservative impact", () => {
    const prompt = scanQualityGatePrompt("");
    for (const expected of [
      "node-suneditor-embed-external-script-xss",
      "GHSA-w93q-cq9w-58p7",
      "CVE-2026-54606",
      "loopback-only HTTP endpoint",
      "scriptSrcWhitelist",
      "3.1.4",
      "CWE-79",
      "never use an external script host or destructive payload",
    ]) {
      expect(prompt).toContain(expected);
    }
  });
});
