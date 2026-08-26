import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface PickemRecord {
  path: string;
  line: number;
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
  };
}

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
      locations?: Array<{ startLine: number; endLine: number }>;
    }>;
  }>;
}

interface CaseOptions {
  declaration?: string;
  dependencySection?: "dependencies" | "devDependencies";
  lock?: boolean;
  lockedVersion?: string;
  lockfileVersion?: number;
  packageName?: string;
  rootLockDeclaration?: string;
  source?: string;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const temporaryPaths: string[] = [];

const defaultSource = `import { pickem } from "pickem";
export async function selectRelease(apiUrl) {
  const response = await fetch(apiUrl);
  const releases = await response.json();
  const choices = releases.map((release) => ({
    label: release.title,
    description: release.summary,
    value: release.id,
  }));
  return pickem(choices, { searchable: false });
}
`;

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function pickemRecords(inventory: string): PickemRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as PickemRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-pickem-terminal-control-injection",
    );
}

async function temporaryRepository(label: string): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), `copilot-security-pickem-${label}-`),
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
  const declaration = options.declaration ?? "1.0.6";
  const dependencySection = options.dependencySection ?? "dependencies";
  const packageName = options.packageName ?? "pickem";
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
    const lockfileVersion = options.lockfileVersion ?? 3;
    await writeFile(
      join(root, "package-lock.json"),
      JSON.stringify(
        lockfileVersion === 1
          ? {
              name: id,
              lockfileVersion,
              dependencies: {
                [packageName]: { version: options.lockedVersion ?? "1.0.6" },
              },
            }
          : {
              name: id,
              lockfileVersion,
              packages: {
                "": {
                  [dependencySection]: {
                    [packageName]: options.rootLockDeclaration ?? declaration,
                  },
                },
                [`node_modules/${packageName}`]: {
                  version: options.lockedVersion ?? "1.0.6",
                },
              },
            },
        null,
        2,
      ),
    );
  }
  await writeFile(
    join(root, "src", "select-release.js"),
    options.source ?? defaultSource,
  );
}

describe("pickem terminal control-sequence injection model", () => {
  test("keeps a strict affected and repaired executable benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-pickem-terminal-control-injection-manifest.json",
        ),
        "utf8",
      ),
    ) as BenchmarkManifest;
    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 1 || value === 0,
      ),
    ).toBe(true);
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-pickem-terminal-control-injection",
      "node-pickem-terminal-control-isolated",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-150"],
      acceptableSeverities: ["high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
      locations: [{ startLine: 11, endLine: 11 }],
    });
    expect(manifest.cases[1]?.expected).toEqual([]);

    const affected = pickemRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-pickem-terminal-control-injection",
        ),
      ),
    );
    const repaired = pickemRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-pickem-terminal-control-isolated",
        ),
      ),
    );
    expect(affected).toHaveLength(1);
    expect(repaired).toEqual([]);
    expect(affected[0]).toMatchObject({
      path: "src/select-release.js",
      line: 11,
      frameworkModel: {
        id: "node-pickem-terminal-control-injection",
        scope: "same-file",
        source: {
          kind: "remote-fetched-json-item-collection",
          path: "src/select-release.js",
          line: 4,
        },
        sink: {
          kind: "vulnerable-pickem-terminal-item-render",
          path: "src/select-release.js",
          line: 11,
          cweIds: ["CWE-150"],
        },
      },
    });
    expect(
      affected[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "remote-pickem-item-collection",
      "pickem-display-field-projection",
      "official-pickem-binding",
      "pickem-terminal-render",
      "pickem-runtime-dependency",
    ]);
    expect(affected[0]?.frameworkModel?.propagators[1]?.symbol).toBe(
      "label:title",
    );
  });

  test("accepts declaration-consistent modern lock provenance", async () => {
    const repository = await temporaryRepository("lock");
    await writeCase(repository, "affected-lock", {
      declaration: "^1.0.0",
      lock: true,
      lockedVersion: "1.0.6",
    });
    const records = pickemRecords(
      await buildResidualRiskInventory(join(repository, "affected-lock")),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-pickem-terminal-item-render",
    );
    expect(records[0]?.frameworkModel?.propagators.at(-1)?.symbol).toBe(
      "pickem@1.0.6:npm-lockfile:unsanitized-terminal-display",
    );
  });

  test("recognizes official named, namespace, TypeScript, and CommonJS bindings", async () => {
    const repository = await temporaryRepository("bindings");
    const body = (call: string) => `
exports.selectRelease = async function(apiUrl) {
  const releases = await (await fetch(apiUrl)).json();
  const choices = releases.map((release) => ({ label: release.title, value: release.id }));
  return ${call}(choices);
};
`;
    const variants = [
      {
        id: "named-alias",
        source: `import { pickem as choose } from "pickem";
export async function selectRelease(apiUrl) {
  const releases = await (await fetch(apiUrl)).json();
  const choices = releases.map((release) => ({ label: release.title, value: release.id }));
  return choose(choices);
}
`,
      },
      {
        id: "namespace",
        source: `import * as Picker from "pickem";
export async function selectRelease(apiUrl) {
  const releases = await (await fetch(apiUrl)).json();
  const choices = releases.map((release) => ({ label: release.title, value: release.id }));
  return Picker.pickem(choices);
}
`,
      },
      {
        id: "typescript-import-equals",
        source: `import Picker = require("pickem");
export async function selectRelease(apiUrl) {
  const releases = await (await fetch(apiUrl)).json();
  const choices = releases.map((release) => ({ label: release.title, value: release.id }));
  return Picker.pickem(choices);
}
`,
      },
      {
        id: "commonjs-receiver",
        source: `const Picker = require("pickem");${body("Picker.pickem")}`,
      },
      {
        id: "commonjs-direct",
        source: `const choose = require("pickem").pickem;${body("choose")}`,
      },
      {
        id: "commonjs-destructured",
        source: `const { pickem: choose } = require("pickem");${body("choose")}`,
      },
    ];
    for (const variant of variants) {
      await writeCase(repository, variant.id, { source: variant.source });
    }
    for (const variant of variants) {
      expect(
        pickemRecords(
          await buildResidualRiskInventory(join(repository, variant.id)),
        ),
        variant.id,
      ).toHaveLength(1);
    }
  });

  test("recognizes request collections, checkbox calls, and exact display fields", async () => {
    const repository = await temporaryRepository("sources-fields");
    const variants = [
      {
        id: "request-description-checkbox",
        source: `import { pickem } from "pickem";
export async function selectRelease(request) {
  const choices = request.body.releases.map((release) => ({
    label: "release",
    description: release.summary,
    value: release.id,
  }));
  return pickem.checkbox(choices);
}
`,
        sourceKind: "remote-request-item-collection",
        field: "description:summary",
        sink: "pickem.checkbox",
      },
      {
        id: "direct-fetch-group",
        source: `import { pickem } from "pickem";
export async function selectRelease(apiUrl) {
  const releases = await (await fetch(apiUrl)).json();
  const choices = releases.map((release) => ({
    label: "release",
    group: release.channel,
    value: release.id,
  }));
  return pickem(choices);
}
`,
        sourceKind: "remote-fetched-json-item-collection",
        field: "group:channel",
        sink: "pickem",
      },
      {
        id: "string-label",
        source: `import { pickem } from "pickem";
export async function selectRelease(apiUrl) {
  const releases = await (await fetch(apiUrl)).json();
  const choices = releases.map((release) => ({ label: String(release.title), value: release.id }));
  return pickem(choices);
}
`,
        sourceKind: "remote-fetched-json-item-collection",
        field: "label:title",
        sink: "pickem",
      },
      {
        id: "template-label",
        source: `import { pickem } from "pickem";
export async function selectRelease(apiUrl) {
  const releases = await (await fetch(apiUrl)).json();
  const choices = releases.map((release) => ({ label: \`release: \${release.title}\`, value: release.id }));
  return pickem(choices);
}
`,
        sourceKind: "remote-fetched-json-item-collection",
        field: "label:title",
        sink: "pickem",
      },
    ];
    for (const variant of variants) {
      await writeCase(repository, variant.id, { source: variant.source });
      const records = pickemRecords(
        await buildResidualRiskInventory(join(repository, variant.id)),
      );
      expect(records, variant.id).toHaveLength(1);
      expect(records[0]?.frameworkModel?.source.kind).toBe(variant.sourceKind);
      expect(records[0]?.frameworkModel?.propagators[1]?.symbol).toBe(
        variant.field,
      );
      expect(records[0]?.frameworkModel?.propagators[3]?.symbol).toBe(
        variant.sink,
      );
    }
  });

  test("rejects fixed, prerelease, wrong, development-only, and unproved versions", async () => {
    const repository = await temporaryRepository("provenance-negatives");
    const cases: Array<[string, CaseOptions]> = [
      ["fixed-107", { declaration: "1.0.7" }],
      ["fixed-110", { declaration: "1.1.0" }],
      ["fixed-200", { declaration: "2.0.0" }],
      ["prerelease", { declaration: "1.0.6-beta.1" }],
      ["wrong-package", { packageName: "pickem-fork" }],
      ["development-only", { dependencySection: "devDependencies" }],
      ["unproved-range", { declaration: "^1.0.0" }],
      [
        "stale-lock",
        {
          declaration: "^1.0.0",
          lock: true,
          lockedVersion: "1.0.7",
        },
      ],
      [
        "inconsistent-lock",
        {
          declaration: "^1.0.0",
          lock: true,
          lockedVersion: "1.0.6",
          rootLockDeclaration: "~0.9.0",
        },
      ],
      [
        "v1-lock",
        {
          declaration: "^1.0.0",
          lock: true,
          lockedVersion: "1.0.6",
          lockfileVersion: 1,
        },
      ],
    ];
    for (const [id, options] of cases) await writeCase(repository, id, options);
    for (const [id] of cases) {
      expect(
        pickemRecords(await buildResidualRiskInventory(join(repository, id))),
        id,
      ).toEqual([]);
    }
  });

  test("rejects trusted, value-only, sanitized, custom-format, reassigned, and lookalike flows", async () => {
    const repository = await temporaryRepository("topology-negatives");
    const cases: Array<[string, string]> = [
      [
        "dependency-only",
        `import { pickem } from "pickem";\nexport const configured = Boolean(pickem);\n`,
      ],
      [
        "trusted-items",
        `import { pickem } from "pickem";
export async function selectRelease() {
  const choices = [{ label: "trusted", value: "release-1" }];
  return pickem(choices);
}
`,
      ],
      [
        "remote-value-only",
        `import { pickem } from "pickem";
export async function selectRelease(apiUrl) {
  const releases = await (await fetch(apiUrl)).json();
  const choices = releases.map((release) => ({ label: "trusted", value: release.id }));
  return pickem(choices);
}
`,
      ],
      [
        "json-stringified-label",
        `import { pickem } from "pickem";
export async function selectRelease(apiUrl) {
  const releases = await (await fetch(apiUrl)).json();
  const choices = releases.map((release) => ({ label: JSON.stringify(release.title), value: release.id }));
  return pickem(choices);
}
`,
      ],
      [
        "sanitized-label",
        `import { pickem } from "pickem";
export async function selectRelease(apiUrl) {
  const releases = await (await fetch(apiUrl)).json();
  const choices = releases.map((release) => ({ label: sanitizeTerminalText(release.title), value: release.id }));
  return pickem(choices);
}
`,
      ],
      [
        "custom-formatter",
        `import { pickem } from "pickem";
export async function selectRelease(apiUrl) {
  const releases = await (await fetch(apiUrl)).json();
  const choices = releases.map((release) => ({ label: release.title, value: release.id }));
  return pickem(choices, { format: (item) => JSON.stringify(item.label) });
}
`,
      ],
      [
        "local-collection",
        `import { pickem } from "pickem";
export async function selectRelease() {
  const releases = [{ title: "trusted", id: "release-1" }];
  const choices = releases.map((release) => ({ label: release.title, value: release.id }));
  return pickem(choices);
}
`,
      ],
      [
        "local-lookalike",
        `function pickem(items) { return items[0].value; }
export async function selectRelease(apiUrl) {
  const releases = await (await fetch(apiUrl)).json();
  const choices = releases.map((release) => ({ label: release.title, value: release.id }));
  return pickem(choices);
}
`,
      ],
      [
        "binding-reassigned",
        `import { pickem } from "pickem";
pickem = localPicker;
export async function selectRelease(apiUrl) {
  const releases = await (await fetch(apiUrl)).json();
  const choices = releases.map((release) => ({ label: release.title, value: release.id }));
  return pickem(choices);
}
`,
      ],
      [
        "namespace-member-reassigned",
        `import * as Picker from "pickem";
Picker.pickem = localPicker;
export async function selectRelease(apiUrl) {
  const releases = await (await fetch(apiUrl)).json();
  const choices = releases.map((release) => ({ label: release.title, value: release.id }));
  return Picker.pickem(choices);
}
`,
      ],
      [
        "choices-reassigned",
        `import { pickem } from "pickem";
export async function selectRelease(apiUrl) {
  const releases = await (await fetch(apiUrl)).json();
  let choices = releases.map((release) => ({ label: release.title, value: release.id }));
  choices = trustedChoices;
  return pickem(choices);
}
`,
      ],
      [
        "collection-reassigned",
        `import { pickem } from "pickem";
export async function selectRelease(apiUrl) {
  let releases = await (await fetch(apiUrl)).json();
  releases = trustedReleases;
  const choices = releases.map((release) => ({ label: release.title, value: release.id }));
  return pickem(choices);
}
`,
      ],
      [
        "unexported-request-body",
        `import { pickem } from "pickem";
async function selectRelease(request) {
  const choices = request.body.releases.map((release) => ({ label: release.title, value: release.id }));
  return pickem(choices);
}
`,
      ],
    ];
    for (const [id, source] of cases) {
      await writeCase(repository, id, { source });
    }
    for (const [id] of cases) {
      expect(
        pickemRecords(await buildResidualRiskInventory(join(repository, id))),
        id,
      ).toEqual([]);
    }
  });

  test("keeps affected and repaired fixture application and witness bytes identical", async () => {
    const affectedRoot = join(
      benchmarkRoot,
      "fixtures",
      "node-pickem-terminal-control-injection",
    );
    const repairedRoot = join(
      benchmarkRoot,
      "fixtures",
      "node-pickem-terminal-control-isolated",
    );
    for (const path of [join("src", "select-release.js"), "witness.test.mjs"]) {
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
    expect(affectedPackage.dependencies["pickem"]).toBe("1.0.6");
    expect(repairedPackage.dependencies["pickem"]).toBe("1.0.7");
  });

  test("requires byte-safe validation and disciplined impact claims", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-pickem-terminal-control-injection");
    expect(prompt).toContain("GHSA-8qx3-8gm5-9cj2");
    expect(prompt).toContain("pickem before 1.0.7");
    expect(prompt).toContain("print only booleans or escaped JSON");
    expect(prompt).toContain("OSC 52 string is a clipboard-write primitive");
    expect(prompt).toContain("never place an executable command");
    expect(prompt).toContain("CWE-150");
  });
});
