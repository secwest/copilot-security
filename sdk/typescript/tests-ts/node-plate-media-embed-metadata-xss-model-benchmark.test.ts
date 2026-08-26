import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface PlateRecord {
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
  loaderSource?: string;
  lock?: boolean;
  lockedVersion?: string;
  lockfileVersion?: number;
  mediaSource?: string;
  packageName?: string;
  rootLockDeclaration?: string;
  viewerSource?: string;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const temporaryPaths: string[] = [];

const defaultMediaSource = `import { parseVideoUrl } from "@platejs/media";
import { useMediaState } from "@platejs/media/react";
export function MediaEmbedElement(props) {
  const { embed, isVideo } = useMediaState({ urlParsers: [parseVideoUrl] });
  if (!embed || !isVideo) return null;
  return <iframe title="Embedded media" src={embed.url} />;
}
`;

const defaultViewerSource = `import { MediaEmbedPlugin } from "@platejs/media/react";
import { Plate } from "platejs/react";
import { MediaEmbedElement } from "./media-embed-node.jsx";
const plugins = [MediaEmbedPlugin.withComponent(MediaEmbedElement)];
export function DocumentViewer(props) {
  return <Plate plugins={plugins} value={props.document} />;
}
`;

const defaultLoaderSource = `import { DocumentViewer } from "./document-viewer.jsx";
export async function StoredDocument(props) {
  const response = await fetch("/api/documents/" + props.id);
  const document = await response.json();
  return <DocumentViewer document={document} />;
}
`;

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function plateRecords(inventory: string): PlateRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as PlateRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-plate-media-embed-metadata-xss",
    );
}

async function temporaryRepository(label: string): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), `copilot-security-plate-${label}-`),
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
  const declaration = options.declaration ?? "53.0.1";
  const dependencySection = options.dependencySection ?? "dependencies";
  const packageName = options.packageName ?? "@platejs/media";
  await mkdir(join(root, "src"), { recursive: true });
  await writeFile(
    join(root, "package.json"),
    JSON.stringify(
      {
        name: id,
        private: true,
        [dependencySection]: {
          [packageName]: declaration,
          platejs: "53.0.0",
        },
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
                [packageName]: { version: options.lockedVersion ?? "53.0.1" },
              },
            }
          : {
              name: id,
              lockfileVersion,
              packages: {
                "": {
                  [dependencySection]: {
                    [packageName]: options.rootLockDeclaration ?? declaration,
                    platejs: "53.0.0",
                  },
                },
                [`node_modules/${packageName}`]: {
                  version: options.lockedVersion ?? "53.0.1",
                },
                "node_modules/platejs": { version: "53.0.0" },
              },
            },
        null,
        2,
      ),
    );
  }
  await writeFile(
    join(root, "src", "media-embed-node.jsx"),
    options.mediaSource ?? defaultMediaSource,
  );
  await writeFile(
    join(root, "src", "document-viewer.jsx"),
    options.viewerSource ?? defaultViewerSource,
  );
  await writeFile(
    join(root, "src", "load-document.jsx"),
    options.loaderSource ?? defaultLoaderSource,
  );
}

describe("Plate serialized media metadata XSS model", () => {
  test("keeps a strict affected and repaired executable benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-plate-media-embed-metadata-xss-manifest.json",
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
      "node-plate-media-embed-metadata-xss",
      "node-plate-media-embed-metadata-isolated",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-79"],
      acceptableSeverities: ["high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
      locations: [{ startLine: 9, endLine: 9 }],
    });
    expect(manifest.cases[1]?.expected).toEqual([]);

    const affected = plateRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-plate-media-embed-metadata-xss"),
      ),
    );
    const repaired = plateRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-plate-media-embed-metadata-isolated",
        ),
      ),
    );
    expect(affected).toHaveLength(1);
    expect(repaired).toHaveLength(0);
    expect(affected[0]).toMatchObject({
      path: "src/media-embed-node.jsx",
      line: 9,
      frameworkModel: {
        scope: "cross-file-multi-hop-wrapper",
        source: {
          kind: "remote-serialized-plate-document",
          path: "src/load-document.jsx",
          line: 5,
        },
        sink: {
          kind: "vulnerable-plate-media-embed-iframe-url",
          path: "src/media-embed-node.jsx",
          line: 9,
          cweIds: ["CWE-79"],
        },
      },
    });
    expect(affected[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "plate-document-component-prop",
          symbol: "document->DocumentViewer.document",
        }),
        expect.objectContaining({
          kind: "plate-editor-value",
          symbol: "document",
        }),
        expect.objectContaining({
          kind: "plate-media-embed-plugin-component",
          symbol: "plugins:MediaEmbedElement",
        }),
        expect.objectContaining({
          kind: "plate-media-state-url-parsers",
          symbol: "parseVideoUrl",
        }),
        expect.objectContaining({
          kind: "plate-media-runtime-dependency",
          symbol:
            "@platejs/media@53.0.1:manifest-exact:serialized-provider-url-fast-path",
        }),
      ]),
    );
  });

  test("enforces the exact stable advisory interval", async () => {
    const repository = await temporaryRepository("versions");
    const cases = [
      ["before", "52.3.10", false],
      ["first", "53.0.0", true],
      ["published-affected", "53.0.1", true],
      ["advisory-middle", "53.1.0", true],
      ["advisory-last", "53.1.3", true],
      ["fixed", "53.1.4", false],
      ["later", "53.2.0", false],
      ["prerelease", "53.1.3-beta.1", false],
      ["later-major", "54.0.0", false],
    ] as const;
    await Promise.all(
      cases.map(([id, declaration]) =>
        writeCase(repository, id, { declaration }),
      ),
    );
    const found = new Set(
      plateRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path.split("/")[0],
      ),
    );
    for (const [id, , expected] of cases) {
      expect(found.has(id)).toBe(expected);
    }
  });

  test("requires exact production provenance or a fresh npm v2/v3 resolution", async () => {
    const repository = await temporaryRepository("provenance");
    await Promise.all([
      writeCase(repository, "exact"),
      writeCase(repository, "lock-v2", {
        declaration: "^53.0.0",
        lock: true,
        lockedVersion: "53.0.1",
        lockfileVersion: 2,
      }),
      writeCase(repository, "lock-v3", {
        declaration: "~53.0.0",
        lock: true,
        lockedVersion: "53.0.1",
      }),
      writeCase(repository, "dev-only", {
        dependencySection: "devDependencies",
      }),
      writeCase(repository, "range-without-lock", { declaration: "^53.0.0" }),
      writeCase(repository, "wrong-package", {
        packageName: "@platejs/media-fork",
      }),
      writeCase(repository, "stale-lock", {
        declaration: "^53.0.0",
        lock: true,
        lockedVersion: "53.0.1",
        rootLockDeclaration: "^52.0.0",
      }),
      writeCase(repository, "v1-lock", {
        declaration: "^53.0.0",
        lock: true,
        lockedVersion: "53.0.1",
        lockfileVersion: 1,
      }),
      writeCase(repository, "repaired-lock", {
        declaration: "^53.0.0",
        lock: true,
        lockedVersion: "53.1.4",
      }),
    ]);
    const found = plateRecords(await buildResidualRiskInventory(repository));
    expect(found.map(({ path }) => path.split("/")[0]).sort()).toEqual([
      "exact",
      "lock-v2",
      "lock-v3",
    ]);
    expect(
      found
        .filter(({ path }) => path.startsWith("lock-"))
        .every((record) =>
          record.frameworkModel?.sink.kind.startsWith("lock-resolved-"),
        ),
    ).toBe(true);
  });

  test("recognizes official import forms, hook result forms, and initialValue", async () => {
    const repository = await temporaryRepository("bindings");
    const bindingCases = [
      {
        id: "alias",
        hook: 'import { useMediaState as mediaState } from "@platejs/media/react";',
        hookCall: "mediaState",
        plugin:
          'import { MediaEmbedPlugin as MediaPlugin } from "@platejs/media/react";',
        pluginCall: "MediaPlugin",
      },
      {
        id: "namespace",
        hook: 'import * as MediaReact from "@platejs/media/react";',
        hookCall: "MediaReact.useMediaState",
        plugin: 'import * as MediaReact from "@platejs/media/react";',
        pluginCall: "MediaReact.MediaEmbedPlugin",
      },
      {
        id: "import-equals",
        hook: 'import MediaReact = require("@platejs/media/react");',
        hookCall: "MediaReact.useMediaState",
        plugin: 'import MediaReact = require("@platejs/media/react");',
        pluginCall: "MediaReact.MediaEmbedPlugin",
      },
      {
        id: "commonjs",
        hook: 'const MediaReact = require("@platejs/media/react");',
        hookCall: "MediaReact.useMediaState",
        plugin: 'const MediaReact = require("@platejs/media/react");',
        pluginCall: "MediaReact.MediaEmbedPlugin",
      },
      {
        id: "direct-require",
        hook: 'const mediaState = require("@platejs/media/react").useMediaState;',
        hookCall: "mediaState",
        plugin:
          'const MediaPlugin = require("@platejs/media/react").MediaEmbedPlugin;',
        pluginCall: "MediaPlugin",
      },
    ] as const;
    await Promise.all(
      bindingCases.map(({ id, hook, hookCall, plugin, pluginCall }) =>
        writeCase(repository, id, {
          mediaSource: `import { parseVideoUrl } from "@platejs/media";
${hook}
export function MediaEmbedElement(props) {
  const state = ${hookCall}({ urlParsers: [parseVideoUrl] });
  if (!state.embed || !state.isVideo) return null;
  return <iframe src={state.embed.url} />;
}
`,
          viewerSource: `${plugin}
import { Plate } from "platejs/react";
import { MediaEmbedElement } from "./media-embed-node.jsx";
const plugins = [${pluginCall}.withComponent(MediaEmbedElement)];
export function DocumentViewer({ document: value }) {
  return <Plate plugins={plugins} initialValue={value} />;
}
`,
        }),
      ),
    );
    expect(
      plateRecords(await buildResidualRiskInventory(repository))
        .map(({ path }) => path.split("/")[0])
        .sort(),
    ).toEqual(bindingCases.map(({ id }) => id).sort());
  });

  test("fails closed when any required reachable topology edge or control is absent", async () => {
    const repository = await temporaryRepository("negatives");
    const cases: Array<[string, CaseOptions]> = [
      [
        "empty-parsers",
        { mediaSource: defaultMediaSource.replace("[parseVideoUrl]", "[]") },
      ],
      [
        "no-video-gate",
        {
          mediaSource: defaultMediaSource.replace(
            "if (!embed || !isVideo) return null;",
            "if (!embed) return null;",
          ),
        },
      ],
      [
        "wrong-iframe-value",
        { mediaSource: defaultMediaSource.replace("embed.url", "props.url") },
      ],
      [
        "script-blocking-sandbox",
        {
          mediaSource: defaultMediaSource.replace(
            '<iframe title="Embedded media"',
            '<iframe sandbox="" title="Embedded media"',
          ),
        },
      ],
      [
        "unregistered-component",
        {
          viewerSource: defaultViewerSource.replace(
            "MediaEmbedPlugin.withComponent(MediaEmbedElement)",
            "MediaEmbedPlugin",
          ),
        },
      ],
      [
        "trusted-static-value",
        {
          viewerSource: defaultViewerSource.replace(
            "value={props.document}",
            "value={trustedDocument}",
          ),
        },
      ],
      [
        "sanitized-document",
        {
          loaderSource: defaultLoaderSource.replace(
            "return <DocumentViewer document={document} />;",
            "const clean = sanitizeDocument(document);\n  return <DocumentViewer document={clean} />;",
          ),
        },
      ],
      [
        "reassigned-plugin-array",
        {
          viewerSource: defaultViewerSource.replace(
            "export function DocumentViewer(props)",
            "plugins = [];\nexport function DocumentViewer(props)",
          ),
        },
      ],
      [
        "local-hook-lookalike",
        {
          mediaSource: defaultMediaSource.replace(
            'import { useMediaState } from "@platejs/media/react";',
            "const useMediaState = localMediaState;",
          ),
        },
      ],
    ];
    await Promise.all(
      cases.map(([id, options]) => writeCase(repository, id, options)),
    );
    expect(plateRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("accepts a direct HTTP request body but rejects reassignment before use", async () => {
    const repository = await temporaryRepository("sources");
    await Promise.all([
      writeCase(repository, "request-body", {
        loaderSource: `import { DocumentViewer } from "./document-viewer.jsx";
export function preview(request) {
  const document = request.body;
  return <DocumentViewer document={document} />;
}
`,
      }),
      writeCase(repository, "reassigned", {
        loaderSource: `import { DocumentViewer } from "./document-viewer.jsx";
export async function preview() {
  const response = await fetch("/api/document");
  let document = await response.json();
  document = trustedFallback;
  return <DocumentViewer document={document} />;
}
`,
      }),
    ]);
    const records = plateRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(1);
    expect(records[0]?.path).toStartWith("request-body/");
    expect(records[0]?.frameworkModel?.source).toMatchObject({
      kind: "remote-serialized-plate-document",
      line: 3,
    });
  });

  test("keeps source-identical pair evidence and model-specific correction rules", async () => {
    const affectedRoot = join(
      benchmarkRoot,
      "fixtures",
      "node-plate-media-embed-metadata-xss",
    );
    const repairedRoot = join(
      benchmarkRoot,
      "fixtures",
      "node-plate-media-embed-metadata-isolated",
    );
    for (const path of [
      "src/load-document.jsx",
      "src/document-viewer.jsx",
      "src/media-embed-node.jsx",
      "witness.test.mjs",
    ]) {
      expect(await readFile(join(affectedRoot, path), "utf8")).toBe(
        await readFile(join(repairedRoot, path), "utf8"),
      );
    }
    const affectedPackage = JSON.parse(
      await readFile(join(affectedRoot, "package.json"), "utf8"),
    ) as { dependencies: Record<string, string> };
    const repairedPackage = JSON.parse(
      await readFile(join(repairedRoot, "package.json"), "utf8"),
    ) as { dependencies: Record<string, string> };
    expect(affectedPackage.dependencies["@platejs/media"]).toBe("53.0.1");
    expect(repairedPackage.dependencies["@platejs/media"]).toBe("53.1.4");

    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-plate-media-embed-metadata-xss");
    expect(prompt).toContain("GHSA-qj6x-xx2h-8hvv / CVE-2026-55596");
    expect(prompt).toContain("javascript:parent.postMessage sentinel");
    expect(prompt).toContain(
      "Compare identical source and document bytes with 53.1.4",
    );
    expect(prompt).toContain("Report CWE-79");
    expect(prompt).toContain("Do not infer account takeover");
  });
});
