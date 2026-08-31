import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import {
  buildFindingQualityGapInventory,
  buildResidualRiskInventory,
} from "../src/residual-risk.js";

interface FrameworkRecord {
  frameworkModel?: {
    id: string;
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

const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function vueRequestForgeryRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-vue-router-client-request-forgery",
    );
}

async function scanVueSource(
  source: string,
  options: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    sourcePath?: string;
    vueRouterVersion?: string;
  } = {},
): Promise<FrameworkRecord[]> {
  const repository = await mkdtemp(join(tmpdir(), "vue-router-csrf-model-"));
  temporaryPaths.push(repository);
  await writeFile(
    join(repository, "package.json"),
    JSON.stringify({
      name: "vue-router-csrf-model",
      private: true,
      dependencies:
        options.dependencies ??
        (options.vueRouterVersion === undefined
          ? { "vue-router": "5.2.0" }
          : { "vue-router": options.vueRouterVersion }),
      ...(options.devDependencies === undefined
        ? {}
        : { devDependencies: options.devDependencies }),
    }),
  );
  const sourcePath = options.sourcePath ?? "component.js";
  await writeFile(join(repository, sourcePath), source);
  return vueRequestForgeryRecords(await buildResidualRiskInventory(repository));
}

describe("Node Vue Router client-side request-forgery model", () => {
  test("keeps the versioned vulnerable and control fixtures paired", async () => {
    const fixtureRoot = resolve(
      process.cwd(),
      "..",
      "..",
      "benchmarks",
      "fixtures",
    );
    const vulnerable = vueRequestForgeryRecords(
      await buildResidualRiskInventory(
        join(fixtureRoot, "node-vue-router-client-request-forgery"),
      ),
    );
    const control = vueRequestForgeryRecords(
      await buildResidualRiskInventory(
        join(fixtureRoot, "node-vue-router-fixed-endpoint-request"),
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      source: { kind: "vue-router-browser-url-query", line: 5 },
      sink: { kind: "browser-fetch-request-url", line: 6 },
    });
    expect(control).toHaveLength(0);
  });

  test("detects an aliased useRoute query field at built-in fetch argument zero", async () => {
    const found = await scanVueSource(
      [
        'import { useRoute as currentRoute } from "vue-router";',
        "export async function loadProfile() {",
        "  const route = currentRoute();",
        "  const target = route.query.target;",
        '  return fetch("/api/profile/" + target);',
        "}",
      ].join("\n"),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      id: "node-vue-router-client-request-forgery",
      source: {
        kind: "vue-router-browser-url-query",
        path: "component.js",
        line: 4,
      },
      sink: {
        kind: "browser-fetch-request-url",
        path: "component.js",
        line: 5,
        cweIds: ["CWE-918"],
      },
      propagators: expect.arrayContaining([
        expect.objectContaining({ kind: "vue-router-use-route-binding" }),
        expect.objectContaining({
          kind: "vue-router-current-route-location",
          symbol: "route",
        }),
        expect.objectContaining({
          kind: "vue-router-runtime-dependency",
          symbol: "vue-router@5.2.0:manifest-exact",
        }),
      ]),
    });
  });

  test("covers query, parameter, path, full-path, and fragment route sources", async () => {
    const cases = [
      ["route.query.target", "vue-router-browser-url-query"],
      ["route.params.target", "vue-router-browser-url-path"],
      ["route.path", "vue-router-browser-url-path"],
      ["route.fullPath", "vue-router-browser-url-path"],
      ["route.hash", "vue-router-browser-url-fragment"],
    ] as const;
    for (const [source, kind] of cases) {
      const found = await scanVueSource(
        [
          'import { useRoute } from "vue-router";',
          "export function loadResource() {",
          "  const route = useRoute();",
          `  return fetch(${source});`,
          "}",
        ].join("\n"),
      );
      expect(found, source).toHaveLength(1);
      expect(found[0]?.frameworkModel?.source.kind, source).toBe(kind);
    }
  });

  test("supports Vue Router 4 and namespace plus CommonJS bindings", async () => {
    const namespace = await scanVueSource(
      [
        'import * as VueRouter from "vue-router";',
        "export function loadResource() {",
        "  const route = VueRouter.useRoute();",
        '  return window.fetch("/api/items/" + route.params.id);',
        "}",
      ].join("\n"),
      { vueRouterVersion: "4.6.3" },
    );
    expect(namespace).toHaveLength(1);

    const commonjs = await scanVueSource(
      [
        'const { useRoute: currentRoute } = require("vue-router");',
        "exports.loadResource = function () {",
        "  const route = currentRoute();",
        '  return globalThis.fetch("/api/items/" + route.params.id);',
        "};",
      ].join("\n"),
    );
    expect(commonjs).toHaveLength(1);
  });

  test("supports Vue script setup and literal bracket route members", async () => {
    const found = await scanVueSource(
      [
        '<script setup lang="ts">',
        'import { useRoute } from "vue-router";',
        "const route = useRoute();",
        'const request = fetch("/api/items/" + route["params"]["id"]);',
        "</script>",
        "<template><div /></template>",
      ].join("\n"),
      { sourcePath: "ProfileLoader.vue" },
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      source: {
        kind: "vue-router-browser-url-path",
        path: "ProfileLoader.vue",
        line: 4,
      },
      sink: { path: "ProfileLoader.vue", line: 4 },
    });
  });

  test("keeps path concatenation reportable but credits query boundaries", async () => {
    const path = await scanVueSource(
      [
        'import { useRoute } from "vue-router";',
        "export function loadResource() {",
        "  const route = useRoute();",
        '  const url = "/api/items/" + route.query.id;',
        "  return fetch(url);",
        "}",
      ].join("\n"),
    );
    expect(path).toHaveLength(1);

    const query = await scanVueSource(
      [
        'import { useRoute } from "vue-router";',
        "export function search() {",
        "  const route = useRoute();",
        '  const url = "/api/search?q=" + route.query.q;',
        "  return fetch(url);",
        "}",
      ].join("\n"),
    );
    expect(query).toHaveLength(0);
  });

  test("credits URI encoding and conservatively rejects opaque transformations", async () => {
    const encoded = await scanVueSource(
      [
        'import { useRoute } from "vue-router";',
        "export function search() {",
        "  const route = useRoute();",
        '  const url = "/api/search?q=" + encodeURIComponent(route.query.q);',
        "  return fetch(url);",
        "}",
      ].join("\n"),
    );
    expect(encoded).toHaveLength(0);

    const opaque = await scanVueSource(
      [
        'import { useRoute } from "vue-router";',
        "export function loadResource() {",
        "  const route = useRoute();",
        "  const target = applicationPolicy(route.fullPath);",
        "  return fetch(target);",
        "}",
      ].join("\n"),
    );
    expect(opaque).toHaveLength(0);
  });

  test("requires Vue Router, source, request boundary, control, and CWE evidence", async () => {
    const repository = resolve(
      process.cwd(),
      "..",
      "..",
      "benchmarks",
      "fixtures",
      "node-vue-router-client-request-forgery",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(join(tmpdir(), "vue-router-quality-"));
    temporaryPaths.push(scanDirectory);
    const finding: any = {
      occurrenceId: "occ_vue_router_request_forgery_quality",
      taxonomy: { cwe: ["CWE-918"] },
      locations: [
        { path: "src/ProfileLoader.vue", startLine: 5, role: "source" },
        { path: "src/ProfileLoader.vue", startLine: 6, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "vue-route-source",
          path: "src/ProfileLoader.vue",
          startLine: 5,
          code: "const resource = route.query.resource;",
          explanation: "Current Vue Router query field.",
          role: "source",
        },
        {
          id: "browser-fetch-sink",
          path: "src/ProfileLoader.vue",
          startLine: 6,
          code: 'const profilePromise = fetch("/api/profile/" + resource);',
          explanation: "Browser request URL at fetch argument zero.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A route value reaches a request.",
        method: "source review",
        evidence: ["vue-route-source", "browser-fetch-sink"],
      },
      attackPath: {
        summary: "A route value reaches a request.",
        dataflow: {
          source: "vue-route-source",
          sink: "browser-fetch-sink",
          outcome: "request",
        },
        evidenceRefs: ["vue-route-source", "browser-fetch-sink"],
      },
    };
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );
    const incomplete = await buildFindingQualityGapInventory(
      scanDirectory,
      repository,
      inventory,
    );
    expect(incomplete).toContain("missing_model_specific_validation_evidence");
    expect(incomplete).toContain("missing_model_specific_attack_path_evidence");

    const contract =
      "Vue Router 5 at vue-router@5.2.0 supplies the current route through useRoute. Its route.query browser URL value reaches fetch argument zero, the browser request URL. Browser URL resolution permits path traversal to an unintended API endpoint because encodeURIComponent, a fixed endpoint, pathname restriction, or allowlist is absent; this is CWE-918 client-side request forgery.";
    finding.validation.summary = contract;
    finding.attackPath.summary = contract;
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );
    const complete = await buildFindingQualityGapInventory(
      scanDirectory,
      repository,
      inventory,
    );
    expect(complete).not.toContain(
      "missing_model_specific_validation_evidence",
    );
    expect(complete).not.toContain(
      "missing_model_specific_attack_path_evidence",
    );
  });

  test("teaches the reviewer the Vue route and browser request boundary", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"node-vue-router-client-request-forgery"}}',
    );
    expect(prompt).toContain("node-vue-router-client-request-forgery");
    expect(prompt).toContain("production vue-router 4 or 5 dependency");
    expect(prompt).toContain("useRoute");
    expect(prompt).toContain("fullPath");
    expect(prompt).toContain("argument zero");
    expect(prompt).toContain("encodeURIComponent");
    expect(prompt).toContain("CWE-918");
    expect(prompt).toContain("credentials are sent");
  });

  const rejectedCases: Array<
    [string, string, Parameters<typeof scanVueSource>[1]?]
  > = [
    [
      "a local useRoute lookalike",
      [
        'import { useRoute } from "./router.js";',
        "export function load() {",
        "  const route = useRoute();",
        "  return fetch(route.fullPath);",
        "}",
      ].join("\n"),
    ],
    [
      "Vue Router 3",
      [
        'import { useRoute } from "vue-router";',
        "export function load() {",
        "  const route = useRoute();",
        "  return fetch(route.fullPath);",
        "}",
      ].join("\n"),
      { vueRouterVersion: "3.6.5" },
    ],
    [
      "an unresolved dependency range",
      [
        'import { useRoute } from "vue-router";',
        "export function load() {",
        "  const route = useRoute();",
        "  return fetch(route.fullPath);",
        "}",
      ].join("\n"),
      { vueRouterVersion: "^5.2.0" },
    ],
    [
      "a development-only dependency",
      [
        'import { useRoute } from "vue-router";',
        "export function load() {",
        "  const route = useRoute();",
        "  return fetch(route.fullPath);",
        "}",
      ].join("\n"),
      { dependencies: {}, devDependencies: { "vue-router": "5.2.0" } },
    ],
    [
      "a test file",
      [
        'import { useRoute } from "vue-router";',
        "export function load() {",
        "  const route = useRoute();",
        "  return fetch(route.fullPath);",
        "}",
      ].join("\n"),
      { sourcePath: "component.test.js" },
    ],
    [
      "a parameter-shadowed useRoute binding",
      [
        'import { useRoute } from "vue-router";',
        "export function load(useRoute) {",
        "  const route = useRoute();",
        "  return fetch(route.fullPath);",
        "}",
      ].join("\n"),
    ],
    [
      "a reassigned route location member",
      [
        'import { useRoute } from "vue-router";',
        "export function load() {",
        "  const route = useRoute();",
        '  route.fullPath = "/fixed";',
        "  return fetch(route.fullPath);",
        "}",
      ].join("\n"),
    ],
    [
      "a parameter-shadowed fetch",
      [
        'import { useRoute } from "vue-router";',
        "export function load(fetch) {",
        "  const route = useRoute();",
        "  return fetch(route.fullPath);",
        "}",
      ].join("\n"),
    ],
    [
      "an imported fetch",
      [
        'import { useRoute } from "vue-router";',
        'import fetch from "node-fetch";',
        "export function load() {",
        "  const route = useRoute();",
        "  return fetch(route.fullPath);",
        "}",
      ].join("\n"),
    ],
    [
      "an arbitrary receiver fetch method",
      [
        'import { useRoute } from "vue-router";',
        "export function load(client) {",
        "  const route = useRoute();",
        "  return client.fetch(route.fullPath);",
        "}",
      ].join("\n"),
    ],
    [
      "route data confined to fetch options",
      [
        'import { useRoute } from "vue-router";',
        "export function load() {",
        "  const route = useRoute();",
        '  return fetch("/api/fixed", { body: route.fullPath });',
        "}",
      ].join("\n"),
    ],
    [
      "an unsupported route member",
      [
        'import { useRoute } from "vue-router";',
        "export function load() {",
        "  const route = useRoute();",
        "  return fetch(route.meta.endpoint);",
        "}",
      ].join("\n"),
    ],
    [
      "a top-level useRoute call outside a function boundary",
      [
        'import { useRoute } from "vue-router";',
        "const route = useRoute();",
        "fetch(route.fullPath);",
      ].join("\n"),
    ],
  ];

  for (const [name, source, options] of rejectedCases) {
    test(`rejects ${name}`, async () => {
      expect(await scanVueSource(source, options)).toHaveLength(0);
    });
  }
});
