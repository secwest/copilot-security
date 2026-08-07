import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface FrameworkRecord {
  path: string;
  line: number;
  categories: string[];
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
      acceptableSeverities?: string[];
      requireValidation?: boolean;
      requireAttackPath?: boolean;
      requireCodeEvidence?: boolean;
    }>;
  }>;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function records(inventory: string, id: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter((record) => record.frameworkModel?.id === id);
}

function chainRecords(inventory: string): FrameworkRecord[] {
  return records(inventory, "node-http-axios-prototype-gadget-chain");
}

const pollutionSource = [
  'import lodash from "lodash";',
  "export function applyPatch(request) {",
  "  return lodash.merge({}, request.body);",
  "}",
  "",
].join("\n");

async function writeCase(
  repository: string,
  id: string,
  axiosVersion: string,
  clientSource: string,
  options: {
    axiosSection?: "dependencies" | "devDependencies";
    lodashVersion?: string;
    clientName?: string;
    pollution?: string;
  } = {},
): Promise<void> {
  const root = join(repository, id);
  await mkdir(root, { recursive: true });
  const axiosSection = options.axiosSection ?? "dependencies";
  await writeFile(
    join(root, "package.json"),
    JSON.stringify(
      {
        name: id,
        private: true,
        dependencies: {
          lodash: options.lodashVersion ?? "4.17.10",
          ...(axiosSection === "dependencies" ? { axios: axiosVersion } : {}),
        },
        ...(axiosSection === "devDependencies"
          ? { devDependencies: { axios: axiosVersion } }
          : {}),
      },
      null,
      2,
    ),
  );
  await writeFile(
    join(root, "pollution.mjs"),
    options.pollution ?? pollutionSource,
  );
  await writeFile(join(root, options.clientName ?? "client.mjs"), clientSource);
}

async function writeLockedCase(
  repository: string,
  id: string,
  options: {
    lockfileVersion?: number;
    axiosInstalled?: string;
    axiosRoot?: string;
    includeAxiosInstall?: boolean;
  } = {},
): Promise<void> {
  const root = join(repository, id);
  await mkdir(root, { recursive: true });
  const axiosDeclaration = "^1.16.0";
  const lodashDeclaration = "^4.17.0";
  await writeFile(
    join(root, "package.json"),
    JSON.stringify(
      {
        name: id,
        private: true,
        dependencies: { axios: axiosDeclaration, lodash: lodashDeclaration },
      },
      null,
      2,
    ),
  );
  await writeFile(join(root, "pollution.mjs"), pollutionSource);
  await writeFile(
    join(root, "client.mjs"),
    [
      'import axios from "axios";',
      "const api = axios.create();",
      "api.interceptors.request.use((config) => ({ ...config }));",
      'export function send() { return api.get("http://internal.test/secret"); }',
      "",
    ].join("\n"),
  );
  await writeFile(
    join(root, "package-lock.json"),
    JSON.stringify(
      {
        name: id,
        lockfileVersion: options.lockfileVersion ?? 3,
        packages: {
          "": {
            dependencies: {
              axios: options.axiosRoot ?? axiosDeclaration,
              lodash: lodashDeclaration,
            },
          },
          ...(options.includeAxiosInstall === false
            ? {}
            : {
                "node_modules/axios": {
                  version: options.axiosInstalled ?? "1.17.0",
                },
              }),
          "node_modules/lodash": { version: "4.17.10" },
        },
      },
      null,
      2,
    ),
  );
}

describe("Axios prototype-gadget attack-chain model", () => {
  test("models direct and interceptor-bypass release stages across official bindings", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-axios-gadget-versions-"),
    );
    temporaryPaths.push(repository);
    const rootDirect = [
      'import axios from "axios";',
      'export function send() { return axios.get("http://internal.test/secret"); }',
      "",
    ].join("\n");
    const cjsDirect = [
      'const transport = require("axios");',
      'exports.send = function send() { return transport.get("http://internal.test/secret"); };',
      "",
    ].join("\n");
    const spreadBypass = [
      'import axios from "axios";',
      "const api = axios.create();",
      "api.interceptors.request.use((config) => ({ ...config }));",
      'export function send() { return api.get("http://internal.test/secret"); }',
      "",
    ].join("\n");
    const assignBypass = [
      'import * as transport from "axios";',
      "transport.interceptors.request.use((config) => Object.assign({}, config));",
      'export function send() { return transport.post("http://internal.test/secret", {}); }',
      "",
    ].join("\n");
    await writeCase(repository, "direct-one", "1.15.1", rootDirect);
    await writeCase(repository, "direct-zero", "0.31.0", cjsDirect, {
      clientName: "client.cjs",
    });
    await writeCase(repository, "bypass-first", "1.15.2", spreadBypass);
    await writeCase(repository, "bypass-late", "1.17.0", assignBypass);
    await writeCase(repository, "hardened-one", "1.15.2", rootDirect);
    await writeCase(repository, "hardened-zero", "0.31.1", cjsDirect, {
      clientName: "client.cjs",
    });
    await writeCase(repository, "repaired-one", "1.18.0", spreadBypass);
    await writeCase(repository, "repaired-zero", "0.33.0", spreadBypass);

    const found = chainRecords(await buildResidualRiskInventory(repository));
    expect(found.map(({ path }) => path)).toEqual([
      "bypass-first/client.mjs",
      "bypass-late/client.mjs",
      "direct-one/client.mjs",
      "direct-zero/client.cjs",
    ]);
    expect(
      found.map((record) => record.frameworkModel?.sink.kind).sort(),
    ).toEqual([
      "vulnerable-axios-direct-prototype-gadget",
      "vulnerable-axios-direct-prototype-gadget",
      "vulnerable-axios-interceptor-proxy-gadget",
      "vulnerable-axios-interceptor-proxy-gadget",
    ]);
  });

  test("retains the complete source, state-write, dependency, interceptor, and gadget path", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-axios-gadget-path-"),
    );
    temporaryPaths.push(repository);
    await writeCase(
      repository,
      "chain",
      "1.17.0",
      [
        'import axios from "axios";',
        "const api = axios.create();",
        "api.interceptors.request.use((config) => ({ ...config }));",
        'export function send() { return api.post("http://internal.test/secret", { secret: true }); }',
        "",
      ].join("\n"),
    );
    const inventory = await buildResidualRiskInventory(repository);
    const found = chainRecords(inventory);
    expect(found).toHaveLength(1);
    expect(records(inventory, "node-http-prototype-merge")).toHaveLength(0);
    expect(found[0]?.frameworkModel).toMatchObject({
      id: "node-http-axios-prototype-gadget-chain",
      scope: "same-file",
      source: {
        kind: "http-request-field",
        path: "chain/pollution.mjs",
        line: 3,
      },
      sink: {
        kind: "vulnerable-axios-interceptor-proxy-gadget",
        path: "chain/client.mjs",
        line: 4,
        cweIds: ["CWE-1321", "CWE-441"],
      },
    });
    expect(found[0]?.frameworkModel?.propagators).toEqual([
      {
        kind: "prototype-pollution-state-write",
        path: "chain/pollution.mjs",
        line: 3,
        symbol: "vulnerable-lodash-recursive-merge",
      },
      {
        kind: "axios-runtime-dependency",
        path: "chain/package.json",
        line: 6,
        symbol: "axios@1.17.0:manifest-exact",
      },
      {
        kind: "axios-request-interceptor-rematerialization",
        path: "chain/client.mjs",
        line: 3,
        symbol: "api",
      },
      {
        kind: "shared-object-prototype-state",
        path: "chain/client.mjs",
        line: 4,
        symbol: "Object.prototype.proxy",
      },
    ]);
    expect(found[0]?.categories).toContain(
      "framework-cross-component-attack-chain",
    );
  });

  test("rejects identity interceptors, repaired primitives, local-only copies, and unsupported bindings", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-axios-gadget-negatives-"),
    );
    temporaryPaths.push(repository);
    const identity = [
      'import axios from "axios";',
      "const api = axios.create();",
      "api.interceptors.request.use((config) => config);",
      'export function send() { return api.get("http://internal.test/secret"); }',
      "",
    ].join("\n");
    const spread = [
      'import axios from "axios";',
      "const api = axios.create();",
      "api.interceptors.request.use((config) => ({ ...config }));",
      'export function send() { return api.get("http://internal.test/secret"); }',
      "",
    ].join("\n");
    await writeCase(repository, "identity", "1.17.0", identity);
    await writeCase(repository, "fixed-upstream", "1.17.0", spread, {
      lodashVersion: "4.17.11",
    });
    await writeCase(repository, "development-axios", "1.17.0", spread, {
      axiosSection: "devDependencies",
    });
    await writeCase(
      repository,
      "local-prototype-only",
      "1.15.1",
      'import axios from "axios";\nexport function send() { return axios.get("http://internal.test"); }\n',
      {
        lodashVersion: "4.17.11",
        pollution:
          "export function applyPatch(request) { return Object.assign({}, request.body); }\n",
      },
    );
    await writeCase(
      repository,
      "wrong-binding",
      "1.17.0",
      [
        'import transport from "ky";',
        "transport.interceptors.request.use((config) => ({ ...config }));",
        'export function send() { return transport.get("http://internal.test"); }',
        "",
      ].join("\n"),
    );
    await writeCase(
      repository,
      "reassigned",
      "1.17.0",
      [
        'import axios from "axios";',
        "const api = axios.create();",
        "api.interceptors.request.use((config) => ({ ...config }));",
        "api = localClient;",
        'export function send() { return api.get("http://internal.test"); }',
        "",
      ].join("\n"),
    );
    await writeCase(
      repository,
      "shadowed",
      "1.17.0",
      [
        'import axios from "axios";',
        "axios.interceptors.request.use((config) => ({ ...config }));",
        'export function send(axios) { return axios.get("http://internal.test"); }',
        "",
      ].join("\n"),
    );

    expect(
      chainRecords(await buildResidualRiskInventory(repository)),
    ).toHaveLength(0);
  });

  test("distinguishes post-hardening proxy controls from the earlier validator stage", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-axios-gadget-controls-"),
    );
    temporaryPaths.push(repository);
    const spreadFalse = [
      'import axios from "axios";',
      "const api = axios.create();",
      "api.interceptors.request.use((config) => ({ ...config, proxy: false }));",
      'export function send() { return api.get("http://internal.test/secret"); }',
      "",
    ].join("\n");
    const instanceFalse = [
      'import axios from "axios";',
      "const api = axios.create({ proxy: false });",
      "api.interceptors.request.use((config) => ({ ...config }));",
      'export function send() { return api.get("http://internal.test/secret"); }',
      "",
    ].join("\n");
    const callFalse = [
      'import axios from "axios";',
      "const api = axios.create();",
      "api.interceptors.request.use((config) => Object.assign({}, config));",
      'export function send() { return api.get("http://internal.test/secret", { proxy: false }); }',
      "",
    ].join("\n");
    const directFalse = [
      'import axios from "axios";',
      'export function send() { return axios.get("http://internal.test/secret", { proxy: false }); }',
      "",
    ].join("\n");
    await writeCase(repository, "spread-false", "1.17.0", spreadFalse);
    await writeCase(repository, "instance-false", "1.17.0", instanceFalse);
    await writeCase(repository, "call-false", "1.17.0", callFalse);
    await writeCase(repository, "direct-false", "1.15.1", directFalse);

    const found = chainRecords(await buildResidualRiskInventory(repository));
    expect(found.map(({ path }) => path)).toEqual(["direct-false/client.mjs"]);
    expect(found[0]?.frameworkModel?.candidateControls).toEqual([
      {
        kind: "own-axios-proxy-disabled",
        path: "direct-false/client.mjs",
        line: 2,
      },
    ]);
  });

  test("requires fresh declaration-consistent npm lock proof", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-axios-gadget-locks-"),
    );
    temporaryPaths.push(repository);
    await writeLockedCase(repository, "valid");
    await writeLockedCase(repository, "missing-install", {
      includeAxiosInstall: false,
    });
    await writeLockedCase(repository, "stale-root", {
      axiosRoot: "~1.16.0",
    });
    await writeLockedCase(repository, "old-lock", { lockfileVersion: 1 });
    await writeCase(
      repository,
      "range-without-lock",
      "^1.16.0",
      'import axios from "axios";\naxios.interceptors.request.use((config) => ({ ...config }));\nexport function send() { return axios.get("http://internal.test"); }\n',
    );

    const found = chainRecords(await buildResidualRiskInventory(repository));
    expect(found).toHaveLength(1);
    expect(found[0]?.path).toBe("valid/client.mjs");
    expect(found[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-axios-interceptor-proxy-gadget",
    );
    expect(found[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "axios-runtime-dependency",
      path: "valid/package.json",
      line: 5,
      symbol: "axios@1.17.0:npm-lockfile",
    });
  });

  test("survives candidate density and gives the reviewer exact chain constraints", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-axios-gadget-density-"),
    );
    temporaryPaths.push(repository);
    const noise = Array.from(
      { length: 40 },
      (_, index) => `helper${index}();`,
    ).join("\n");
    await writeCase(
      repository,
      "dense",
      "1.17.0",
      [
        'import axios from "axios";',
        "const api = axios.create();",
        "api.interceptors.request.use((config) => ({ ...config }));",
        noise,
        'export function send() { return api.get("http://internal.test/secret"); }',
        "",
      ].join("\n"),
    );
    expect(
      chainRecords(await buildResidualRiskInventory(repository)),
    ).toHaveLength(1);
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-axios-prototype-gadget-chain");
    expect(prompt).toContain("1.15.2 through 1.17.x");
    expect(prompt).toContain("CWE-441");
    expect(prompt).toContain("config.proxy");
  });

  test("keeps the benchmark pair strict and topology complete", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-axios-prototype-gadget-chain-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;
    expect(manifest.schemaVersion).toBe("1.0");
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-multi-hop-axios-prototype-gadget-chain",
      "node-multi-hop-patched-axios-prototype-gadget-chain",
    ]);
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBe(true);
    expect(manifest.thresholds["minPrecision"]).toBe(1);
    expect(manifest.thresholds["minRecall"]).toBe(1);
    expect(manifest.thresholds["maxFalsePositivesPerRun"]).toBe(0);
    const positive = manifest.cases[0]!;
    expect(positive.findingsPaths).toHaveLength(1);
    expect(positive.expected[0]).toMatchObject({
      cwe: ["CWE-1321", "CWE-441"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);

    const inventory = await buildResidualRiskInventory(
      join(
        benchmarkRoot,
        "fixtures",
        "node-multi-hop-axios-prototype-gadget-chain",
      ),
    );
    const found = chainRecords(inventory);
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-multi-hop-wrapper",
      source: { path: "src/server.js", line: 12 },
      sink: {
        path: "src/server.js",
        line: 13,
        kind: "vulnerable-axios-interceptor-proxy-gadget",
      },
    });
    expect(found[0]?.frameworkModel?.propagators).toHaveLength(13);
    expect(
      chainRecords(
        await buildResidualRiskInventory(
          join(
            benchmarkRoot,
            "fixtures",
            "node-multi-hop-patched-axios-prototype-gadget-chain",
          ),
        ),
      ),
    ).toHaveLength(0);
  });
});
