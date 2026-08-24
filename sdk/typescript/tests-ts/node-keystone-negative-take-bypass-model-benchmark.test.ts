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
const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function records(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-keystone-graphql-negative-take-bypass",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(
    join(tmpdir(), "copilot-security-node-keystone-negative-take-"),
  );
  temporaryPaths.push(root);
  return root;
}

async function writeCase(
  root: string,
  id: string,
  source: string,
  options: {
    packageName?: string;
    version?: string;
    section?: "dependencies" | "devDependencies";
  } = {},
): Promise<void> {
  const directory = join(root, id);
  await mkdir(directory, { recursive: true });
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({
      name: id,
      private: true,
      [options.section ?? "dependencies"]: {
        [options.packageName ?? "@keystone-6/core"]: options.version ?? "6.5.2",
      },
    }),
  );
  await writeFile(join(directory, "keystone.ts"), source);
}

const db = 'db: { provider: "sqlite", url: "file:./app.db" }';
const namedSource = `import { config, list } from "@keystone-6/core";
const lists = { Post: list({ graphql: { maxTake: 3 }, fields: {} }) };
export default config({ ${db}, lists });`;

describe("Keystone negative-take maxTake bypass framework model", () => {
  test("supports official ESM, namespace, TypeScript, CommonJS, and direct bindings", async () => {
    const root = await repository();
    const cases = [
      `import { config as defineConfig, list as defineList } from "@keystone-6/core";
const lists = { Post: defineList({ graphql: { maxTake: 3 }, fields: {} }) };
export default defineConfig({ ${db}, lists });`,
      `import * as keystone from "@keystone-6/core";
const lists = { Post: keystone.list({ graphql: { maxTake: 3 }, fields: {} }) };
export default keystone.config({ ${db}, lists });`,
      `import keystone = require("@keystone-6/core");
const lists = { Post: keystone.list({ graphql: { maxTake: 3 }, fields: {} }) };
export default keystone.config({ ${db}, lists });`,
      `const { config: defineConfig, list: defineList } = require("@keystone-6/core");
const lists = { Post: defineList({ graphql: { maxTake: 3 }, fields: {} }) };
module.exports = defineConfig({ ${db}, lists });`,
      `const keystone = require("@keystone-6/core");
const lists = { Post: keystone.list({ graphql: { maxTake: 3 }, fields: {} }) };
module.exports = keystone.config({ ${db}, lists });`,
      `const lists = { Post: require("@keystone-6/core").list({ graphql: { maxTake: 3 }, fields: {} }) };
module.exports = require("@keystone-6/core").config({ ${db}, lists });`,
    ];
    await Promise.all(
      cases.map((source, index) => writeCase(root, `case-${index}`, source)),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual(
      cases.map((_, index) => `case-${index}/keystone.ts`),
    );
    expect(
      found.every(
        (record) =>
          record.frameworkModel?.source.kind ===
            "untrusted-keystone-graphql-negative-take" &&
          record.frameworkModel.sink.kind ===
            "vulnerable-keystone-graphql-negative-take-max-take-bypass" &&
          record.frameworkModel.sink.cweIds.join(",") === "CWE-20,CWE-770",
      ),
    ).toBeTrue();
  });

  test("follows exported configuration aliases, wrappers, and relative list modules", async () => {
    const root = await repository();
    const directory = join(root, "cross-file");
    await mkdir(join(directory, "src"), { recursive: true });
    await writeFile(
      join(directory, "package.json"),
      JSON.stringify({
        name: "cross-file",
        private: true,
        dependencies: { "@keystone-6/core": "6.5.2" },
      }),
    );
    await writeFile(
      join(directory, "src", "schema.ts"),
      `import { list as defineList } from "@keystone-6/core";
const postOptions = { graphql: { maxTake: 25 }, fields: {} };
export const models = { Post: defineList(postOptions) };`,
    );
    await writeFile(
      join(directory, "src", "keystone.ts"),
      `import { config as defineConfig } from "@keystone-6/core";
import { models as lists } from "./schema";
const withDeployment = value => value;
const base = defineConfig({ ${db}, lists });
export default withDeployment(base);`,
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.path).toBe("cross-file/src/schema.ts");
    expect(found[0]?.frameworkModel?.source.path).toBe(
      "cross-file/src/keystone.ts",
    );
    expect(
      found[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("relative-keystone-lists-import");
  });

  test("requires exact or fresh declaration-consistent affected runtime proof", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(root, "last-vulnerable", namedSource),
      writeCase(root, "older-major", namedSource, { version: "5.0.2" }),
      writeCase(root, "patched", namedSource, { version: "6.5.3" }),
      writeCase(root, "later-major", namedSource, { version: "7.0.0" }),
      writeCase(root, "prerelease", namedSource, {
        version: "6.5.2-beta.1",
      }),
      writeCase(root, "range-no-lock", namedSource, { version: "^6.5.0" }),
      writeCase(root, "dev-only", namedSource, {
        section: "devDependencies",
      }),
      writeCase(root, "wrong-package", namedSource, {
        packageName: "keystone",
      }),
      writeCase(root, "locked", namedSource, { version: "^6.5.0" }),
      writeCase(root, "inconsistent-lock", namedSource, {
        version: "^6.5.3",
      }),
      writeCase(root, "v1-lock", namedSource, { version: "^6.5.0" }),
    ]);
    await writeFile(
      join(root, "locked", "package-lock.json"),
      JSON.stringify({
        name: "locked",
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { "@keystone-6/core": "^6.5.0" } },
          "node_modules/@keystone-6/core": { version: "6.5.2" },
        },
      }),
    );
    await writeFile(
      join(root, "inconsistent-lock", "package-lock.json"),
      JSON.stringify({
        name: "inconsistent-lock",
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { "@keystone-6/core": "^6.5.3" } },
          "node_modules/@keystone-6/core": { version: "6.5.2" },
        },
      }),
    );
    await writeFile(
      join(root, "v1-lock", "package-lock.json"),
      JSON.stringify({
        name: "v1-lock",
        lockfileVersion: 1,
        dependencies: { "@keystone-6/core": { version: "6.5.2" } },
      }),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual([
      "last-vulnerable/keystone.ts",
      "locked/keystone.ts",
      "older-major/keystone.ts",
    ]);
    const locked = found.find(({ path }) => path === "locked/keystone.ts");
    expect(locked?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-keystone-graphql-negative-take-max-take-bypass",
    );
    expect(locked?.frameworkModel?.propagators.at(-1)?.symbol).toBe(
      "@keystone-6/core@6.5.2:npm-lockfile:negative-take-max-take-bypass",
    );
  });

  test("rejects non-deployed, unbounded, omitted, denied, and unstable lookalikes", async () => {
    const root = await repository();
    const cases: Record<string, string> = {
      stable: namedSource,
      "not-exported": `import { config, list } from "@keystone-6/core";
const lists = { Post: list({ graphql: { maxTake: 3 }, fields: {} }) };
const unused = config({ ${db}, lists });`,
      "missing-limit": `import { config, list } from "@keystone-6/core";
const lists = { Post: list({ graphql: {}, fields: {} }) };
export default config({ ${db}, lists });`,
      "dynamic-limit": `import { config, list } from "@keystone-6/core";
const limit = process.env.MAX_TAKE;
const lists = { Post: list({ graphql: { maxTake: limit }, fields: {} }) };
export default config({ ${db}, lists });`,
      "zero-limit": `import { config, list } from "@keystone-6/core";
const lists = { Post: list({ graphql: { maxTake: 0 }, fields: {} }) };
export default config({ ${db}, lists });`,
      "omitted-query": `import { config, list } from "@keystone-6/core";
const lists = { Post: list({ graphql: { maxTake: 3, omit: { query: true } }, fields: {} }) };
export default config({ ${db}, lists });`,
      "denied-query": `import { config, list } from "@keystone-6/core";
const lists = { Post: list({ access: { operation: { query: () => false } }, graphql: { maxTake: 3 }, fields: {} }) };
export default config({ ${db}, lists });`,
      "official-deny-all": `import { config, list } from "@keystone-6/core";
import { denyAll } from "@keystone-6/core/access";
const lists = { Post: list({ access: denyAll, graphql: { maxTake: 3 }, fields: {} }) };
export default config({ ${db}, lists });`,
      "reassigned-config": `import { config, list } from "@keystone-6/core";
config = fake;
const lists = { Post: list({ graphql: { maxTake: 3 }, fields: {} }) };
export default config({ ${db}, lists });`,
      "replaced-list": `import * as keystone from "@keystone-6/core";
keystone.list = fake;
const lists = { Post: keystone.list({ graphql: { maxTake: 3 }, fields: {} }) };
export default keystone.config({ ${db}, lists });`,
      "local-lookalike": `import "@keystone-6/core";
const config = value => value;
const list = value => value;
const lists = { Post: list({ graphql: { maxTake: 3 }, fields: {} }) };
export default config({ ${db}, lists });`,
    };
    await Promise.all(
      Object.entries(cases).map(([id, source]) => writeCase(root, id, source)),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual(["stable/keystone.ts"]);
  });

  test("keeps the benchmark pair strict and teaches bounded impact validation", async () => {
    const vulnerable = join(
      benchmarkRoot,
      "fixtures",
      "node-keystone-negative-take-max-take-bypass",
    );
    const patched = join(
      benchmarkRoot,
      "fixtures",
      "node-keystone-patched-negative-take-max-take",
    );
    const vulnerableRecords = records(
      await buildResidualRiskInventory(vulnerable),
    );
    expect(vulnerableRecords).toHaveLength(1);
    expect(records(await buildResidualRiskInventory(patched))).toEqual([]);
    expect(vulnerableRecords[0]?.frameworkModel?.source.line).toBe(4);
    expect(vulnerableRecords[0]?.frameworkModel?.sink.line).toBe(8);
    expect(
      vulnerableRecords[0]?.frameworkModel?.propagators.at(-1)?.symbol,
    ).toBe(
      "@keystone-6/core@6.5.2:manifest-exact:negative-take-max-take-bypass",
    );
    for (const relative of [
      join("src", "keystone.js"),
      join("src", "schema.js"),
      "witness.mjs",
    ]) {
      expect(await readFile(join(vulnerable, relative), "utf8")).toBe(
        await readFile(join(patched, relative), "utf8"),
      );
    }
    const prompt = scanQualityGatePrompt("inventory-row");
    expect(prompt).toContain("node-keystone-graphql-negative-take-bypass rows");
    expect(prompt).toContain("GHSA-cqmq-8755-7xvh");
    expect(prompt).toContain("Math.abs(take ?? Infinity)");
    expect(prompt).toContain("Do not infer authorization bypass");
  });
});
