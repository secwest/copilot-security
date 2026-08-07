import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface FrameworkRecord {
  path: string;
  line: number;
  frameworkModel?: {
    id: string;
    source: { path: string; line: number };
    sink: { kind: string; path: string; line: number; cweIds: string[] };
    propagators: Array<{ kind: string; path: string; line: number }>;
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

function records(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-http-postcss-source-map-traversal",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "copilot-security-postcss-model-"));
  temporaryPaths.push(root);
  return root;
}

async function writeCase(
  root: string,
  id: string,
  source: string,
  options: {
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
        postcss: options.version ?? "8.5.17",
      },
    }),
  );
  await writeFile(join(directory, "server.mjs"), source);
}

describe("PostCSS previous-source-map traversal framework model", () => {
  test("supports official parse, processor, ESM, and CommonJS bindings", async () => {
    const root = await repository();
    await writeCase(
      root,
      "default-parse",
      'import postcss from "postcss";\nexport function route(req) { return postcss.parse(req.body.css, { from: "/srv/in.css" }); }\n',
    );
    await writeCase(
      root,
      "named-parse",
      'import { parse as parseCss } from "postcss";\nexport function route(req) { return parseCss(req.body.css); }\n',
    );
    await writeCase(
      root,
      "chain-process",
      'import * as postcss from "postcss";\nexport function route(req) { return postcss([]).process(req.body.css, { from: "/srv/in.css" }); }\n',
    );
    await writeCase(
      root,
      "processor",
      'const postcss = require("postcss");\nconst processor = postcss([]);\nexports.route = function route(req) { return processor.process(req.body.css, { from: "/srv/in.css" }); };\n',
    );
    await writeCase(
      root,
      "direct-commonjs",
      'exports.route = function route(req) { return require("postcss").parse(req.body.css); };\n',
    );
    await writeCase(
      root,
      "patched",
      'import postcss from "postcss";\nexport function route(req) { return postcss.parse(req.body.css); }\n',
      { version: "8.5.18" },
    );
    await writeCase(
      root,
      "development",
      'import postcss from "postcss";\nexport function route(req) { return postcss.parse(req.body.css); }\n',
      { section: "devDependencies" },
    );

    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual([
      "chain-process/server.mjs",
      "default-parse/server.mjs",
      "direct-commonjs/server.mjs",
      "named-parse/server.mjs",
      "processor/server.mjs",
    ]);
    expect(
      found.map((record) => record.frameworkModel?.sink.kind).sort(),
    ).toEqual([
      "vulnerable-postcss-parse-source-map-traversal",
      "vulnerable-postcss-parse-source-map-traversal",
      "vulnerable-postcss-parse-source-map-traversal",
      "vulnerable-postcss-process-source-map-traversal",
      "vulnerable-postcss-process-source-map-traversal",
    ]);
  });

  test("treats exact map and previous-map disablement as counterevidence", async () => {
    const root = await repository();
    await writeCase(
      root,
      "options",
      [
        'import postcss from "postcss";',
        "export function route(req) {",
        '  postcss.parse(req.body.css, { from: "/srv/in.css" });',
        '  postcss.parse(req.body.css, { from: "/srv/in.css", map: false });',
        "  postcss.parse(req.body.css, { map: { prev: false } });",
        "  postcss.parse(req.body.css, req.body.options);",
        "}",
        "",
      ].join("\n"),
    );
    expect(
      records(await buildResidualRiskInventory(root)).map(({ line }) => line),
    ).toEqual([3, 6]);
  });

  test("rejects wrong packages, fixed CSS, reassignment, and wrapper shadowing", async () => {
    const root = await repository();
    await writeCase(
      root,
      "negative",
      [
        'import postcss from "postcss";',
        'import local from "css-processor";',
        'postcss.parse("a{}");',
        "local.parse(request.body.css);",
        "postcss.parse = local.parse;",
        "postcss.parse(request.body.css);",
        "export function shadow(postcss, request) { return postcss.parse(request.body.css); }",
        "",
      ].join("\n"),
    );
    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("uses a fresh declaration-consistent npm lock resolution", async () => {
    const root = await repository();
    const valid = join(root, "valid");
    await mkdir(valid);
    await writeFile(
      join(valid, "package.json"),
      JSON.stringify({ name: "valid", dependencies: { postcss: "^8.5.15" } }),
    );
    await writeFile(
      join(valid, "package-lock.json"),
      JSON.stringify({
        name: "valid",
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { postcss: "^8.5.15" } },
          "node_modules/postcss": { version: "8.5.17" },
        },
      }),
    );
    await writeFile(
      join(valid, "server.mjs"),
      'import postcss from "postcss";\nexport function route(req) { return postcss.parse(req.body.css); }\n',
    );
    await writeCase(
      root,
      "unlocked",
      'import postcss from "postcss";\nexport function route(req) { return postcss.parse(req.body.css); }\n',
      { version: "^8.5.15" },
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-postcss-parse-source-map-traversal",
    );
  });

  test("preserves a typed cross-file wrapper and exact review bounds", async () => {
    const root = await repository();
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({ name: "wrapper", dependencies: { postcss: "8.5.17" } }),
    );
    await writeFile(
      join(root, "style.mjs"),
      'import postcss from "postcss";\nexport function compile(css) { return postcss([]).process(css, { from: "/srv/in.css" }); }\n',
    );
    await writeFile(
      join(root, "server.mjs"),
      'import { compile } from "./style.mjs";\nexport function route(req) { return compile(req.body.css); }\n',
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      source: { path: "server.mjs", line: 2 },
      sink: {
        path: "style.mjs",
        line: 2,
        kind: "vulnerable-postcss-process-source-map-traversal",
        cweIds: ["CWE-22"],
      },
    });
    expect(found[0]?.frameworkModel?.propagators.length).toBeGreaterThan(0);
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-postcss-source-map-traversal");
    expect(prompt).toContain("through 8.5.17");
    expect(prompt).toContain("sourcesContent");
    expect(prompt).toContain("unsafeMap:true");
  });
});
