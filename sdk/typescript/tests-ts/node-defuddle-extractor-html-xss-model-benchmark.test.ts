import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface DefuddleRecord {
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
  parserSource?: string;
  rootLockDeclaration?: string;
  serverSource?: string;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const temporaryPaths: string[] = [];

const defaultParserSource = `import { Defuddle } from "defuddle/node";
export async function extractArticle(html, url) {
  return Defuddle(html, url);
}
`;

const defaultServerSource = `import { extractArticle } from "./extract-article.js";
export async function clipArticle(request, response) {
  const html = request.body.html;
  const url = request.body.url;
  const extracted = await extractArticle(html, url);
  response.type("html").send(extracted.content);
}
`;

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function defuddleRecords(inventory: string): DefuddleRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as DefuddleRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-defuddle-extractor-html-xss",
    );
}

async function temporaryRepository(label: string): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), `copilot-security-defuddle-${label}-`),
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
  const declaration = options.declaration ?? "0.19.0";
  const dependencySection = options.dependencySection ?? "dependencies";
  const packageName = options.packageName ?? "defuddle";
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
                [packageName]: { version: options.lockedVersion ?? "0.19.0" },
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
                  version: options.lockedVersion ?? "0.19.0",
                },
              },
            },
        null,
        2,
      ),
    );
  }
  await writeFile(
    join(root, "src", "extract-article.js"),
    options.parserSource ?? defaultParserSource,
  );
  await writeFile(
    join(root, "src", "server.js"),
    options.serverSource ?? defaultServerSource,
  );
}

describe("Defuddle site-extractor HTML XSS model", () => {
  test("keeps a strict affected and repaired executable benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-defuddle-extractor-html-xss-manifest.json"),
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
      "node-defuddle-extractor-html-xss",
      "node-defuddle-extractor-html-isolated",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-79"],
      acceptableSeverities: ["high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
      locations: [{ startLine: 7, endLine: 7 }],
    });
    expect(manifest.cases[1]?.expected).toEqual([]);

    const affected = defuddleRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", "node-defuddle-extractor-html-xss"),
      ),
    );
    const repaired = defuddleRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-defuddle-extractor-html-isolated",
        ),
      ),
    );
    expect(affected).toHaveLength(1);
    expect(repaired).toEqual([]);
    expect(affected[0]).toMatchObject({
      path: "src/server.js",
      line: 7,
      frameworkModel: {
        id: "node-defuddle-extractor-html-xss",
        scope: "cross-file-multi-hop-wrapper",
        source: {
          kind: "remote-request-html-body",
          path: "src/server.js",
          line: 4,
        },
        sink: {
          kind: "vulnerable-defuddle-extractor-html-render",
          path: "src/server.js",
          line: 7,
          cweIds: ["CWE-79"],
        },
      },
    });
    expect(
      affected[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "relative-defuddle-parser-wrapper-call",
      "defuddle-node-html-input",
      "defuddle-site-extractor-response",
      "html-response-defuddle-content",
      "defuddle-runtime-dependency",
    ]);
  });

  test("accepts declaration-consistent lock provenance", async () => {
    const repository = await temporaryRepository("lock");
    await writeCase(repository, "affected-lock", {
      declaration: "^0.19.0",
      lock: true,
      lockedVersion: "0.19.0",
    });
    const records = defuddleRecords(
      await buildResidualRiskInventory(join(repository, "affected-lock")),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-vulnerable-defuddle-extractor-html-render",
    );
    expect(records[0]?.frameworkModel?.propagators.at(-1)?.symbol).toBe(
      "defuddle@0.19.0:npm-lockfile:unsanitized-site-extractor-output",
    );
  });

  test("recognizes official aliases and namespace receivers", async () => {
    const repository = await temporaryRepository("bindings");
    const variants = [
      {
        id: "named-alias",
        source: `import { Defuddle as parseArticle } from "defuddle/node";
export async function extractArticle(html, url) {
  return parseArticle(html, url);
}
`,
      },
      {
        id: "namespace",
        source: `import * as DefuddleNode from "defuddle/node";
export async function extractArticle(html, url) {
  return DefuddleNode.Defuddle(html, url);
}
`,
      },
      {
        id: "typescript-import-equals",
        source: `import DefuddleNode = require("defuddle/node");
export async function extractArticle(html, url) {
  return DefuddleNode.Defuddle(html, url);
}
`,
      },
      {
        id: "commonjs-receiver",
        source: `const DefuddleNode = require("defuddle/node");
exports.extractArticle = async function(html, url) {
  return DefuddleNode.Defuddle(html, url);
};
`,
      },
      {
        id: "commonjs-direct",
        source: `const parseArticle = require("defuddle/node").Defuddle;
exports.extractArticle = async function(html, url) {
  return parseArticle(html, url);
};
`,
      },
    ];
    for (const variant of variants) {
      await writeCase(repository, variant.id, { parserSource: variant.source });
    }
    for (const variant of variants) {
      expect(
        defuddleRecords(
          await buildResidualRiskInventory(join(repository, variant.id)),
        ),
        variant.id,
      ).toHaveLength(1);
    }
  });

  test("recognizes request text, fetched text, DOM, React, and Web Response boundaries", async () => {
    const repository = await temporaryRepository("boundaries");
    const variants = [
      {
        id: "request-text-innerhtml",
        serverSource: `import { extractArticle } from "./extract-article.js";
export async function clipArticle(request, output) {
  const html = await request.text();
  const extracted = await extractArticle(html, request.url);
  output.innerHTML = extracted.content;
}
`,
        sourceKind: "remote-request-html-text",
        sinkKind: "dom-innerhtml-defuddle-content",
      },
      {
        id: "fetched-text-react",
        serverSource: `import { extractArticle } from "./extract-article.js";
export async function ArticlePreview(props) {
  const upstream = await fetch(props.url);
  const html = await upstream.text();
  const extracted = await extractArticle(html, props.url);
  return <article dangerouslySetInnerHTML={{ __html: extracted.content }} />;
}
`,
        sourceKind: "remote-fetched-html-text",
        sinkKind: "react-raw-html-defuddle-content",
      },
      {
        id: "web-response",
        serverSource: `import { extractArticle } from "./extract-article.js";
export async function clipArticle(request) {
  const html = request.body.html;
  const extracted = await extractArticle(html, request.body.url);
  return new Response(extracted.content, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
`,
        sourceKind: "remote-request-html-body",
        sinkKind: "web-response-defuddle-content",
      },
    ];
    for (const variant of variants) {
      await writeCase(repository, variant.id, {
        serverSource: variant.serverSource,
      });
      const records = defuddleRecords(
        await buildResidualRiskInventory(join(repository, variant.id)),
      );
      expect(records, variant.id).toHaveLength(1);
      expect(records[0]?.frameworkModel?.source.kind).toBe(variant.sourceKind);
      expect(records[0]?.frameworkModel?.propagators.at(-2)?.kind).toBe(
        variant.sinkKind,
      );
    }
  });

  test("rejects patched, prerelease, wrong, development-only, and unproved ranges", async () => {
    const repository = await temporaryRepository("provenance-negatives");
    const cases: Array<[string, CaseOptions]> = [
      ["patched-0191", { declaration: "0.19.1" }],
      ["patched-latest", { declaration: "0.19.3" }],
      ["prerelease", { declaration: "0.19.0-beta.1" }],
      ["wrong-package", { packageName: "defuddle-fork" }],
      ["development-only", { dependencySection: "devDependencies" }],
      ["unproved-range", { declaration: "^0.18.0" }],
      [
        "stale-lock",
        {
          declaration: "^0.18.0",
          lock: true,
          lockedVersion: "0.19.1",
        },
      ],
      [
        "inconsistent-lock",
        {
          declaration: "^0.18.0",
          lock: true,
          lockedVersion: "0.19.0",
          rootLockDeclaration: "~0.18.0",
        },
      ],
      [
        "v1-lock",
        {
          declaration: "^0.18.0",
          lock: true,
          lockedVersion: "0.19.0",
          lockfileVersion: 1,
        },
      ],
    ];
    for (const [id, options] of cases) await writeCase(repository, id, options);
    for (const [id] of cases) {
      expect(
        defuddleRecords(await buildResidualRiskInventory(join(repository, id))),
        id,
      ).toEqual([]);
    }
  });

  test("rejects incomplete, trusted, sanitized, reassigned, and lookalike flows", async () => {
    const repository = await temporaryRepository("topology-negatives");
    const cases: Array<[string, CaseOptions]> = [
      [
        "dependency-only",
        { parserSource: "export const configured = true;\n" },
      ],
      [
        "trusted-literal",
        {
          serverSource: `import { extractArticle } from "./extract-article.js";
export async function clipArticle(request, response) {
  const extracted = await extractArticle("<article>trusted</article>", request.body.url);
  response.type("html").send(extracted.content);
}
`,
        },
      ],
      [
        "local-body-lookalike",
        {
          serverSource: `import { extractArticle } from "./extract-article.js";
export async function clipArticle(request, response) {
  const template = { body: { html: "<article>trusted</article>" } };
  const extracted = await extractArticle(template.body.html, request.body.url);
  response.type("html").send(extracted.content);
}
`,
        },
      ],
      [
        "json-output",
        {
          serverSource: `import { extractArticle } from "./extract-article.js";
export async function clipArticle(request, response) {
  const extracted = await extractArticle(request.body.html, request.body.url);
  response.json({ content: extracted.content });
}
`,
        },
      ],
      [
        "text-output",
        {
          serverSource: `import { extractArticle } from "./extract-article.js";
export async function clipArticle(request, response) {
  const extracted = await extractArticle(request.body.html, request.body.url);
  response.type("text/plain").send(extracted.content);
}
`,
        },
      ],
      [
        "sanitized-output",
        {
          serverSource: `import { extractArticle } from "./extract-article.js";
export async function clipArticle(request, response) {
  const extracted = await extractArticle(request.body.html, request.body.url);
  const safe = sanitizeHtml(extracted.content);
  response.type("html").send(safe);
}
`,
        },
      ],
      [
        "sanitized-caller-input",
        {
          serverSource: `import { extractArticle } from "./extract-article.js";
export async function clipArticle(request, response) {
  const html = sanitizeHtml(request.body.html);
  const extracted = await extractArticle(html, request.body.url);
  response.type("html").send(extracted.content);
}
`,
        },
      ],
      [
        "wrong-property",
        {
          serverSource: `import { extractArticle } from "./extract-article.js";
export async function clipArticle(request, response) {
  const extracted = await extractArticle(request.body.html, request.body.url);
  response.type("html").send(extracted.title);
}
`,
        },
      ],
      [
        "local-lookalike",
        {
          parserSource: `function Defuddle(html, url) { return { content: html, url }; }
export async function extractArticle(html, url) {
  return Defuddle(html, url);
}
`,
        },
      ],
      [
        "binding-reassigned",
        {
          parserSource: `import { Defuddle } from "defuddle/node";
Defuddle = localParser;
export async function extractArticle(html, url) {
  return Defuddle(html, url);
}
`,
        },
      ],
      [
        "namespace-member-reassigned",
        {
          parserSource: `import * as DefuddleNode from "defuddle/node";
DefuddleNode.Defuddle = localParser;
export async function extractArticle(html, url) {
  return DefuddleNode.Defuddle(html, url);
}
`,
        },
      ],
      [
        "wrapper-import-reassigned",
        {
          serverSource: `import { extractArticle } from "./extract-article.js";
export async function clipArticle(request, response) {
  extractArticle = localParser;
  const extracted = await extractArticle(request.body.html, request.body.url);
  response.type("html").send(extracted.content);
}
`,
        },
      ],
      [
        "result-reassigned",
        {
          serverSource: `import { extractArticle } from "./extract-article.js";
export async function clipArticle(request, response) {
  let extracted = await extractArticle(request.body.html, request.body.url);
  extracted = trustedArticle;
  response.type("html").send(extracted.content);
}
`,
        },
      ],
      [
        "input-reassigned",
        {
          serverSource: `import { extractArticle } from "./extract-article.js";
export async function clipArticle(request, response) {
  let html = request.body.html;
  html = trustedTemplate;
  const extracted = await extractArticle(html, request.body.url);
  response.type("html").send(extracted.content);
}
`,
        },
      ],
      [
        "wrapper-sanitizes-input",
        {
          parserSource: `import { Defuddle } from "defuddle/node";
export async function extractArticle(html, url) {
  return Defuddle(sanitizeHtml(html), url);
}
`,
        },
      ],
      [
        "wrapper-sanitizes-output",
        {
          parserSource: `import { Defuddle } from "defuddle/node";
export async function extractArticle(html, url) {
  const extracted = await Defuddle(html, url);
  return { ...extracted, content: sanitizeHtml(extracted.content) };
}
`,
        },
      ],
      [
        "unexported-wrapper",
        {
          parserSource: `import { Defuddle } from "defuddle/node";
async function extractArticle(html, url) {
  return Defuddle(html, url);
}
`,
        },
      ],
    ];
    for (const [id, options] of cases) await writeCase(repository, id, options);
    for (const [id] of cases) {
      expect(
        defuddleRecords(await buildResidualRiskInventory(join(repository, id))),
        id,
      ).toEqual([]);
    }
  });

  test("keeps affected and repaired fixture application source identical", async () => {
    const affectedRoot = join(
      benchmarkRoot,
      "fixtures",
      "node-defuddle-extractor-html-xss",
    );
    const repairedRoot = join(
      benchmarkRoot,
      "fixtures",
      "node-defuddle-extractor-html-isolated",
    );
    for (const path of [
      join("src", "extract-article.js"),
      join("src", "server.js"),
      "witness.test.mjs",
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
    expect(affectedPackage.dependencies["defuddle"]).toBe("0.19.0");
    expect(repairedPackage.dependencies["defuddle"]).toBe("0.19.1");
    expect(affectedPackage.dependencies["linkedom"]).toBe(
      repairedPackage.dependencies["linkedom"],
    );
  });

  test("requires bounded validation and disciplined impact claims", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-defuddle-extractor-html-xss");
    expect(prompt).toContain("GHSA-jg4p-g6xj-4qmf / CVE-2026-61824");
    expect(prompt).toContain("Defuddle 0.19.1");
    expect(prompt).toContain("synthetic X article");
    expect(prompt).toContain("do not execute the event handler");
    expect(prompt).toContain("CWE-79");
  });
});
