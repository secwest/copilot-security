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

function fastifyRedirectRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) => record.frameworkModel?.id === "node-fastify-open-redirect",
    );
}

async function scanFastifySource(
  source: string,
  options: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    fastifyVersion?: string;
    sourcePath?: string;
  } = {},
): Promise<FrameworkRecord[]> {
  const repository = await mkdtemp(join(tmpdir(), "fastify-redirect-model-"));
  temporaryPaths.push(repository);
  await writeFile(
    join(repository, "package.json"),
    JSON.stringify({
      name: "fastify-redirect-model",
      private: true,
      dependencies:
        options.dependencies ??
        (options.fastifyVersion === undefined
          ? { fastify: "5.12.1" }
          : { fastify: options.fastifyVersion }),
      ...(options.devDependencies === undefined
        ? {}
        : { devDependencies: options.devDependencies }),
    }),
  );
  await writeFile(join(repository, options.sourcePath ?? "server.js"), source);
  return fastifyRedirectRecords(await buildResidualRiskInventory(repository));
}

describe("Node Fastify open-redirect model", () => {
  test("keeps the versioned vulnerable and control fixtures paired", async () => {
    const fixtureRoot = resolve(
      process.cwd(),
      "..",
      "..",
      "benchmarks",
      "fixtures",
    );
    const vulnerable = fastifyRedirectRecords(
      await buildResidualRiskInventory(
        join(fixtureRoot, "node-fastify-open-redirect"),
      ),
    );
    const control = fastifyRedirectRecords(
      await buildResidualRiskInventory(
        join(fixtureRoot, "node-fastify-safe-local-redirect"),
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      source: { kind: "fastify-request-query-string", line: 6 },
      sink: { kind: "fastify-reply-redirect-location", line: 7 },
    });
    expect(control).toHaveLength(0);
  });

  test("detects a default-import query field at redirect argument zero", async () => {
    const found = await scanFastifySource(
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        'app.get("/continue", (request, reply) => {',
        "  const target = request.query.next;",
        "  return reply.redirect(target);",
        "});",
      ].join("\n"),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      id: "node-fastify-open-redirect",
      source: {
        kind: "fastify-request-query-string",
        path: "server.js",
        line: 4,
      },
      sink: {
        kind: "fastify-reply-redirect-location",
        path: "server.js",
        line: 5,
        cweIds: ["CWE-601"],
      },
      propagators: expect.arrayContaining([
        expect.objectContaining({ kind: "fastify-runtime-dependency" }),
        expect.objectContaining({
          kind: "fastify-literal-route-registration",
          symbol: "/continue",
        }),
      ]),
    });
  });

  test("supports CommonJS, route parameters, and destination-first status", async () => {
    const found = await scanFastifySource(
      [
        'const app = require("fastify")();',
        'app.post("/leave/:destination", function (request, reply) {',
        "  return reply.redirect(request.params.destination, 303);",
        "});",
      ].join("\n"),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      source: { kind: "fastify-request-route-parameter", line: 3 },
      sink: { line: 3 },
    });
  });

  test("supports a named factory, route options, native body parsing, and a named handler", async () => {
    const found = await scanFastifySource(
      [
        'import { fastify as createServer } from "fastify";',
        "const app = createServer({ logger: false });",
        "const issueRedirect = (request, reply) => {",
        "  const destination = request.body.destination;",
        "  return reply.redirect(destination);",
        "};",
        'app.put("/continue", { schema: {} }, issueRedirect);',
      ].join("\n"),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      source: { kind: "fastify-request-body-field", line: 4 },
      sink: { line: 5 },
    });
  });

  test("keeps root-only prefixes and incomplete substring checks reportable", async () => {
    const rootPrefix = await scanFastifySource(
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        'app.get("/out", (request, reply) => {',
        '  const target = "/" + request.query.next;',
        "  return reply.redirect(target);",
        "});",
      ].join("\n"),
    );
    expect(rootPrefix).toHaveLength(1);

    const substring = await scanFastifySource(
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        'app.get("/out", (request, reply) => {',
        "  const target = request.query.next;",
        '  if (!target.includes("example.com")) return reply.code(400).send();',
        "  return reply.redirect(target);",
        "});",
      ].join("\n"),
    );
    expect(substring).toHaveLength(1);
    expect(substring[0]?.frameworkModel?.candidateControls).toContainEqual(
      expect.objectContaining({ kind: "incomplete-url-substring-check" }),
    );
  });

  test("credits only fixed non-root destinations and stable fail-closed local allowlists", async () => {
    const fixed = await scanFastifySource(
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        'app.get("/out", (request, reply) => {',
        '  const target = "/continue/" + request.query.next;',
        "  return reply.redirect(target);",
        "});",
      ].join("\n"),
    );
    expect(fixed).toHaveLength(0);

    const allowlisted = await scanFastifySource(
      [
        'import Fastify from "fastify";',
        'const ALLOWED = new Set(["/home", "/account"]);',
        "const app = Fastify();",
        'app.get("/out", (request, reply) => {',
        "  const target = request.query.next;",
        "  if (!ALLOWED.has(target)) return reply.code(400).send();",
        "  return reply.redirect(target);",
        "});",
      ].join("\n"),
    );
    expect(allowlisted).toHaveLength(0);
  });

  test("does not trust a local allowlist after mutation", async () => {
    const found = await scanFastifySource(
      [
        'import Fastify from "fastify";',
        'const ALLOWED = new Set(["/home", "/account"]);',
        "const app = Fastify();",
        'app.get("/out", (request, reply) => {',
        "  const target = request.query.next;",
        "  ALLOWED.add(target);",
        "  if (!ALLOWED.has(target)) return reply.code(400).send();",
        "  return reply.redirect(target);",
        "});",
      ].join("\n"),
    );
    expect(found).toHaveLength(1);
  });

  test("requires Fastify, argument-zero Location, origin, control, and CWE evidence", async () => {
    const repository = resolve(
      process.cwd(),
      "..",
      "..",
      "benchmarks",
      "fixtures",
      "node-fastify-open-redirect",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(join(tmpdir(), "fastify-quality-"));
    temporaryPaths.push(scanDirectory);
    const finding: any = {
      occurrenceId: "occ_fastify_redirect_quality",
      taxonomy: { cwe: ["CWE-601"] },
      locations: [
        { path: "src/server.js", startLine: 6, role: "source" },
        { path: "src/server.js", startLine: 7, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "fastify-source",
          path: "src/server.js",
          startLine: 6,
          code: "request.query.next",
          explanation: "Fastify request query field.",
          role: "source",
        },
        {
          id: "fastify-sink",
          path: "src/server.js",
          startLine: 7,
          code: 'reply.redirect("/" + target)',
          explanation: "Fastify redirect argument zero becomes Location.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A request value reaches a redirect.",
        method: "source review",
        evidence: ["fastify-source", "fastify-sink"],
      },
      attackPath: {
        summary: "A request value reaches a redirect.",
        dataflow: {
          source: "fastify-source",
          sink: "fastify-sink",
          outcome: "redirect",
        },
        evidenceRefs: ["fastify-source", "fastify-sink"],
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
      "Fastify 5 registers a literal route whose remote request.query query field reaches argument zero of reply.redirect and therefore the Location header. The root-only prefix can form a scheme-relative absolute URL with an attacker-selected origin; a fixed local prefix, exact allowlist, or same-origin control is absent, producing a CWE-601 open redirect.";
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

  test("teaches the reviewer Fastify 5 binding and argument roles", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"node-fastify-open-redirect"}}',
    );
    expect(prompt).toContain("node-fastify-open-redirect");
    expect(prompt).toContain("production Fastify 5 dependency");
    expect(prompt).toContain("request.query");
    expect(prompt).toContain("request.params");
    expect(prompt).toContain("request.body");
    expect(prompt).toContain("argument zero");
    expect(prompt).toContain("CWE-601");
    expect(prompt).toContain("phishing success");
  });

  const rejectedCases: Array<
    [string, string, Parameters<typeof scanFastifySource>[1]?]
  > = [
    [
      "a local lookalike",
      [
        'import Fastify from "./fastify.js";',
        "const app = Fastify();",
        'app.get("/out", (request, reply) => reply.redirect(request.query.next));',
      ].join("\n"),
    ],
    [
      "Fastify 4",
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        'app.get("/out", (request, reply) => reply.redirect(request.query.next));',
      ].join("\n"),
      { fastifyVersion: "4.29.1" },
    ],
    [
      "an unresolved version range",
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        'app.get("/out", (request, reply) => reply.redirect(request.query.next));',
      ].join("\n"),
      { fastifyVersion: "^5.12.0" },
    ],
    [
      "a development-only dependency",
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        'app.get("/out", (request, reply) => reply.redirect(request.query.next));',
      ].join("\n"),
      { dependencies: {}, devDependencies: { fastify: "5.12.1" } },
    ],
    [
      "a dynamic route path",
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        "const route = process.env.ROUTE;",
        "app.get(route, (request, reply) => reply.redirect(request.query.next));",
      ].join("\n"),
    ],
    [
      "an unregistered handler",
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        "function handler(request, reply) { reply.redirect(request.query.next); }",
        "export { app, handler };",
      ].join("\n"),
    ],
    [
      "a const handler declared after registration",
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        'app.get("/out", handler);',
        "const handler = (request, reply) => reply.redirect(request.query.next);",
      ].join("\n"),
    ],
    [
      "a rebound factory",
      [
        'import Fastify from "fastify";',
        "Fastify = localFactory;",
        "const app = Fastify();",
        'app.get("/out", (request, reply) => reply.redirect(request.query.next));',
      ].join("\n"),
    ],
    [
      "a rebound application",
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        "app = localApp;",
        'app.get("/out", (request, reply) => reply.redirect(request.query.next));',
      ].join("\n"),
    ],
    [
      "an overwritten route member",
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        "app.get = localGet;",
        'app.get("/out", (request, reply) => reply.redirect(request.query.next));',
      ].join("\n"),
    ],
    [
      "a rebound request parameter",
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        'app.get("/out", (request, reply) => {',
        "  request = trustedRequest;",
        "  return reply.redirect(request.query.next);",
        "});",
      ].join("\n"),
    ],
    [
      "an overwritten redirect member",
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        'app.get("/out", (request, reply) => {',
        "  reply.redirect = localRedirect;",
        "  return reply.redirect(request.query.next);",
        "});",
      ].join("\n"),
    ],
    [
      "the removed status-first signature",
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        'app.get("/out", (request, reply) => reply.redirect(303, request.query.next));',
      ].join("\n"),
    ],
    [
      "a static destination",
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        'app.get("/out", (_request, reply) => reply.redirect("/home"));',
      ].join("\n"),
    ],
    [
      "an opaque transformation",
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        'app.get("/out", (request, reply) => reply.redirect(sanitize(request.query.next)));',
      ].join("\n"),
    ],
    [
      "a test file",
      [
        'import Fastify from "fastify";',
        "const app = Fastify();",
        'app.get("/out", (request, reply) => reply.redirect(request.query.next));',
      ].join("\n"),
      { sourcePath: "server.test.js" },
    ],
  ];

  for (const [name, source, options] of rejectedCases) {
    test(`rejects ${name}`, async () => {
      expect(await scanFastifySource(source, options)).toHaveLength(0);
    });
  }
});
