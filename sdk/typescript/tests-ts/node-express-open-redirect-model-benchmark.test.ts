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

function expressRedirectRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) => record.frameworkModel?.id === "node-express-open-redirect",
    );
}

async function scanExpressSource(
  source: string,
  options: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    expressVersion?: string;
    sourcePath?: string;
  } = {},
): Promise<FrameworkRecord[]> {
  const repository = await mkdtemp(join(tmpdir(), "express-redirect-model-"));
  temporaryPaths.push(repository);
  await writeFile(
    join(repository, "package.json"),
    JSON.stringify({
      name: "express-redirect-model",
      private: true,
      dependencies:
        options.dependencies ??
        (options.expressVersion === undefined
          ? { express: "5.2.1" }
          : { express: options.expressVersion }),
      ...(options.devDependencies === undefined
        ? {}
        : { devDependencies: options.devDependencies }),
    }),
  );
  await writeFile(join(repository, options.sourcePath ?? "server.js"), source);
  return expressRedirectRecords(await buildResidualRiskInventory(repository));
}

describe("Node Express open-redirect model", () => {
  test("keeps the versioned vulnerable and control fixtures paired", async () => {
    const fixtureRoot = resolve(
      process.cwd(),
      "..",
      "..",
      "benchmarks",
      "fixtures",
    );
    const vulnerable = expressRedirectRecords(
      await buildResidualRiskInventory(
        join(fixtureRoot, "node-express-open-redirect"),
      ),
    );
    const control = expressRedirectRecords(
      await buildResidualRiskInventory(
        join(fixtureRoot, "node-express-safe-local-redirect"),
      ),
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      source: { kind: "express-request-query-string", line: 6 },
      sink: { kind: "express-response-redirect-location", line: 7 },
    });
    expect(control).toHaveLength(0);
  });

  test("detects an official Express query value emitted as Location", async () => {
    const found = await scanExpressSource(
      [
        'import express from "express";',
        "const app = express();",
        'app.get("/continue", (req, res) => {',
        "  const target = req.query.next;",
        "  return res.redirect(target);",
        "});",
        "export default app;",
        "",
      ].join("\n"),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      id: "node-express-open-redirect",
      source: {
        kind: "express-request-query-string",
        path: "server.js",
        line: 4,
      },
      sink: {
        kind: "express-response-redirect-location",
        path: "server.js",
        line: 5,
        cweIds: ["CWE-601"],
      },
    });
  });

  test("supports CommonJS, route parameters, and the Express 5 status-first signature", async () => {
    const found = await scanExpressSource(
      [
        'const express = require("express");',
        "const app = express();",
        'app.post("/leave/:destination", function (request, response) {',
        "  response.redirect(303, request.params.destination);",
        "});",
        "",
      ].join("\n"),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      source: { kind: "express-request-route-parameter", line: 4 },
      sink: { kind: "express-response-redirect-location", line: 4 },
    });
  });

  test("requires an official body parser before a body field reaches a named handler", async () => {
    const found = await scanExpressSource(
      [
        'import express from "express";',
        "const app = express();",
        "app.use(express.json());",
        "const continueHandler = (req, res) => {",
        "  const destination = req.body.destination;",
        "  return res.redirect(destination);",
        "};",
        'app.put("/continue", continueHandler);',
        "",
      ].join("\n"),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      source: { kind: "express-request-body-field", line: 5 },
      sink: { line: 6 },
      propagators: expect.arrayContaining([
        expect.objectContaining({
          kind: "express-body-parser-middleware",
          line: 3,
        }),
      ]),
    });
  });

  test("supports an aliased official Router import and a bracket query field", async () => {
    const found = await scanExpressSource(
      [
        'import { Router as ExpressRouter } from "express";',
        "const router = ExpressRouter();",
        'router.get("/out", (request, response) => {',
        '  return response.redirect(request.query["destination"]);',
        "});",
        "export default router;",
        "",
      ].join("\n"),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      source: { kind: "express-request-query-string", line: 4 },
      sink: { line: 4 },
    });
  });

  test("supports Express 4's deprecated destination-first status signature", async () => {
    const found = await scanExpressSource(
      [
        'const app = require("express")();',
        'app.get("/out", (req, res) => {',
        "  const target = req.query.target;",
        "  res.redirect(target, 302);",
        "});",
        "",
      ].join("\n"),
      { expressVersion: "4.22.2" },
    );
    expect(found).toHaveLength(1);
  });

  test("keeps root-only prefixes and incomplete substring checks reportable", async () => {
    const rootPrefix = await scanExpressSource(
      [
        'import express from "express";',
        "const app = express();",
        'app.get("/out", (req, res) => {',
        '  const target = "/" + req.query.target;',
        "  res.redirect(target);",
        "});",
        "",
      ].join("\n"),
    );
    expect(rootPrefix).toHaveLength(1);

    const substring = await scanExpressSource(
      [
        'import express from "express";',
        "const app = express();",
        'app.get("/out", (req, res) => {',
        "  const target = req.query.target;",
        '  if (!target.includes("example.com")) return res.status(400).end();',
        "  res.redirect(target);",
        "});",
        "",
      ].join("\n"),
    );
    expect(substring).toHaveLength(1);
    expect(substring[0]?.frameworkModel?.candidateControls).toContainEqual(
      expect.objectContaining({
        kind: "incomplete-url-substring-check",
        line: 5,
      }),
    );
  });

  test("does not trust a local Set after its contents are mutated", async () => {
    const found = await scanExpressSource(
      [
        'import express from "express";',
        'const ALLOWED = new Set(["/home", "/account"]);',
        "const app = express();",
        'app.get("/out", (req, res) => {',
        "  const target = req.query.next;",
        "  ALLOWED.add(target);",
        "  if (!ALLOWED.has(target)) return res.status(400).end();",
        "  res.redirect(target);",
        "});",
      ].join("\n"),
    );
    expect(found).toHaveLength(1);
  });

  test("requires Express, Location, origin, control, and CWE evidence in review fields", async () => {
    const repository = resolve(
      process.cwd(),
      "..",
      "..",
      "benchmarks",
      "fixtures",
      "node-express-open-redirect",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "express-redirect-quality-"),
    );
    temporaryPaths.push(scanDirectory);
    const finding: any = {
      occurrenceId: "occ_express_redirect_quality",
      taxonomy: { cwe: ["CWE-601"] },
      locations: [
        { path: "src/server.js", startLine: 6, role: "source" },
        { path: "src/server.js", startLine: 7, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "express-source",
          path: "src/server.js",
          startLine: 6,
          code: "req.query.next",
          explanation: "Express request query field.",
          role: "source",
        },
        {
          id: "express-sink",
          path: "src/server.js",
          startLine: 7,
          code: 'res.redirect("/" + target)',
          explanation: "Express response Location.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A request value reaches a redirect.",
        method: "source review",
        evidence: ["express-source", "express-sink"],
      },
      attackPath: {
        summary: "A request value reaches a redirect.",
        dataflow: {
          source: "express-source",
          sink: "express-sink",
          outcome: "redirect",
        },
        evidenceRefs: ["express-source", "express-sink"],
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
      "An Express 5 registered route binds a remote request.query query field and emits it through response.redirect into the Location header. The root-only prefix can form a scheme-relative absolute URL with an attacker-selected origin; a fixed local prefix, exact allowlist, or same-origin control is absent, producing a CWE-601 open redirect.";
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

  test("teaches the reviewer the Express binding, Location, and origin boundary", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"node-express-open-redirect"}}',
    );
    expect(prompt).toContain("node-express-open-redirect");
    expect(prompt).toContain("production express dependency");
    expect(prompt).toContain("request.query");
    expect(prompt).toContain("request.params");
    expect(prompt).toContain("request.body");
    expect(prompt).toContain("express.json");
    expect(prompt).toContain("redirect-to-Location");
    expect(prompt).toContain('target.includes("example.com")');
    expect(prompt).toContain("CWE-601");
    expect(prompt).toContain("phishing success");
  });

  const rejectedCases: Array<
    [string, string, Parameters<typeof scanExpressSource>[1]?]
  > = [
    [
      "a local Express lookalike",
      [
        'import express from "./express.js";',
        "const app = express();",
        'app.get("/out", (req, res) => res.redirect(req.query.next));',
      ].join("\n"),
    ],
    [
      "an unregistered handler",
      [
        'import express from "express";',
        "const app = express();",
        "function handler(req, res) { res.redirect(req.query.next); }",
        "export { app, handler };",
      ].join("\n"),
    ],
    [
      "a const handler declared after registration",
      [
        'import express from "express";',
        "const app = express();",
        'app.get("/out", handler);',
        "const handler = (req, res) => res.redirect(req.query.next);",
      ].join("\n"),
    ],
    [
      "a dynamic route path",
      [
        'import express from "express";',
        "const app = express();",
        "const route = process.env.ROUTE;",
        "app.get(route, (req, res) => res.redirect(req.query.next));",
      ].join("\n"),
    ],
    [
      "a rebound Express factory",
      [
        'import express from "express";',
        "express = localFactory;",
        "const app = express();",
        'app.get("/out", (req, res) => res.redirect(req.query.next));',
      ].join("\n"),
    ],
    [
      "a rebound application",
      [
        'import express from "express";',
        "const app = express();",
        "app = localApp;",
        'app.get("/out", (req, res) => res.redirect(req.query.next));',
      ].join("\n"),
    ],
    [
      "an overwritten route member",
      [
        'import express from "express";',
        "const app = express();",
        "app.get = localGet;",
        'app.get("/out", (req, res) => res.redirect(req.query.next));',
      ].join("\n"),
    ],
    [
      "a rebound request parameter",
      [
        'import express from "express";',
        "const app = express();",
        'app.get("/out", (req, res) => {',
        "  req = trustedRequest;",
        "  res.redirect(req.query.next);",
        "});",
      ].join("\n"),
    ],
    [
      "a request parameter rebound on the sink line",
      [
        'import express from "express";',
        "const app = express();",
        'app.get("/out", (req, res) => { req = trustedRequest; res.redirect(req.query.next); });',
      ].join("\n"),
    ],
    [
      "an overwritten redirect member",
      [
        'import express from "express";',
        "const app = express();",
        'app.get("/out", (req, res) => {',
        "  res.redirect = localRedirect;",
        "  res.redirect(req.query.next);",
        "});",
      ].join("\n"),
    ],
    [
      "a fixed non-root local prefix",
      [
        'import express from "express";',
        "const app = express();",
        'app.get("/out", (req, res) => {',
        '  const target = "/continue/" + req.query.next;',
        "  res.redirect(target);",
        "});",
      ].join("\n"),
    ],
    [
      "a fixed complete HTTPS origin prefix",
      [
        'import express from "express";',
        "const app = express();",
        'app.get("/out", (req, res) => {',
        '  res.redirect("https://accounts.example/continue/" + req.query.next);',
        "});",
      ].join("\n"),
    ],
    [
      "a fail-closed stable local Set allowlist",
      [
        'import express from "express";',
        'const ALLOWED = new Set(["/home", "/account"]);',
        "const app = express();",
        'app.get("/out", (req, res) => {',
        "  const target = req.query.next;",
        "  if (!ALLOWED.has(target)) return res.status(400).end();",
        "  res.redirect(target);",
        "});",
      ].join("\n"),
    ],
    [
      "a body field without body-parser middleware",
      [
        'import express from "express";',
        "const app = express();",
        'app.post("/out", (req, res) => res.redirect(req.body.next));',
      ].join("\n"),
    ],
    [
      "body-parser middleware registered after the route",
      [
        'import express from "express";',
        "const app = express();",
        'app.post("/out", (req, res) => res.redirect(req.body.next));',
        "app.use(express.json());",
      ].join("\n"),
    ],
    [
      "an overwritten Express body-parser factory",
      [
        'import express from "express";',
        "const app = express();",
        "express.json = localParser;",
        "app.use(express.json());",
        'app.post("/out", (req, res) => res.redirect(req.body.next));',
      ].join("\n"),
    ],
    [
      "a static destination",
      [
        'import express from "express";',
        "const app = express();",
        'app.get("/out", (_req, res) => res.redirect("/home"));',
      ].join("\n"),
    ],
    [
      "a test file",
      [
        'import express from "express";',
        "const app = express();",
        'app.get("/out", (req, res) => res.redirect(req.query.next));',
      ].join("\n"),
      { sourcePath: "server.test.js" },
    ],
    [
      "a development-only Express dependency",
      [
        'import express from "express";',
        "const app = express();",
        'app.get("/out", (req, res) => res.redirect(req.query.next));',
      ].join("\n"),
      { dependencies: {}, devDependencies: { express: "5.2.1" } },
    ],
    [
      "an unresolved Express version range",
      [
        'import express from "express";',
        "const app = express();",
        'app.get("/out", (req, res) => res.redirect(req.query.next));',
      ].join("\n"),
      { expressVersion: "^5.2.0" },
    ],
  ];

  for (const [name, source, options] of rejectedCases) {
    test(`rejects ${name}`, async () => {
      expect(await scanExpressSource(source, options)).toHaveLength(0);
    });
  }
});
