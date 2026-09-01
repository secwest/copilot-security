import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
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
const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function corsRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-express-credentialed-cors-session-exposure",
    );
}

async function fixtureRecords(name: string): Promise<FrameworkRecord[]> {
  return corsRecords(
    await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", name)),
  );
}

async function scanExpressCorsSource(
  source: string,
  options: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    sourcePath?: string;
  } = {},
): Promise<FrameworkRecord[]> {
  const repository = await mkdtemp(join(tmpdir(), "express-cors-model-"));
  temporaryPaths.push(repository);
  await writeFile(
    join(repository, "package.json"),
    JSON.stringify({
      name: "express-cors-model",
      private: true,
      type: "module",
      dependencies: options.dependencies ?? {
        cors: "2.8.6",
        express: "5.2.1",
        "express-session": "1.19.0",
      },
      devDependencies: options.devDependencies,
    }),
  );
  const path = join(repository, options.sourcePath ?? "server.js");
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, source);
  return corsRecords(await buildResidualRiskInventory(repository));
}

function accountRoute(
  corsOptions = "{ origin: true, credentials: true }",
  placement: "global" | "route" = "global",
  response = "return response.json({ email: request.session.account.email, roles: request.session.account.roles });",
): string {
  const globalCors =
    placement === "global" ? "app.use(cors(corsOptions));" : "";
  const routeCors = placement === "route" ? "cors(corsOptions), " : "";
  return [
    'import express from "express";',
    'import cors from "cors";',
    'import session from "express-session";',
    "const app = express();",
    `const corsOptions = ${corsOptions};`,
    "app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));",
    globalCors,
    "function readAccount(request, response) {",
    `  ${response}`,
    "}",
    `app.get("/account", ${routeCors}readAccount);`,
  ]
    .filter((line) => line !== "")
    .join("\n");
}

describe("Express credentialed CORS session-exposure model", () => {
  test("detects the reflected fixture and rejects its fixed-origin twin", async () => {
    const vulnerable = await fixtureRecords(
      "node-express-credentialed-cors-reflection",
    );
    const control = await fixtureRecords(
      "node-express-credentialed-cors-allowlist",
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      id: "node-express-credentialed-cors-session-exposure",
      source: {
        kind: "cors-reflected-request-origin",
        path: "src/server.js",
        line: 8,
      },
      sink: {
        kind: "express-credentialed-cors-session-response",
        path: "src/server.js",
        line: 21,
        cweIds: ["CWE-942", "CWE-346", "CWE-639"],
      },
      propagators: expect.arrayContaining([
        expect.objectContaining({
          kind: "express-literal-session-data-route",
          symbol: "GET /account",
        }),
        expect.objectContaining({
          kind: "cors-runtime-dependency",
          symbol: "cors@2.8.6:manifest-exact",
        }),
        expect.objectContaining({
          kind: "express-session-runtime-dependency",
          symbol: "express-session@1.19.0:manifest-exact",
        }),
        expect.objectContaining({
          kind: "express-session-response-data",
          symbol: "request.session.account",
        }),
      ]),
      candidateControls: expect.arrayContaining([
        expect.objectContaining({ kind: "cors-credentials-enabled" }),
        expect.objectContaining({ kind: "cors-origin-reflection-enabled" }),
        expect.objectContaining({ kind: "express-session-middleware-active" }),
      ]),
    });
    expect(control).toHaveLength(0);
  });

  test("models global, route, null-origin, and exact callback activation", async () => {
    expect(await scanExpressCorsSource(accountRoute())).toHaveLength(1);
    expect(
      await scanExpressCorsSource(
        accountRoute("{ origin: true, credentials: true }", "route"),
      ),
    ).toHaveLength(1);
    expect(
      await scanExpressCorsSource(
        accountRoute('{ origin: "null", credentials: true }'),
      ),
    ).toHaveLength(1);
    for (const callback of [
      "(origin, done) => done(null, true)",
      "(origin, done) => done(null, origin)",
      "function (origin, done) { return done(null, true); }",
    ]) {
      expect(
        await scanExpressCorsSource(
          accountRoute(`{ origin: ${callback}, credentials: true }`),
        ),
      ).toHaveLength(1);
    }
    const stableCallback = [
      'import express from "express";',
      'import cors from "cors";',
      'import session from "express-session";',
      "const app = express();",
      "const reflectOrigin = (origin, done) => done(null, origin);",
      "const corsOptions = { origin: reflectOrigin, credentials: true };",
      "app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));",
      "app.use(cors(corsOptions));",
      'app.get("/account", (request, response) => response.json(request.session.account));',
    ].join("\n");
    expect(await scanExpressCorsSource(stableCallback)).toHaveLength(1);
  });

  test("uses final option values and rejects browser-blocked or ambiguous policies", async () => {
    for (const options of [
      "{ origin: true }",
      "{ origin: true, credentials: false }",
      "{ origin: true, credentials: enabled }",
      "{ origin: false, credentials: true }",
      '{ origin: "*", credentials: true }',
      '{ origin: "https://app.example", credentials: true }',
      "{ origin: trustedOrigin, credentials: true }",
      "{ ...defaults, origin: true, credentials: true }",
      "{ origin: (origin, done) => allowed.has(origin) ? done(null, origin) : done(null, false), credentials: true }",
      "{ origin: true, origin: false, credentials: true }",
      "{ origin: true, credentials: true, credentials: false }",
    ]) {
      expect(await scanExpressCorsSource(accountRoute(options))).toHaveLength(
        0,
      );
    }
    expect(
      await scanExpressCorsSource(
        accountRoute("{ origin: false, origin: true, credentials: true }"),
      ),
    ).toHaveLength(1);
    expect(
      await scanExpressCorsSource(
        accountRoute("{ origin: true, credentials: false, credentials: true }"),
      ),
    ).toHaveLength(1);
  });

  test("supports Express 4, Router, CommonJS, import-equals, and route-scoped middleware", async () => {
    const commonJs = [
      'const express = require("express");',
      'const cors = require("cors");',
      'const session = require("express-session");',
      "const router = express.Router();",
      "const policy = { origin: true, credentials: true };",
      'router.use("/account", session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));',
      'router.use("/account", cors(policy));',
      "function readAccount(request, response) {",
      "  return response.send(request.session.profile);",
      "}",
      'router.get("/account", readAccount);',
    ].join("\n");
    expect(
      await scanExpressCorsSource(commonJs, {
        dependencies: {
          cors: "2.8.6",
          express: "4.22.1",
          "express-session": "1.19.0",
        },
        sourcePath: "server.cjs",
      }),
    ).toHaveLength(1);

    const importEquals = [
      'import express = require("express");',
      'import cors = require("cors");',
      'import session = require("express-session");',
      "const app = express();",
      "const policy = { origin: true, credentials: true };",
      "app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));",
      "app.use(cors(policy));",
      'app.get("/account", (request, response) => response.json(request.session.permissions));',
    ].join("\n");
    expect(
      await scanExpressCorsSource(importEquals, { sourcePath: "server.ts" }),
    ).toHaveLength(1);

    const routeScoped = [
      'import { Router } from "express";',
      'import cors from "cors";',
      'import session from "express-session";',
      "const router = Router();",
      "const policy = { origin: true, credentials: true };",
      'router.get("/account", session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }), cors(policy), (request, response) => response.json(request.session.apiKey));',
    ].join("\n");
    expect(await scanExpressCorsSource(routeScoped)).toHaveLength(1);
  });

  test("honors path scope, middleware order, mutation, and supported versions", async () => {
    const pathScoped = accountRoute().replace(
      "app.use(cors(corsOptions));",
      'app.use("/account", cors(corsOptions));',
    );
    expect(await scanExpressCorsSource(pathScoped)).toHaveLength(1);
    expect(
      await scanExpressCorsSource(
        pathScoped.replace('app.use("/account",', 'app.use("/admin",'),
      ),
    ).toHaveLength(0);
    expect(
      await scanExpressCorsSource(
        accountRoute().replace(
          'app.get("/account", readAccount);',
          'corsOptions.origin = "https://app.example";\napp.get("/account", readAccount);',
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scanExpressCorsSource(
        accountRoute("{ origin: reflectOrigin, credentials: true }")
          .replace(
            "const corsOptions =",
            "let reflectOrigin = (origin, done) => done(null, origin);\nconst corsOptions =",
          )
          .replace(
            "app.use(cors(corsOptions));",
            "reflectOrigin = trustedOrigin;\napp.use(cors(corsOptions));",
          ),
      ),
    ).toHaveLength(0);
    expect(
      await scanExpressCorsSource(
        accountRoute(undefined, "route").replace(
          "cors(corsOptions), readAccount",
          "readAccount, cors(corsOptions)",
        ),
      ),
    ).toHaveLength(0);
    for (const dependencies of [
      { cors: "1.2.2", express: "5.2.1", "express-session": "1.19.0" },
      { cors: "3.0.0", express: "5.2.1", "express-session": "1.19.0" },
      { cors: "2.8.6", express: "3.21.2", "express-session": "1.19.0" },
      { cors: "2.8.6", express: "6.0.0", "express-session": "1.19.0" },
      { cors: "2.8.6", express: "5.2.1", "express-session": "0.0.1" },
      { cors: "2.8.6", express: "5.2.1", "express-session": "2.0.0" },
    ]) {
      expect(
        await scanExpressCorsSource(accountRoute(), { dependencies }),
      ).toHaveLength(0);
    }
  });

  test("requires exact dependencies, bindings, app identity, activation, and order", async () => {
    const dependencies = {
      cors: "2.8.6",
      express: "5.2.1",
      "express-session": "1.19.0",
    };
    expect(
      await scanExpressCorsSource(accountRoute(), {
        dependencies: { express: "5.2.1", "express-session": "1.19.0" },
        devDependencies: { cors: "2.8.6" },
      }),
    ).toHaveLength(0);
    expect(
      await scanExpressCorsSource(accountRoute(), {
        dependencies: { cors: "2.8.6", express: "5.2.1" },
        devDependencies: { "express-session": "1.19.0" },
      }),
    ).toHaveLength(0);
    for (const source of [
      accountRoute().replace('"cors"', '"./cors.js"'),
      accountRoute().replace('"express-session"', '"./session.js"'),
      accountRoute().replace("app.use(cors(corsOptions));", ""),
      accountRoute().replace("app.use(session(", "other.use(session("),
      accountRoute()
        .replace(
          'app.get("/account", readAccount);',
          'app.get("/account", readAccount);\napp.use(cors(corsOptions));',
        )
        .replace("app.use(cors(corsOptions));\n", ""),
      accountRoute()
        .replace(
          'app.get("/account", readAccount);',
          'app.get("/account", readAccount);\napp.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));',
        )
        .replace(
          "app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));\n",
          "",
        ),
      accountRoute().replace(
        "app.use(cors(corsOptions));",
        "cors = localCors;\napp.use(cors(corsOptions));",
      ),
      accountRoute().replace(
        "app.use(session({ secret:",
        "session = localSession;\napp.use(session({ secret:",
      ),
      accountRoute().replace(
        'app.get("/account", readAccount);',
        'app = other;\napp.get("/account", readAccount);',
      ),
    ]) {
      expect(
        await scanExpressCorsSource(source, { dependencies }),
      ).toHaveLength(0);
    }
    expect(
      await scanExpressCorsSource(accountRoute(), {
        dependencies,
        sourcePath: "test/server.test.js",
      }),
    ).toHaveLength(0);
  });

  test("requires a registered handler and concrete session-derived response", async () => {
    for (const response of [
      'return response.json({ status: "ok" });',
      "return response.json({ email: request.query.email });",
      "return response.json({ theme: request.session.theme });",
      "return other.json({ email: request.session.account.email });",
    ]) {
      expect(
        await scanExpressCorsSource(
          accountRoute(undefined, "global", response),
        ),
      ).toHaveLength(0);
    }
    expect(
      await scanExpressCorsSource(
        accountRoute(
          undefined,
          "global",
          "const account = request.session.account;\n  return response.json(account);",
        ),
      ),
    ).toHaveLength(1);
    expect(
      await scanExpressCorsSource(
        accountRoute().replace(
          'app.get("/account", readAccount);',
          "export { readAccount };",
        ),
      ),
    ).toHaveLength(0);
  });

  test("executes paired real-cors witnesses without a server or network", () => {
    const outputs = [
      "node-express-credentialed-cors-reflection",
      "node-express-credentialed-cors-allowlist",
    ].map((fixture) => {
      const result = spawnSync(
        "node",
        [join(benchmarkRoot, "fixtures", fixture, "examples", "witness.mjs")],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            COPILOT_SECURITY_CORS_MODULE_URL: pathToFileURL(
              join(process.cwd(), "node_modules", "cors", "lib", "index.js"),
            ).href,
          },
          shell: false,
        },
      );
      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      return JSON.parse(result.stdout) as {
        allow_credentials: boolean;
        allow_origin: string;
        attacker_can_read: boolean;
        control: boolean;
      };
    });
    expect(outputs).toEqual([
      {
        allow_credentials: true,
        allow_origin: "https://attacker.example",
        attacker_can_read: true,
        control: false,
      },
      {
        allow_credentials: true,
        allow_origin: "https://app.example",
        attacker_can_read: false,
        control: true,
      },
    ]);
  });

  test("requires browser, session, origin, and impact-boundary evidence", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "node-express-credentialed-cors-reflection",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(join(tmpdir(), "cors-quality-"));
    temporaryPaths.push(scanDirectory);
    const finding: any = {
      occurrenceId: "occ_express_credentialed_cors",
      taxonomy: { cwe: ["CWE-942", "CWE-346", "CWE-639"] },
      locations: [
        { path: "src/server.js", startLine: 8, role: "source" },
        { path: "src/server.js", startLine: 21, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "cors-source",
          path: "src/server.js",
          startLine: 8,
          code: "origin: true",
          explanation: "cors reflects the requesting origin.",
          role: "source",
        },
        {
          id: "session-sink",
          path: "src/server.js",
          startLine: 21,
          code: "response.json({",
          explanation: "Express returns session-derived account data.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A permissive CORS option reaches an account route.",
        method: "source review",
        evidence: ["cors-source", "session-sink"],
      },
      attackPath: {
        summary: "The account route returns data.",
        dataflow: {
          source: "cors-source",
          sink: "session-sink",
          outcome: "response",
        },
        evidenceRefs: ["cors-source", "session-sink"],
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
      "Express 5 registers literal GET /account. Official cors 2.8.6 runs with origin: true and credentials: true after official express-session 1.19.0 activation. It reflects the attacker-controlled Origin and lets cross-origin browser JavaScript read response.json data from request.session.account when the victim is authenticated and cookie SameSite, domain, Secure, and third-party-cookie policy permit credentials. CORS governs browser response readability, not whether the server receives the request or performs authorization. CORS is not authentication or authorization and does not block the server request. This is CWE-942, CWE-346, and CWE-639; the inert in-memory witness uses no listener, request, real cookie, or account.";
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

  test("teaches the reviewer exact activation and browser boundaries", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"node-express-credentialed-cors-session-exposure"}}',
    );
    expect(prompt).toContain("node-express-credentialed-cors-session-exposure");
    expect(prompt).toContain("origin is finally literal true");
    expect(prompt).toContain('exact string "null"');
    expect(prompt).toContain("credentials: true");
    expect(prompt).toContain("express-session");
    expect(prompt).toContain("browser JavaScript read");
    expect(prompt).toContain("wildcard");
    expect(prompt).toContain("SameSite");
    expect(prompt).toContain("CWE-942/CWE-346/CWE-639");
    expect(prompt).toContain("CORS is not authentication or authorization");
  });
});
