import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function jwtAuthorizationRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-express-unverified-jwt-authorization",
    );
}

async function fixtureRecords(name: string): Promise<FrameworkRecord[]> {
  return jwtAuthorizationRecords(
    await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", name)),
  );
}

async function scanSource(
  source: string,
  options: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    sourcePath?: string;
  } = {},
): Promise<FrameworkRecord[]> {
  const repository = await mkdtemp(join(tmpdir(), "express-jwt-model-"));
  temporaryPaths.push(repository);
  await writeFile(
    join(repository, "package.json"),
    JSON.stringify({
      name: "express-jwt-model",
      private: true,
      type: "module",
      dependencies: options.dependencies ?? {
        express: "5.2.1",
        jsonwebtoken: "9.0.3",
      },
      devDependencies: options.devDependencies,
    }),
  );
  const path = join(repository, options.sourcePath ?? "server.js");
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, source);
  return jwtAuthorizationRecords(await buildResidualRiskInventory(repository));
}

function adminRoute(
  options: {
    auth?: string;
    decision?: string;
    decode?: string;
    effect?: string;
    importLine?: string;
    instance?: string;
    route?: string;
  } = {},
): string {
  return [
    'import express from "express";',
    options.importLine ?? 'import jwt from "jsonwebtoken";',
    options.instance ?? "const app = express();",
    'app.get("/admin/status", (request, response) => {',
    options.auth ??
      '  const authorization = request.get("authorization") ?? "";',
    '  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";',
    options.decode ?? "  const claims = jwt.decode(token);",
    options.decision ??
      '  if (claims?.role !== "admin") return response.status(403).end();',
    options.effect ??
      "  return response.json({ systemKey: process.env.SYSTEM_STATUS_KEY });",
    "});",
  ].join("\n");
}

describe("Express unverified JWT authorization model", () => {
  test("keeps a strict executable exploit/control benchmark contract", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-express-unverified-jwt-authorization-manifest.json",
        ),
        "utf8",
      ),
    );
    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }: { id: string }) => id)).toEqual([
      "node-express-unverified-jwt-authorization",
      "node-express-verified-jwt-authorization",
    ]);
    expect(manifest.cases[0].expected[0]).toMatchObject({
      id: "node-express-unverified-jwt-authorization",
      cwe: ["CWE-347", "CWE-863"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(
      manifest.cases[0].expected[0].requiredValidationTextAnyOf,
    ).toHaveLength(9);
    expect(
      manifest.cases[0].expected[0].requiredAttackPathTextAnyOf,
    ).toHaveLength(6);
    expect(manifest.cases[0].expected[0].forbiddenText.length).toBeGreaterThan(
      0,
    );
    expect(manifest.cases[1].expected).toEqual([]);
  });

  test("detects decoded authorization claims and rejects the verified twin", async () => {
    const vulnerable = await fixtureRecords(
      "node-express-unverified-jwt-authorization",
    );
    const control = await fixtureRecords(
      "node-express-verified-jwt-authorization",
    );

    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      id: "node-express-unverified-jwt-authorization",
      source: {
        kind: "express-bearer-authorization-token",
        path: "src/server.js",
        line: 7,
      },
      sink: {
        kind: "unverified-jwt-claim-authorization-decision",
        path: "src/server.js",
        line: 12,
        cweIds: ["CWE-347", "CWE-863"],
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "jsonwebtoken-runtime-dependency",
          symbol: "jsonwebtoken@9.0.3:manifest-exact",
        }),
        expect.objectContaining({
          kind: "express-runtime-dependency",
          symbol: "express@5.2.1:manifest-exact",
        }),
        expect.objectContaining({
          kind: "express-protected-response-after-claim-gate",
        }),
      ]),
    );
    expect(vulnerable[0]?.frameworkModel?.candidateControls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "jwt-signature-verification-absent" }),
        expect.objectContaining({ kind: "authorization-claim-gate" }),
      ]),
    );
    expect(control).toHaveLength(0);
  });

  test("supports official module and authorization-header forms", async () => {
    const variants = [
      adminRoute({
        importLine: 'import * as jwt from "jsonwebtoken";',
        auth: '  const authorization = request.headers.authorization ?? "";',
      }),
      adminRoute({
        importLine: 'import { decode as decodeJwt } from "jsonwebtoken";',
        auth: '  const authorization = request.headers["authorization"] ?? "";',
        decode: "  const claims = decodeJwt(token);",
      }),
      adminRoute({
        importLine: 'const jwt = require("jsonwebtoken");',
        auth: '  const authorization = request.header("Authorization") ?? "";',
      }),
      adminRoute({
        importLine: 'import jwt = require("jsonwebtoken");',
      }),
    ];
    for (let index = 0; index < variants.length; index += 1) {
      expect(
        await scanSource(variants[index]!, {
          sourcePath: index === 2 ? "server.cjs" : "server.ts",
        }),
      ).toHaveLength(1);
    }
  });

  test("supports Express 4 routers and named handlers", async () => {
    const source = [
      'const express = require("express");',
      'const jwt = require("jsonwebtoken");',
      "const router = express.Router();",
      "function adminStatus(request, response) {",
      '  const authorization = request.get("authorization") ?? "";',
      '  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";',
      "  const claims = jwt.decode(token);",
      '  if (!claims?.permissions?.includes("system:read")) return response.status(403).end();',
      "  return response.send(process.env.SYSTEM_STATUS_KEY);",
      "}",
      'router.get("/admin/status", adminStatus);',
    ].join("\n");
    const records = await scanSource(source, {
      dependencies: { express: "4.22.1", jsonwebtoken: "8.5.1" },
      sourcePath: "server.cjs",
    });
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "express-router-factory-binding",
          symbol: "router",
        }),
        expect.objectContaining({
          kind: "jsonwebtoken-runtime-dependency",
          symbol: "jsonwebtoken@8.5.1:manifest-exact",
        }),
      ]),
    );
  });

  test("requires exact production dependencies and official bindings", async () => {
    for (const dependencies of [
      { express: "3.21.2", jsonwebtoken: "9.0.3" },
      { express: "5.2.1", jsonwebtoken: "7.4.3" },
      { express: "5.2.1", jsonwebtoken: "^9.0.0" },
    ]) {
      expect(await scanSource(adminRoute(), { dependencies })).toHaveLength(0);
    }
    expect(
      await scanSource(adminRoute(), {
        dependencies: { express: "5.2.1" },
        devDependencies: { jsonwebtoken: "9.0.3" },
      }),
    ).toHaveLength(0);
    expect(
      await scanSource(
        adminRoute({ importLine: "const jwt = localJwtLibrary;" }),
      ),
    ).toHaveLength(0);
  });

  test("rejects rebound package, method, application, and handler identities", async () => {
    for (const line of [
      "jwt = localJwtLibrary;",
      "jwt.decode = localDecode;",
      "app = anotherApp;",
      "app.get = localGet;",
    ]) {
      const source = adminRoute().replace(
        'app.get("/admin/status",',
        `${line}\napp.get("/admin/status",`,
      );
      expect(await scanSource(source)).toHaveLength(0);
    }
    const named = [
      'import express from "express";',
      'import jwt from "jsonwebtoken";',
      "const app = express();",
      "function adminStatus(request, response) {",
      '  const token = request.get("authorization");',
      "  const claims = jwt.decode(token);",
      '  if (claims.role !== "admin") return response.status(403).end();',
      "  return response.json({ secret: process.env.SYSTEM_STATUS_KEY });",
      "}",
      "adminStatus = replacement;",
      'app.get("/admin/status", adminStatus);',
    ].join("\n");
    expect(await scanSource(named)).toHaveLength(0);
  });

  test("requires a literal registered route and an Express handler", async () => {
    expect(
      await scanSource(adminRoute().replace('"/admin/status"', "routePath")),
    ).toHaveLength(0);
    expect(
      await scanSource(adminRoute().replace("app.get", "localApp.get")),
    ).toHaveLength(0);
    expect(
      await scanSource(
        adminRoute()
          .replace(
            'app.get("/admin/status", (request, response) => {',
            "function adminStatus(request, response) {",
          )
          .replace(/\n\}\);$/u, "\n}"),
      ),
    ).toHaveLength(0);
    expect(
      await scanSource(adminRoute(), { sourcePath: "test/server.test.js" }),
    ).toHaveLength(0);
  });

  test("requires a live Bearer source to reach the decode call", async () => {
    expect(
      await scanSource(
        adminRoute().replace(
          '  const authorization = request.get("authorization") ?? "";\n  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";',
          '  const token = request.get("authorization") ?? "";',
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scanSource(
        adminRoute({
          auth: '  const authorization = "Bearer fixed.fixture.token";',
        }),
      ),
    ).toHaveLength(0);
    expect(
      await scanSource(
        adminRoute({
          auth: "  const authorization = request.body.token;",
        }),
      ),
    ).toHaveLength(0);
    expect(
      await scanSource(
        adminRoute().replace(
          "  const claims = jwt.decode(token);",
          '  token = "fixed.fixture.token";\n  const claims = jwt.decode(token);',
        ),
      ),
    ).toHaveLength(0);
  });

  test("requires decoded authorization claims and a later protected effect", async () => {
    for (const source of [
      adminRoute({
        decision:
          "  if (claims.exp < Date.now()) return response.status(403).end();",
      }),
      adminRoute({
        decode:
          "  const decoded = jwt.decode(token);\n  const claims = trustedClaims;",
      }),
      adminRoute().replace(
        "  if (claims?.role",
        '  claims = { role: "user" };\n  if (claims?.role',
      ),
      adminRoute({ effect: "  return true;" }),
      adminRoute({
        effect: '  return response.status(403).json({ error: "denied" });',
      }),
    ]) {
      expect(await scanSource(source)).toHaveLength(0);
    }
  });

  test("executes the real jsonwebtoken exploit and verification witnesses", () => {
    const outputs = [
      "node-express-unverified-jwt-authorization",
      "node-express-verified-jwt-authorization",
    ].map((fixture) => {
      const result = spawnSync(
        "node",
        [join(benchmarkRoot, "fixtures", fixture, "examples", "witness.mjs")],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            COPILOT_SECURITY_JSONWEBTOKEN_MODULE_URL: pathToFileURL(
              join(process.cwd(), "node_modules", "jsonwebtoken", "index.js"),
            ).href,
          },
          shell: false,
        },
      );
      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      return JSON.parse(result.stdout) as {
        authorization_granted: boolean;
        control: boolean;
        signature_verified: boolean;
      };
    });
    expect(outputs).toEqual([
      {
        authorization_granted: true,
        control: false,
        signature_verified: false,
      },
      {
        authorization_granted: false,
        control: true,
        signature_verified: false,
      },
    ]);
  });

  test("requires JWT integrity and authorization-boundary evidence", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "node-express-unverified-jwt-authorization",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(join(tmpdir(), "jwt-quality-"));
    temporaryPaths.push(scanDirectory);
    const finding: any = {
      occurrenceId: "occ_express_unverified_jwt",
      taxonomy: { cwe: ["CWE-347", "CWE-863"] },
      locations: [
        { path: "src/server.js", startLine: 7, role: "source" },
        { path: "src/server.js", startLine: 12, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "jwt-source",
          path: "src/server.js",
          startLine: 7,
          code: 'const authorization = request.get("authorization") ?? "";',
          explanation: "The Express handler reads a Bearer credential.",
          role: "source",
        },
        {
          id: "jwt-sink",
          path: "src/server.js",
          startLine: 12,
          code: 'if (claims?.role !== "admin") return response.status(403).end();',
          explanation: "An unverified role claim controls the admin gate.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A decoded token reaches an admin check.",
        method: "source review",
        evidence: ["jwt-source", "jwt-sink"],
      },
      attackPath: {
        summary: "A role claim controls a response.",
        dataflow: {
          source: "jwt-source",
          sink: "jwt-sink",
          outcome: "authorization",
        },
        evidenceRefs: ["jwt-source", "jwt-sink"],
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
      "Express 5 registers the literal GET /admin/status admin route. The request Authorization Bearer token reaches official jsonwebtoken 9.0.3 jwt.decode without signature verification. The attacker-authored role claim controls the authorization decision and accepted branch returning the protected SYSTEM_STATUS_KEY response. Verify signature with a pinned algorithm, trusted issuer, expected audience, and nonempty key before using any claim. This is CWE-347 and CWE-863 authorization bypass. The inert witness starts no listener, sends no network request, and uses no real token, credential, key, or protected data.";
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

  test("teaches the reviewer the exact JWT trust boundary", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"node-express-unverified-jwt-authorization"}}',
    );
    expect(prompt).toContain("node-express-unverified-jwt-authorization");
    expect(prompt).toContain("jsonwebtoken.decode");
    expect(prompt).toContain("signature verification");
    expect(prompt).toContain("algorithm, issuer, and audience");
    expect(prompt).toContain("CWE-347/CWE-863");
    expect(prompt).toContain("protected response");
    expect(prompt).toContain("inert unsigned token");
  });
});
