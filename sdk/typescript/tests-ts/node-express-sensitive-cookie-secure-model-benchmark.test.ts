import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
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

function secureCookieRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-express-sensitive-cookie-missing-secure",
    );
}

async function fixtureRecords(name: string): Promise<FrameworkRecord[]> {
  return secureCookieRecords(
    await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", name)),
  );
}

async function scanExpressCookieSource(
  source: string,
  sourcePath = "server.js",
): Promise<FrameworkRecord[]> {
  const repository = await mkdtemp(join(tmpdir(), "express-secure-model-"));
  temporaryPaths.push(repository);
  await writeFile(
    join(repository, "package.json"),
    JSON.stringify({
      name: "express-secure-model",
      private: true,
      type: "module",
      dependencies: { express: "5.2.1", jsonwebtoken: "9.0.3" },
    }),
  );
  const path = join(repository, sourcePath);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, source);
  return secureCookieRecords(await buildResidualRiskInventory(repository));
}

function inlineSessionRoute(
  options = '{ httpOnly: true, secure: false, sameSite: "lax" }',
  name = '"session"',
): string {
  return [
    'import express from "express";',
    'import jwt from "jsonwebtoken";',
    "const app = express();",
    'app.post("/session", (request, response) => {',
    "  const token = jwt.sign({ sub: request.user.id }, process.env.JWT_KEY);",
    `  return response.cookie(${name}, token, ${options});`,
    "});",
  ].join("\n");
}

describe("Express sensitive-cookie Secure model", () => {
  test("detects the cleartext fixture and rejects its Secure twin", async () => {
    const vulnerable = await fixtureRecords(
      "node-express-sensitive-cookie-cleartext",
    );
    const control = await fixtureRecords(
      "node-express-sensitive-cookie-secure",
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      id: "node-express-sensitive-cookie-missing-secure",
      source: {
        kind: "jsonwebtoken-signed-authentication-token",
        path: "src/server.js",
        line: 14,
      },
      sink: {
        kind: "express-cleartext-sensitive-cookie",
        path: "src/server.js",
        line: 19,
        cweIds: ["CWE-614", "CWE-319"],
      },
      propagators: expect.arrayContaining([
        expect.objectContaining({
          kind: "express-literal-session-route",
          symbol: "POST /session",
        }),
        expect.objectContaining({
          kind: "jsonwebtoken-runtime-dependency",
          symbol: "jsonwebtoken@9.0.3:manifest-exact",
        }),
        expect.objectContaining({
          kind: "sensitive-response-cookie-name",
          symbol: "session",
        }),
      ]),
      candidateControls: expect.arrayContaining([
        expect.objectContaining({ kind: "explicitly-disabled-secure" }),
        expect.objectContaining({ kind: "httponly-cookie-attribute" }),
        expect.objectContaining({ kind: "samesite-cookie-attribute" }),
      ]),
    });
    expect(control).toHaveLength(0);
  });

  test("detects omitted or false Secure and rejects ambiguous values", async () => {
    expect(
      await scanExpressCookieSource(
        inlineSessionRoute('{ httpOnly: true, sameSite: "lax" }'),
      ),
    ).toHaveLength(1);
    expect(await scanExpressCookieSource(inlineSessionRoute())).toHaveLength(1);
    expect(
      await scanExpressCookieSource(
        inlineSessionRoute(
          "{ httpOnly: true, secure: false, sameSite: false, partitioned: false }",
        ),
      ),
    ).toHaveLength(1);
    expect(
      await scanExpressCookieSource(
        inlineSessionRoute("{ httpOnly: true, secure: true }"),
      ),
    ).toHaveLength(0);
    expect(
      await scanExpressCookieSource(
        inlineSessionRoute("{ httpOnly: true, secure: production }"),
      ),
    ).toHaveLength(0);
    expect(
      await scanExpressCookieSource(
        inlineSessionRoute("{ ...defaults, secure: false }"),
      ),
    ).toHaveLength(0);
    expect(
      await scanExpressCookieSource(
        inlineSessionRoute("{ secure: true, secure: false }"),
      ),
    ).toHaveLength(1);
    expect(
      await scanExpressCookieSource(
        inlineSessionRoute("{ secure: false, secure: true }"),
      ),
    ).toHaveLength(0);
  });

  test("keeps independent HttpOnly semantics and browser rejection controls", async () => {
    expect(
      await scanExpressCookieSource(
        inlineSessionRoute("{ httpOnly: dynamicValue, secure: false }"),
      ),
    ).toHaveLength(1);
    expect(
      await scanExpressCookieSource(inlineSessionRoute("{ secure: false }")),
    ).toHaveLength(1);
    for (const source of [
      inlineSessionRoute(
        "{ httpOnly: true, secure: false }",
        '"__Host-session"',
      ),
      inlineSessionRoute(
        "{ httpOnly: true, secure: false }",
        '"__Secure-session"',
      ),
      inlineSessionRoute(
        "{ httpOnly: true, secure: false }",
        '"__secure-session"',
      ),
      inlineSessionRoute(
        "{ httpOnly: true, secure: false }",
        '"__HOST-session"',
      ),
      inlineSessionRoute('{ httpOnly: true, secure: false, sameSite: "none" }'),
      inlineSessionRoute(
        "{ httpOnly: true, secure: false, sameSite: sameSitePolicy }",
      ),
      inlineSessionRoute(
        '{ httpOnly: true, secure: false, sameSite: "invalid" }',
      ),
      inlineSessionRoute(
        "{ httpOnly: true, secure: false, partitioned: true }",
      ),
      inlineSessionRoute(
        "{ httpOnly: true, secure: false, partitioned: partitionPolicy }",
      ),
    ]) {
      expect(await scanExpressCookieSource(source)).toHaveLength(0);
    }
  });

  test("keeps both transport witnesses offline, inert, and paired", () => {
    const outputs = [
      "node-express-sensitive-cookie-cleartext",
      "node-express-sensitive-cookie-secure",
    ].map((fixture) => {
      const result = spawnSync(
        process.execPath,
        [join(benchmarkRoot, "fixtures", fixture, "examples", "witness.mjs")],
        { encoding: "utf8", shell: false },
      );
      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      return JSON.parse(result.stdout) as {
        control: boolean;
        permits_http_transport: boolean;
        set_cookie: string;
      };
    });
    expect(outputs).toEqual([
      {
        control: false,
        permits_http_transport: true,
        set_cookie: "session=modeled-session-value; HttpOnly; SameSite=Lax",
      },
      {
        control: true,
        permits_http_transport: false,
        set_cookie:
          "session=modeled-session-value; HttpOnly; Secure; SameSite=Lax",
      },
    ]);
  });

  test("requires transport and deployment-boundary evidence", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "node-express-sensitive-cookie-cleartext",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(join(tmpdir(), "secure-quality-"));
    temporaryPaths.push(scanDirectory);
    const finding: any = {
      occurrenceId: "occ_express_cleartext_cookie",
      taxonomy: { cwe: ["CWE-614", "CWE-319"] },
      locations: [
        { path: "src/server.js", startLine: 14, role: "source" },
        { path: "src/server.js", startLine: 19, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "jwt-source",
          path: "src/server.js",
          startLine: 14,
          code: "const token = jwt.sign(",
          explanation: "jsonwebtoken creates the authentication value.",
          role: "source",
        },
        {
          id: "cookie-sink",
          path: "src/server.js",
          startLine: 19,
          code: 'response.cookie("session", token, sessionCookie)',
          explanation: "Express serializes the response cookie.",
          role: "sink",
        },
      ],
      validation: {
        summary: "Express writes a signed value to a cookie.",
        method: "source review",
        evidence: ["jwt-source", "cookie-sink"],
      },
      attackPath: {
        summary: "A signed value reaches a cookie.",
        dataflow: {
          source: "jwt-source",
          sink: "cookie-sink",
          outcome: "cookie write",
        },
        evidenceRefs: ["jwt-source", "cookie-sink"],
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
      "Express 5 registers literal POST /session. jsonwebtoken jwt.sign creates a signed authentication token and response.cookie writes the session authentication cookie with secure: false. This permits HTTP cleartext transmission and possible network interception only if the deployment is HTTP reachable; HTTPS deployment and an on-path observer are separate transport prerequisites. HttpOnly and SameSite do not encrypt transport. This is CWE-614 and CWE-319.";
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

  test("teaches the reviewer transport, rejection, and impact boundaries", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"node-express-sensitive-cookie-missing-secure"}}',
    );
    expect(prompt).toContain("node-express-sensitive-cookie-missing-secure");
    expect(prompt).toContain("secure property is literal false");
    expect(prompt).toContain("__Host-");
    expect(prompt).toContain("SameSite=None");
    expect(prompt).toContain("partitioned: true");
    expect(prompt).toContain("matching as case-insensitive");
    expect(prompt).toContain("CWE-614/CWE-319");
    expect(prompt).toContain("HTTP-reachable deployment");
    expect(prompt).toContain("account takeover");
  });
});
