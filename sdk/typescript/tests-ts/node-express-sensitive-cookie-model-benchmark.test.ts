import { afterEach, describe, expect, test } from "bun:test";
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
    candidateControls: Array<{
      kind: string;
      path: string;
      line: number;
      symbol?: string;
    }>;
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

function sensitiveCookieRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-express-sensitive-cookie-missing-httponly",
    );
}

async function fixtureRecords(name: string): Promise<FrameworkRecord[]> {
  return sensitiveCookieRecords(
    await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", name)),
  );
}

async function scanExpressCookieSource(
  source: string,
  options: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    sourcePath?: string;
  } = {},
): Promise<FrameworkRecord[]> {
  const repository = await mkdtemp(join(tmpdir(), "express-cookie-model-"));
  temporaryPaths.push(repository);
  await writeFile(
    join(repository, "package.json"),
    JSON.stringify({
      name: "express-cookie-model",
      private: true,
      type: "module",
      dependencies: options.dependencies ?? {
        express: "5.2.1",
        jsonwebtoken: "9.0.3",
      },
      ...(options.devDependencies === undefined
        ? {}
        : { devDependencies: options.devDependencies }),
    }),
  );
  const path = join(repository, options.sourcePath ?? "server.js");
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, source);
  return sensitiveCookieRecords(await buildResidualRiskInventory(repository));
}

function inlineSessionRoute(
  options = '{ secure: true, sameSite: "lax" }',
): string {
  return [
    'import express from "express";',
    'import jwt from "jsonwebtoken";',
    "const app = express();",
    'app.post("/session", (request, response) => {',
    "  const token = jwt.sign({ sub: request.user.id }, process.env.JWT_KEY);",
    `  return response.cookie("__Host-session", token, ${options});`,
    "});",
  ].join("\n");
}

describe("Express sensitive-cookie HttpOnly model", () => {
  test("keeps the browser-readable and HttpOnly fixtures paired", async () => {
    const vulnerable = await fixtureRecords(
      "node-express-sensitive-cookie-readable",
    );
    const control = await fixtureRecords(
      "node-express-sensitive-cookie-httponly",
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      id: "node-express-sensitive-cookie-missing-httponly",
      source: {
        kind: "jsonwebtoken-signed-authentication-token",
        path: "src/server.js",
        line: 14,
      },
      sink: {
        kind: "express-browser-readable-sensitive-cookie",
        path: "src/server.js",
        line: 19,
        cweIds: ["CWE-1004"],
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
          symbol: "__Host-session",
        }),
      ]),
      candidateControls: expect.arrayContaining([
        expect.objectContaining({ kind: "explicitly-disabled-httponly" }),
        expect.objectContaining({ kind: "secure-cookie-attribute" }),
        expect.objectContaining({ kind: "samesite-cookie-attribute" }),
      ]),
    });
    expect(control).toHaveLength(0);
  });

  test("detects omitted or false HttpOnly and rejects ambiguous values", async () => {
    expect(await scanExpressCookieSource(inlineSessionRoute())).toHaveLength(1);
    expect(
      await scanExpressCookieSource(
        inlineSessionRoute(
          '{ httpOnly: false, secure: true, sameSite: "strict" }',
        ),
      ),
    ).toHaveLength(1);
    expect(
      await scanExpressCookieSource(
        inlineSessionRoute('{ httpOnly: true, secure: true, sameSite: "lax" }'),
      ),
    ).toHaveLength(0);
    expect(
      await scanExpressCookieSource(
        inlineSessionRoute(
          '{ httpOnly: enabled, secure: true, sameSite: "lax" }',
        ),
      ),
    ).toHaveLength(0);
  });

  test("supports stable option bindings, CommonJS, routers, and direct sign imports", async () => {
    const commonjs = await scanExpressCookieSource(
      [
        'const express = require("express");',
        'const jwt = require("jsonwebtoken");',
        "const router = express.Router();",
        'const options = { secure: true, sameSite: "lax" };',
        'router.put("/auth/token", function login(req, res) {',
        '  return res.cookie("access_token", jwt.sign({ sub: req.user.id }, process.env.JWT_KEY), options);',
        "});",
      ].join("\n"),
    );
    expect(commonjs).toHaveLength(1);
    expect(commonjs[0]?.frameworkModel?.source.line).toBe(6);
    expect(commonjs[0]?.frameworkModel?.sink.line).toBe(6);

    const namedSign = await scanExpressCookieSource(
      inlineSessionRoute()
        .replace(
          'import jwt from "jsonwebtoken";',
          'import { sign as createToken } from "jsonwebtoken";',
        )
        .replace("jwt.sign(", "createToken("),
    );
    expect(namedSign).toHaveLength(1);

    const multilineDirect = await scanExpressCookieSource(
      inlineSessionRoute()
        .replace(
          '  return response.cookie("__Host-session", token, { secure: true, sameSite: "lax" });',
          [
            "  return response.cookie(",
            '    "__Host-session",',
            "    jwt.sign({ sub: request.user.id }, process.env.JWT_KEY),",
            '    { secure: true, sameSite: "lax" },',
            "  );",
          ].join("\n"),
        )
        .replace(
          "  const token = jwt.sign({ sub: request.user.id }, process.env.JWT_KEY);\n",
          "",
        ),
    );
    expect(multilineDirect).toHaveLength(1);

    const importEquals = await scanExpressCookieSource(
      [
        'import express = require("express");',
        'import jwt = require("jsonwebtoken");',
        "const app = express();",
        'app.post("/login", function (request, response) {',
        "  const signed = jwt.sign({ sub: request.user.id }, process.env.JWT_KEY);",
        '  response.cookie("refresh-token", signed);',
        "});",
      ].join("\n"),
    );
    expect(importEquals).toHaveLength(1);
  });

  test("requires a literal sensitive name and a proven jsonwebtoken sign result", async () => {
    expect(
      await scanExpressCookieSource(
        inlineSessionRoute().replace('"__Host-session"', '"theme"'),
      ),
    ).toHaveLength(0);
    expect(
      await scanExpressCookieSource(
        inlineSessionRoute().replace('"__Host-session"', "cookieName"),
      ),
    ).toHaveLength(0);
    expect(
      await scanExpressCookieSource(
        inlineSessionRoute().replace(
          "jwt.sign({ sub: request.user.id }, process.env.JWT_KEY)",
          '"public-preference"',
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scanExpressCookieSource(
        inlineSessionRoute().replace('"jsonwebtoken"', '"./jsonwebtoken.js"'),
      ),
    ).toHaveLength(0);
  });

  test("rejects development dependencies, excluded paths, and rebound identities", async () => {
    expect(
      await scanExpressCookieSource(inlineSessionRoute(), {
        dependencies: { express: "5.2.1" },
        devDependencies: { jsonwebtoken: "9.0.3" },
      }),
    ).toHaveLength(0);
    expect(
      await scanExpressCookieSource(inlineSessionRoute(), {
        sourcePath: join("tests", "cookie.test.js"),
      }),
    ).toHaveLength(0);
    for (const mutation of [
      "express = localExpress;",
      "jwt = localJwt;",
      "app = localApp;",
      "response.cookie = localCookie;",
    ]) {
      const source = inlineSessionRoute().replace(
        'app.post("/session", (request, response) => {',
        `app.post("/session", (request, response) => {\n  ${mutation}`,
      );
      expect(await scanExpressCookieSource(source)).toHaveLength(0);
    }
  });

  test("records Secure and SameSite without confusing them with HttpOnly", async () => {
    const [record] = await scanExpressCookieSource(inlineSessionRoute());
    expect(record?.frameworkModel?.candidateControls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "secure-cookie-attribute" }),
        expect.objectContaining({ kind: "samesite-cookie-attribute" }),
      ]),
    );
    expect(record?.frameworkModel?.candidateControls).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "httponly-cookie-attribute" }),
      ]),
    );
  });

  test("requires route, token, cookie, visibility, prerequisite, and CWE evidence", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "node-express-sensitive-cookie-readable",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "express-cookie-quality-"),
    );
    temporaryPaths.push(scanDirectory);
    const finding: any = {
      occurrenceId: "occ_express_sensitive_cookie",
      taxonomy: { cwe: ["CWE-1004"] },
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
          code: 'response.cookie("__Host-session", token, sessionCookie)',
          explanation: "Express writes the session cookie.",
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
      "Express 5 registers literal POST /session. jsonwebtoken jwt.sign creates a signed authentication token and the response writes it to the __Host-session cookie with httpOnly: false. Browser JavaScript executing in the same origin can read that session value through document.cookie; an XSS or equivalent script-execution prerequisite is a separate prerequisite not proven by this in-memory, no-server witness. This is CWE-1004.";
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

  test("teaches the reviewer sensitivity, visibility, and impact boundaries", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"node-express-sensitive-cookie-missing-httponly"}}',
    );
    expect(prompt).toContain("node-express-sensitive-cookie-missing-httponly");
    expect(prompt).toContain("jsonwebtoken");
    expect(prompt).toContain("response.cookie");
    expect(prompt).toContain("httpOnly");
    expect(prompt).toContain("document.cookie");
    expect(prompt).toContain("CWE-1004");
    expect(prompt).toContain("XSS");
    expect(prompt).toContain("account takeover");
  });
});
