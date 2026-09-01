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

function authRateLimitRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-fastify-authentication-missing-rate-limit",
    );
}

async function fixtureRecords(name: string): Promise<FrameworkRecord[]> {
  return authRateLimitRecords(
    await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", name)),
  );
}

async function scanFastifyAuthSource(
  source: string,
  options: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    sourcePath?: string;
  } = {},
): Promise<FrameworkRecord[]> {
  const repository = await mkdtemp(join(tmpdir(), "fastify-auth-limit-model-"));
  temporaryPaths.push(repository);
  await writeFile(
    join(repository, "package.json"),
    JSON.stringify({
      name: "fastify-auth-limit-model",
      private: true,
      type: "module",
      dependencies: options.dependencies ?? {
        "@fastify/rate-limit": "11.2.0",
        bcryptjs: "3.0.2",
        fastify: "5.12.1",
      },
      ...(options.devDependencies === undefined
        ? {}
        : { devDependencies: options.devDependencies }),
    }),
  );
  const path = join(repository, options.sourcePath ?? "server.js");
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, source);
  return authRateLimitRecords(await buildResidualRiskInventory(repository));
}

function inlineBcryptRoute(): string {
  return [
    'import Fastify from "fastify";',
    'import bcrypt from "bcryptjs";',
    "const app = Fastify();",
    'app.post("/login", async (request, reply) => {',
    "  const password = request.body.password;",
    "  const accepted = await bcrypt.compare(password, process.env.HASH);",
    '  if (!accepted) return reply.code(401).send("invalid");',
    "  return reply.send({ ok: true });",
    "});",
  ].join("\n");
}

describe("Fastify authentication rate-limit model", () => {
  test("keeps the inert configuration and registered-plugin fixtures paired", async () => {
    const vulnerable = await fixtureRecords(
      "node-fastify-auth-inert-rate-limit",
    );
    const control = await fixtureRecords(
      "node-fastify-auth-enforced-rate-limit",
    );
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      id: "node-fastify-authentication-missing-rate-limit",
      source: {
        kind: "fastify-request-body-password",
        path: "src/server.js",
        line: 8,
      },
      sink: {
        kind: "bcryptjs-password-verification-attempt",
        path: "src/server.js",
        line: 9,
        cweIds: ["CWE-307", "CWE-400", "CWE-770"],
      },
      propagators: expect.arrayContaining([
        expect.objectContaining({
          kind: "fastify-literal-authentication-route",
          symbol: "POST /login",
        }),
        expect.objectContaining({
          kind: "unregistered-fastify-rate-limit-configuration",
        }),
        expect.objectContaining({
          kind: "password-verifier-runtime-dependency",
          symbol: "bcryptjs@3.0.2:manifest-exact",
        }),
      ]),
    });
    expect(control).toHaveLength(0);
  });

  test("requires plugin activation before crediting per-route configuration", async () => {
    const prefix = [
      'import Fastify from "fastify";',
      'import rateLimit from "@fastify/rate-limit";',
      'import bcrypt from "bcryptjs";',
      "const app = Fastify();",
    ];
    const suffix = [
      "async function login(request) {",
      "  return bcrypt.compare(request.body.password, process.env.HASH);",
      "}",
      'app.post("/login", { config: { rateLimit: { max: 5 } } }, login);',
    ];
    const inert = await scanFastifyAuthSource(
      [...prefix, ...suffix].join("\n"),
    );
    expect(inert).toHaveLength(1);
    expect(inert[0]?.frameworkModel?.candidateControls).toContainEqual(
      expect.objectContaining({
        kind: "inert-fastify-rate-limit-route-configuration",
      }),
    );
    const active = await scanFastifyAuthSource(
      [
        ...prefix,
        "await app.register(rateLimit, { global: false });",
        ...suffix,
      ].join("\n"),
    );
    expect(active).toHaveLength(0);
  });

  test("models global, disabled-global, disabled-route, and registration order", async () => {
    const build = (registration: string, options = "") =>
      [
        'import Fastify from "fastify";',
        'import rateLimit from "@fastify/rate-limit";',
        'import bcrypt from "bcryptjs";',
        "const app = Fastify();",
        ...(registration === "after" ? [] : [registration]),
        `app.post("/login"${options}, async (request) => bcrypt.compare(request.body.password, process.env.HASH));`,
        ...(registration === "after" ? ["await app.register(rateLimit);"] : []),
      ].join("\n");
    expect(
      await scanFastifyAuthSource(
        build("await app.register(rateLimit, { max: 5 });"),
      ),
    ).toHaveLength(0);
    expect(
      await scanFastifyAuthSource(
        build("await app.register(rateLimit, { global: false });"),
      ),
    ).toHaveLength(1);
    expect(
      await scanFastifyAuthSource(
        build(
          "await app.register(rateLimit);",
          ", { config: { rateLimit: false } }",
        ),
      ),
    ).toHaveLength(1);
    expect(await scanFastifyAuthSource(build("after"))).toHaveLength(1);
  });

  test("supports direct plugin imports, direct route options, and route objects", async () => {
    const dynamicGlobal = await scanFastifyAuthSource(
      [
        'import Fastify from "fastify";',
        'import bcrypt from "bcryptjs";',
        "const app = Fastify();",
        'await app.register(import("@fastify/rate-limit"), { max: 5 });',
        'app.post("/login", async (request) => bcrypt.compare(request.body.password, process.env.HASH));',
      ].join("\n"),
    );
    expect(dynamicGlobal).toHaveLength(0);

    const directOptions = await scanFastifyAuthSource(
      [
        'const app = require("fastify")();',
        'const bcrypt = require("bcryptjs");',
        'app.register(require("@fastify/rate-limit"), { global: false });',
        'app.post("/login", { rateLimit: { max: 5 } }, async (request) => bcrypt.compare(request.body.password, process.env.HASH));',
      ].join("\n"),
    );
    expect(directOptions).toHaveLength(0);

    const objectRoute = await scanFastifyAuthSource(
      [
        'import Fastify from "fastify";',
        'import bcrypt from "bcryptjs";',
        "const app = Fastify();",
        "app.route({",
        '  method: "POST",',
        '  url: "/login",',
        "  config: { rateLimit: { max: 5 } },",
        "  handler: async (request) => bcrypt.compare(request.body.password, process.env.HASH),",
        "});",
      ].join("\n"),
    );
    expect(objectRoute).toHaveLength(1);
  });

  test("supports bcrypt, bcryptjs, and argon2 verifier bindings", async () => {
    const named = await scanFastifyAuthSource(
      [
        'import { fastify as createServer } from "fastify";',
        'import { compare as verifyPassword } from "bcrypt";',
        "const app = createServer();",
        'app.put("/session", async (request) => verifyPassword(request.body.passcode, process.env.HASH));',
      ].join("\n"),
      {
        dependencies: {
          "@fastify/rate-limit": "11.2.0",
          bcrypt: "6.0.0",
          fastify: "5.12.1",
        },
      },
    );
    expect(named).toHaveLength(1);
    expect(named[0]?.frameworkModel?.sink.kind).toBe(
      "bcrypt-password-verification-attempt",
    );

    const argon = await scanFastifyAuthSource(
      [
        'import Fastify from "fastify";',
        'import * as argon2 from "argon2";',
        "const app = Fastify();",
        'app.post("/login", async (request) => argon2.verify(process.env.HASH, request.body.password));',
      ].join("\n"),
      {
        dependencies: {
          "@fastify/rate-limit": "11.2.0",
          argon2: "0.44.0",
          fastify: "5.12.1",
        },
      },
    );
    expect(argon).toHaveLength(1);
    expect(argon[0]?.frameworkModel?.sink.kind).toBe(
      "argon2-password-verification-attempt",
    );
  });

  test("rejects fixed credentials, lookalikes, development dependencies, tests, and rebound bindings", async () => {
    expect(
      await scanFastifyAuthSource(
        inlineBcryptRoute().replace(
          "bcrypt.compare(password, process.env.HASH)",
          'bcrypt.compare("fixed", process.env.HASH)',
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scanFastifyAuthSource(
        inlineBcryptRoute().replace('"bcryptjs"', '"./bcryptjs.js"'),
      ),
    ).toHaveLength(0);
    expect(
      await scanFastifyAuthSource(inlineBcryptRoute(), {
        dependencies: { fastify: "5.12.1" },
        devDependencies: { bcryptjs: "3.0.2" },
      }),
    ).toHaveLength(0);
    expect(
      await scanFastifyAuthSource(inlineBcryptRoute(), {
        sourcePath: join("tests", "login.test.js"),
      }),
    ).toHaveLength(0);

    for (const mutation of [
      "Fastify = localFactory;",
      "bcrypt = localVerifier;",
      "app = localApp;",
    ]) {
      const found = await scanFastifyAuthSource(
        [
          'import Fastify from "fastify";',
          'import bcrypt from "bcryptjs";',
          "const app = Fastify();",
          mutation,
          'app.post("/login", async (request) => bcrypt.compare(request.body.password, process.env.HASH));',
        ].join("\n"),
      );
      expect(found).toHaveLength(0);
    }
  });

  test("requires route, password, verifier, activation, attempt, and CWE evidence", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "node-fastify-auth-inert-rate-limit",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "fastify-auth-quality-"),
    );
    temporaryPaths.push(scanDirectory);
    const finding: any = {
      occurrenceId: "occ_fastify_auth_rate_limit",
      taxonomy: { cwe: ["CWE-307", "CWE-400", "CWE-770"] },
      locations: [
        { path: "src/server.js", startLine: 8, role: "source" },
        { path: "src/server.js", startLine: 9, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "password-source",
          path: "src/server.js",
          startLine: 8,
          code: "request.body.password",
          explanation: "Remote Fastify password field.",
          role: "source",
        },
        {
          id: "password-sink",
          path: "src/server.js",
          startLine: 9,
          code: "bcrypt.compare(password, process.env.PASSWORD_HASH)",
          explanation: "Password verification attempt.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A request password reaches bcrypt.",
        method: "source review",
        evidence: ["password-source", "password-sink"],
      },
      attackPath: {
        summary: "A request password reaches bcrypt.",
        dataflow: {
          source: "password-source",
          sink: "password-sink",
          outcome: "password check",
        },
        evidenceRefs: ["password-source", "password-sink"],
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
      "Fastify 5 registers literal POST /login and reads remote request.body.password before the bcryptjs bcrypt.compare password verification attempt. The route declares config.rateLimit max five, but @fastify/rate-limit has no plugin registration, so the configuration is inert and repeated password guesses continue to the expensive verifier; the sixth in-memory attempt is not rejected. This is missing authentication-attempt throttling under CWE-307, CWE-400, and CWE-770.";
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

  test("teaches the reviewer activation, ordering, and authentication boundaries", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"node-fastify-authentication-missing-rate-limit"}}',
    );
    expect(prompt).toContain("node-fastify-authentication-missing-rate-limit");
    expect(prompt).toContain("@fastify/rate-limit");
    expect(prompt).toContain("global: false");
    expect(prompt).toContain("config.rateLimit");
    expect(prompt).toContain("registered before the route");
    expect(prompt).toContain("bcrypt");
    expect(prompt).toContain("argon2");
    expect(prompt).toContain("CWE-307");
    expect(prompt).toContain("account takeover");
  });
});
