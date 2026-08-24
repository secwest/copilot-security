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
        "node-authjs-configuration-error-fail-open",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(
    join(tmpdir(), "copilot-security-node-authjs-fail-open-"),
  );
  temporaryPaths.push(root);
  return root;
}

async function writeCase(
  root: string,
  id: string,
  options: {
    authSource?: string;
    declaration?: string;
    lockedVersion?: string;
    middlewareSource?: string;
    packageName?: string;
    section?: "dependencies" | "devDependencies";
    lock?: boolean;
    lockfileVersion?: number;
  } = {},
): Promise<void> {
  const directory = join(root, id);
  await mkdir(join(directory, "src"), { recursive: true });
  const packageName = options.packageName ?? "next-auth";
  const declaration = options.declaration ?? "5.0.0-beta.31";
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({
      name: id,
      private: true,
      [options.section ?? "dependencies"]: { [packageName]: declaration },
    }),
  );
  if (options.lock === true) {
    await writeFile(
      join(directory, "package-lock.json"),
      JSON.stringify({
        name: id,
        lockfileVersion: options.lockfileVersion ?? 3,
        packages: {
          "": { dependencies: { [packageName]: declaration } },
          [`node_modules/${packageName}`]: {
            version: options.lockedVersion ?? "5.0.0-beta.31",
          },
        },
      }),
    );
  }
  await writeFile(
    join(directory, "src", "auth.ts"),
    options.authSource ??
      'import NextAuth from "next-auth";\nexport const { auth } = NextAuth({ providers: [] });',
  );
  await writeFile(
    join(directory, "src", "middleware.ts"),
    options.middlewareSource ??
      'import { auth } from "./auth";\nimport { NextResponse } from "next/server";\nexport default auth((request) => {\n const loggedIn = !!request.auth;\n if (!loggedIn) return NextResponse.redirect(new URL("/login", request.url));\n return NextResponse.next();\n});',
  );
}

describe("Auth.js configuration-error fail-open model", () => {
  test("preserves official factory and wrapper bindings across supported module forms", async () => {
    const root = await repository();
    const cases = [
      [
        "default-alias",
        'import AuthFactory from "next-auth";\nexport const { auth: protect } = AuthFactory({ providers: [] });',
        'import { protect as gate } from "./auth";\nexport default gate((request) => {\n if (!request.auth) return Response.redirect("/login");\n return new Response("private");\n});',
      ],
      [
        "namespace-default",
        'import * as authjs from "next-auth";\nexport const { auth } = authjs.default({ providers: [] });',
        undefined,
      ],
      [
        "typescript-import-equals",
        'import Auth = require("next-auth");\nexport const { auth } = Auth.default({ providers: [] });',
        undefined,
      ],
      [
        "commonjs-default",
        'const Auth = require("next-auth").default;\nexports.auth = Auth({ providers: [] }).auth;',
        'const { auth } = require("./auth");\nmodule.exports = auth((request) => {\n const loggedIn = Boolean(request.auth);\n if (!loggedIn) return Response.redirect("/login");\n return new Response("private");\n});',
      ],
      [
        "destructured-default",
        'const { default: Auth } = require("next-auth");\nexport const { auth } = Auth({ providers: [] });',
        undefined,
      ],
    ] as const;
    await Promise.all(
      cases.map(([id, authSource, middlewareSource]) =>
        writeCase(root, id, { authSource, middlewareSource }),
      ),
    );
    expect(
      records(await buildResidualRiskInventory(root))
        .map(({ path }) => path)
        .sort(),
    ).toEqual(cases.map(([id]) => `${id}/src/middleware.ts`).sort());
  });

  test("uses the complete published affected beta boundary", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(root, "first-beta", { declaration: "5.0.0-beta.0" }),
      writeCase(root, "last-affected", { declaration: "5.0.0-beta.31" }),
      writeCase(root, "first-repaired", { declaration: "5.0.0-beta.32" }),
      writeCase(root, "later-beta", { declaration: "5.0.0-beta.40" }),
      writeCase(root, "v4", { declaration: "4.24.11" }),
    ]);
    expect(
      records(await buildResidualRiskInventory(root))
        .map(({ path }) => path)
        .sort(),
    ).toEqual(
      [
        "first-beta/src/middleware.ts",
        "last-affected/src/middleware.ts",
      ].sort(),
    );
  });

  test("supports exact prereleases and fresh declaration-consistent npm v2/v3 proof", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(root, "exact", { declaration: "5.0.0-beta.31" }),
      writeCase(root, "locked-v2", {
        declaration: "^5.0.0-beta.0",
        lock: true,
        lockfileVersion: 2,
      }),
      writeCase(root, "locked-v3", {
        declaration: ">=5.0.0-beta.0 <5.0.0-beta.32",
        lock: true,
      }),
      writeCase(root, "unlocked-range", {
        declaration: "^5.0.0-beta.0",
      }),
      writeCase(root, "repaired-lock", {
        declaration: "^5.0.0-beta.0",
        lockedVersion: "5.0.0-beta.32",
        lock: true,
      }),
      writeCase(root, "legacy-lock", {
        declaration: "^5.0.0-beta.0",
        lock: true,
        lockfileVersion: 1,
      }),
    ]);
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path).sort()).toEqual(
      [
        "exact/src/middleware.ts",
        "locked-v2/src/middleware.ts",
        "locked-v3/src/middleware.ts",
      ].sort(),
    );
    expect(
      found
        .filter(({ path }) => path.startsWith("locked-"))
        .every(({ frameworkModel }) =>
          frameworkModel?.sink.kind.startsWith("lock-resolved-"),
        ),
    ).toBe(true);
  });

  test("recognizes bare direct, aliased, destructured, and no-argument auth decisions", async () => {
    const root = await repository();
    const cases = [
      [
        "direct-negative",
        'import { auth } from "./auth";\nexport default auth((req) => {\n if (!req.auth) return Response.redirect("/login");\n return new Response("private");\n});',
      ],
      [
        "direct-positive",
        'import { auth } from "./auth";\nexport default auth((req) => {\n if (req.auth) return new Response("private");\n return Response.redirect("/login");\n});',
      ],
      [
        "destructured",
        'import { auth } from "./auth";\nexport default auth(({ auth: session }) => {\n return !!session ? new Response("private") : Response.redirect("/login");\n});',
      ],
      [
        "local-alias",
        'import { auth } from "./auth";\nexport default auth((req) => {\n const session = req.auth;\n const loggedIn = Boolean(session);\n if (!loggedIn) return Response.redirect("/login");\n return new Response("private");\n});',
      ],
      [
        "no-argument",
        'import { auth } from "./auth";\nexport async function GET() {\n const session = await auth();\n if (!session) return new Response("denied", { status: 401 });\n return new Response("private");\n}',
      ],
    ] as const;
    await Promise.all(
      cases.map(([id, middlewareSource]) =>
        writeCase(root, id, { middlewareSource }),
      ),
    );
    expect(
      records(await buildResidualRiskInventory(root))
        .map(({ path }) => path)
        .sort(),
    ).toEqual(cases.map(([id]) => `${id}/src/middleware.ts`).sort());
  });

  test("models the official authorized callback through deployed proxy exports", async () => {
    const root = await repository();
    const cases = [
      [
        "relative-reexport",
        'import NextAuth from "next-auth";\nexport const { auth } = NextAuth({ callbacks: { authorized: async ({ auth }) => {\n return !!auth;\n} } });',
        'export { auth as proxy } from "./auth";',
        true,
      ],
      [
        "root-alias-expression",
        'import NextAuth from "next-auth";\nexport const { auth } = NextAuth({ callbacks: { authorized: ({ auth: session }) => Boolean(session) } });',
        'export { auth as middleware } from "@/auth";',
        true,
      ],
      [
        "imported-reexport-method",
        'import NextAuth from "next-auth";\nexport const { auth } = NextAuth({ callbacks: { authorized({ auth }) {\n if (!auth) return false;\n return true;\n} } });',
        'import { auth as gate } from "./auth";\nexport { gate as middleware };',
        true,
      ],
      [
        "safe-concrete-user",
        'import NextAuth from "next-auth";\nexport const { auth } = NextAuth({ callbacks: { authorized: ({ auth }) => !!auth?.user } });',
        'export { auth as proxy } from "./auth";',
        false,
      ],
      [
        "not-deployed",
        'import NextAuth from "next-auth";\nexport const { auth } = NextAuth({ callbacks: { authorized: ({ auth }) => !!auth } });',
        'import { auth } from "./auth";\nexport const inspect = auth;',
        false,
      ],
    ] as const;
    await Promise.all(
      cases.map(([id, authSource, middlewareSource]) =>
        writeCase(root, id, { authSource, middlewareSource }),
      ),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path).sort()).toEqual(
      cases
        .filter(([, , , expected]) => expected)
        .map(([id]) => `${id}/src/auth.ts`)
        .sort(),
    );
    for (const record of found) {
      expect(record.frameworkModel?.source.path).toBe(
        record.path.replace(/auth\.ts$/u, "middleware.ts"),
      );
      expect(record.frameworkModel?.source.kind).toBe(
        "unauthenticated-authjs-request-during-configuration-error",
      );
      expect(record.frameworkModel?.sink.cweIds).toEqual([
        "CWE-636",
        "CWE-285",
      ]);
    }
  });

  test("resolves the common unique root alias but rejects ambiguity", async () => {
    const root = await repository();
    await writeCase(root, "unique-alias", {
      middlewareSource:
        'import { auth } from "@/auth";\nexport default auth((request) => {\n if (!request.auth) return Response.redirect("/login");\n return new Response("private");\n});',
    });
    const ambiguous = join(root, "ambiguous-alias");
    await writeCase(root, "ambiguous-alias", {
      middlewareSource:
        'import { auth } from "@/auth";\nexport default auth((request) => {\n if (!request.auth) return Response.redirect("/login");\n return new Response("private");\n});',
    });
    await mkdir(join(ambiguous, "other"), { recursive: true });
    await writeFile(
      join(ambiguous, "other", "auth.ts"),
      'import NextAuth from "next-auth";\nexport const { auth } = NextAuth({ providers: [] });',
    );
    expect(
      records(await buildResidualRiskInventory(root)).map(({ path }) => path),
    ).toEqual(["unique-alias/src/middleware.ts"]);
  });

  test("rejects concrete session checks, inert truthiness, and unproved provenance", async () => {
    const root = await repository();
    const cases = [
      [
        "safe-user",
        'import { auth } from "./auth";\nexport default auth((request) => {\n if (!request.auth?.user) return Response.redirect("/login");\n return new Response("private");\n});',
      ],
      [
        "safe-role",
        'import { auth } from "./auth";\nexport default auth((request) => {\n if (request.auth?.user?.role !== "admin") return Response.redirect("/login");\n return new Response("private");\n});',
      ],
      [
        "log-only",
        'import { auth } from "./auth";\nexport default auth((request) => {\n const loggedIn = !!request.auth;\n console.log(loggedIn);\n return new Response("public");\n});',
      ],
      [
        "conditional-log-only",
        'import { auth } from "./auth";\nexport default auth((request) => {\n if (request.auth) console.log("present");\n return new Response("public");\n});',
      ],
      [
        "no-argument-log-only",
        'import { auth } from "./auth";\nexport async function GET() {\n const session = await auth();\n if (session) console.log("present");\n return new Response("public");\n}',
      ],
      [
        "unused-wrapper",
        'import { auth } from "./auth";\nexport const middleware = auth;',
      ],
    ] as const;
    await Promise.all(
      cases.map(([id, middlewareSource]) =>
        writeCase(root, id, { middlewareSource }),
      ),
    );
    await Promise.all([
      writeCase(root, "dev-only", { section: "devDependencies" }),
      writeCase(root, "wrong-package", { packageName: "@auth/core" }),
      writeCase(root, "reassigned-import", {
        authSource:
          'import NextAuth from "next-auth";\nNextAuth = localFactory;\nexport const { auth } = NextAuth({ providers: [] });',
      }),
      writeCase(root, "reassigned-wrapper", {
        middlewareSource:
          'import { auth } from "./auth";\nauth = localAuth;\nexport default auth((request) => {\n if (!request.auth) return Response.redirect("/login");\n return new Response("private");\n});',
      }),
      writeCase(root, "local-lookalike", {
        authSource:
          'export const auth = (callback) => callback;\nconst packageName = "next-auth";',
      }),
    ]);
    await mkdir(join(root, "test-only", "test"), { recursive: true });
    await writeFile(
      join(root, "test-only", "package.json"),
      JSON.stringify({ dependencies: { "next-auth": "5.0.0-beta.31" } }),
    );
    await writeFile(
      join(root, "test-only", "test", "auth.ts"),
      'import NextAuth from "next-auth";\nexport const { auth } = NextAuth({ providers: [] });',
    );
    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("keeps the benchmark pair source-identical and under perfect gates", async () => {
    const vulnerable = join(
      benchmarkRoot,
      "fixtures",
      "node-authjs-configuration-error-fail-open",
    );
    const repaired = join(
      benchmarkRoot,
      "fixtures",
      "node-authjs-configuration-error-fail-closed",
    );
    const found = records(await buildResidualRiskInventory(vulnerable));
    expect(found).toHaveLength(1);
    expect(records(await buildResidualRiskInventory(repaired))).toEqual([]);
    expect(found[0]?.frameworkModel?.source).toEqual({
      kind: "unauthenticated-authjs-request-during-configuration-error",
      path: "src/middleware.ts",
      line: 4,
    });
    expect(found[0]?.frameworkModel?.sink).toEqual({
      kind: "vulnerable-next-auth-truthy-error-object-authorization-decision",
      path: "src/middleware.ts",
      line: 5,
      cweIds: ["CWE-636", "CWE-285"],
    });
    for (const path of [
      "src/auth.ts",
      "src/middleware.ts",
      "examples/witness.mjs",
    ]) {
      expect(await readFile(join(vulnerable, path), "utf8")).toBe(
        await readFile(join(repaired, path), "utf8"),
      );
    }
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-authjs-configuration-error-manifest.json"),
        "utf8",
      ),
    ) as {
      thresholds: Record<string, number>;
      cases: Array<{ id: string; expected: unknown[] }>;
    };
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-authjs-configuration-error-fail-open",
      "node-authjs-configuration-error-fail-closed",
    ]);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(manifest.thresholds["minPrecision"]).toBe(1);
    expect(manifest.thresholds["minRecall"]).toBe(1);
    expect(manifest.thresholds["maxFalsePositivesPerRun"]).toBe(0);
  });

  test("teaches the exact error-object, version, and impact boundaries", () => {
    const prompt = scanQualityGatePrompt("inventory-row");
    expect(prompt).toContain("node-authjs-configuration-error-fail-open rows");
    expect(prompt).toContain("GHSA-8fpg-xm3f-6cx3");
    expect(prompt).toContain("5.0.0-beta.31");
    expect(prompt).toContain("5.0.0-beta.32");
    expect(prompt).toContain("CWE-636");
    expect(prompt).toContain("CWE-285");
  });
});
