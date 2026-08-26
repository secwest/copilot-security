import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface FrameworkRecord {
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
    }>;
  }>;
}

interface CaseOptions {
  declaration?: string;
  dependencySection?: "dependencies" | "devDependencies";
  lock?: boolean;
  lockedVersion?: string;
  lockfileVersion?: number;
  middlewarePath?: string;
  middlewareSource?: string;
  packageName?: string;
  rootLockDeclaration?: string;
  routePath?: string;
  routeSource?: string;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const temporaryPaths: string[] = [];

const defaultMiddleware = `import { NextResponse } from "next/server";
export function middleware(request) {
  if (request.nextUrl.pathname === "/documents/secret") {
    return new NextResponse("Unauthorized", { status: 401 });
  }
  return NextResponse.next();
}
export const config = { matcher: "/documents/:path*" };
`;

const defaultRoute = `export default async function Page({ params }) {
  return loadDocument((await params).slug);
}
`;

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function nextJsRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-nextjs-dynamic-route-param-authorization-bypass",
    );
}

async function temporaryRepository(label: string): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), `copilot-security-nextjs-${label}-`),
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
  const routePath = options.routePath ?? "src/app/documents/[slug]/page.js";
  const middlewarePath = options.middlewarePath ?? "src/middleware.js";
  const packageName = options.packageName ?? "next";
  const declaration = options.declaration ?? "15.5.15";
  const dependencySection = options.dependencySection ?? "dependencies";
  await mkdir(dirname(join(root, routePath)), { recursive: true });
  await mkdir(dirname(join(root, middlewarePath)), { recursive: true });
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
                [packageName]: {
                  version: options.lockedVersion ?? "15.5.15",
                },
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
                  version: options.lockedVersion ?? "15.5.15",
                },
              },
            },
        null,
        2,
      ),
    );
  }
  await writeFile(
    join(root, middlewarePath),
    options.middlewareSource ?? defaultMiddleware,
  );
  await writeFile(join(root, routePath), options.routeSource ?? defaultRoute);
}

describe("Next.js dynamic route parameter authorization model", () => {
  test("keeps a strict affected and repaired executable benchmark pair", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-nextjs-dynamic-route-param-authorization-manifest.json",
        ),
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
      "node-nextjs-dynamic-route-param-authorization-bypass",
      "node-nextjs-dynamic-route-param-isolated",
    ]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-288"],
      acceptableSeverities: ["high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);

    const affected = nextJsRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-nextjs-dynamic-route-param-authorization-bypass",
        ),
      ),
    );
    const repaired = nextJsRecords(
      await buildResidualRiskInventory(
        join(
          benchmarkRoot,
          "fixtures",
          "node-nextjs-dynamic-route-param-isolated",
        ),
      ),
    );
    expect(affected).toHaveLength(1);
    expect(repaired).toHaveLength(0);
    expect(affected[0]).toMatchObject({
      path: "src/pages/documents/[slug].jsx",
      line: 11,
      frameworkModel: {
        scope: "cross-file",
        source: {
          kind: "external-next-internal-route-param-query-injection",
          path: "src/middleware.js",
          line: 4,
        },
        sink: {
          kind: "vulnerable-nextjs-dynamic-route-param-data-access",
          path: "src/pages/documents/[slug].jsx",
          line: 11,
          cweIds: ["CWE-288"],
        },
      },
    });
    expect(affected[0]?.frameworkModel?.propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "nextjs-visible-pathname-authorization-gate",
          symbol: "/documents/secret",
        }),
        expect.objectContaining({
          kind: "nextjs-dynamic-route-parameter",
          symbol: "slug:nxtPslug:secret",
        }),
        expect.objectContaining({
          kind: "nextjs-server-data-access",
          line: 11,
          symbol: "slug:loadDocument(",
        }),
        expect.objectContaining({
          kind: "nextjs-runtime-dependency",
          symbol:
            "next@15.5.15:manifest-exact:external-nxtP-route-param-normalization",
        }),
      ]),
    );
  });

  test("enforces both official stable affected intervals", async () => {
    const repository = await temporaryRepository("versions");
    const cases = [
      ["before", "15.3.9", false],
      ["first-15", "15.4.0", true],
      ["middle-15", "15.4.12", true],
      ["last-15", "15.5.15", true],
      ["fixed-15", "15.5.16", false],
      ["later-15", "15.6.0", false],
      ["first-16", "16.0.0", true],
      ["middle-16", "16.1.9", true],
      ["last-16", "16.2.4", true],
      ["fixed-16", "16.2.5", false],
      ["prerelease", "16.2.4-canary.1", false],
      ["later-major", "17.0.0", false],
    ] as const;
    await Promise.all(
      cases.map(([id, declaration]) =>
        writeCase(repository, id, { declaration }),
      ),
    );
    const found = new Set(
      nextJsRecords(await buildResidualRiskInventory(repository)).map(
        ({ path }) => path.split("/")[0],
      ),
    );
    for (const [id, , expected] of cases) {
      expect(found.has(id)).toBe(expected);
    }
  });

  test("recognizes bounded middleware and proxy authorization forms", async () => {
    const repository = await temporaryRepository("gates");
    const cases = [
      ["direct", defaultMiddleware, "src/middleware.js"],
      [
        "alias",
        `import { NextResponse } from "next/server";
export function middleware(request) {
  const pathname = request.nextUrl.pathname;
  if (pathname === "/documents/secret") return new Response("Forbidden", { status: 403 });
  return NextResponse.next();
}
export const config = { matcher: "/documents/:path*" };
`,
        "src/middleware.js",
      ],
      [
        "reversed",
        `import { NextResponse } from "next/server";
export function middleware(request) {
  if ("/documents/secret" === request.nextUrl.pathname) {
    return NextResponse.redirect(new URL("/login", request.url));
  }
  return NextResponse.next();
}
`,
        "src/middleware.js",
      ],
      [
        "proxy",
        `import { NextResponse } from "next/server";
export function proxy(request) {
  if (
    request.nextUrl.pathname === "/documents/secret"
  ) return new NextResponse("Unauthorized", { status: 401 });
  return NextResponse.next();
}
`,
        "src/proxy.js",
      ],
    ] as const;
    await Promise.all(
      cases.map(([id, middlewareSource, middlewarePath]) =>
        writeCase(repository, id, { middlewarePath, middlewareSource }),
      ),
    );
    expect(
      nextJsRecords(await buildResidualRiskInventory(repository))
        .map(({ path }) => path.split("/")[0])
        .sort(),
    ).toEqual(cases.map(([id]) => id).sort());
  });

  test("fails closed for incomplete or unrelated visible-path gates", async () => {
    const repository = await temporaryRepository("gate-negatives");
    const cases: Array<[string, string]> = [
      [
        "no-next-server",
        defaultMiddleware.replace(
          'import { NextResponse } from "next/server";',
          "const NextResponse = globalThis.NextResponse;",
        ),
      ],
      [
        "no-denial",
        defaultMiddleware.replace(
          'return new NextResponse("Unauthorized", { status: 401 });',
          "return NextResponse.next();",
        ),
      ],
      [
        "unrelated-path",
        defaultMiddleware.replace("/documents/secret", "/admin/secret"),
      ],
      [
        "unrelated-matcher",
        defaultMiddleware.replace("/documents/:path*", "/unrelated/:path*"),
      ],
      [
        "dynamic-denial",
        defaultMiddleware.replace(
          'request.nextUrl.pathname === "/documents/secret"',
          "request.nextUrl.pathname === protectedPath",
        ),
      ],
    ];
    await Promise.all(
      cases.map(([id, middlewareSource]) =>
        writeCase(repository, id, { middlewareSource }),
      ),
    );
    expect(nextJsRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("binds one dynamic segment to an actual server-side data access", async () => {
    const repository = await temporaryRepository("routes");
    const positive = [
      ["direct", "src/app/documents/[slug]/page.js", defaultRoute],
      [
        "bracket",
        "src/app/documents/[slug]/page.js",
        `export default async function Page({ params }) {
  return fetch("https://records.invalid/" + params["slug"]);
}
`,
      ],
      [
        "destructured-alias",
        "src/app/(staff)/documents/[slug]/page.js",
        `export default async function Page({ params }) {
  const { slug: documentId } = await params;
  return database.documents.findUnique({ where: { id: documentId } });
}
`,
      ],
      [
        "pages-router",
        "src/pages/documents/[slug].js",
        `export async function getServerSideProps({ params }) {
  const document = await repository.lookup(params.slug);
  return { props: { document } };
}
export default function Page({ document }) { return document; }
`,
      ],
    ] as const;
    await Promise.all(
      positive.map(([id, routePath, routeSource]) =>
        writeCase(repository, id, { routePath, routeSource }),
      ),
    );
    const negative = [
      [
        "display-only",
        "src/app/documents/[slug]/page.js",
        `export default async function Page({ params }) {
  return <main>{(await params).slug}</main>;
}
`,
      ],
      [
        "route-local-auth",
        "src/app/documents/[slug]/page.js",
        `export default async function Page({ params }) {
  const session = await auth();
  if (!session) redirect("/login");
  return loadDocument((await params).slug);
}
`,
      ],
      [
        "two-dynamic-segments",
        "src/app/[tenant]/documents/[slug]/page.js",
        defaultRoute,
      ],
      ["static-route", "src/app/documents/public/page.js", defaultRoute],
      [
        "reassigned-alias",
        "src/app/documents/[slug]/page.js",
        `export default async function Page({ params }) {
  let { slug: documentId } = await params;
  documentId = "public";
  return loadDocument(documentId);
}
`,
      ],
    ] as const;
    await Promise.all(
      negative.map(([id, routePath, routeSource]) =>
        writeCase(repository, id, { routePath, routeSource }),
      ),
    );
    expect(
      nextJsRecords(await buildResidualRiskInventory(repository))
        .map(({ path }) => path.split("/")[0])
        .sort(),
    ).toEqual(positive.map(([id]) => id).sort());
  });

  test("accepts only exact production or fresh modern npm provenance", async () => {
    const repository = await temporaryRepository("metadata");
    await Promise.all([
      writeCase(repository, "exact"),
      writeCase(repository, "locked-v2", {
        declaration: "^15.4.0",
        lock: true,
        lockfileVersion: 2,
      }),
      writeCase(repository, "locked-v3", {
        declaration: ">=15.4.0 <15.5.16",
        lock: true,
      }),
      writeCase(repository, "unlocked-range", { declaration: "^15.4.0" }),
      writeCase(repository, "fixed-lock", {
        declaration: "^15.4.0",
        lock: true,
        lockedVersion: "15.5.16",
      }),
      writeCase(repository, "stale-lock", {
        declaration: "^15.4.0",
        lock: true,
        rootLockDeclaration: "~15.4.0",
      }),
      writeCase(repository, "legacy-lock", {
        declaration: "^15.4.0",
        lock: true,
        lockfileVersion: 1,
      }),
      writeCase(repository, "dev-only", {
        dependencySection: "devDependencies",
      }),
      writeCase(repository, "wrong-package", {
        packageName: "next-lookalike",
      }),
    ]);
    const found = nextJsRecords(await buildResidualRiskInventory(repository));
    expect(found.map(({ path }) => path.split("/")[0]).sort()).toEqual([
      "exact",
      "locked-v2",
      "locked-v3",
    ]);
    expect(
      found
        .filter(({ path }) => path.startsWith("locked-"))
        .every(({ frameworkModel }) =>
          frameworkModel?.sink.kind.startsWith("lock-resolved-"),
        ),
    ).toBe(true);
  });

  test("requires primitive-specific validation and restrained impact claims", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({
        frameworkModel: {
          id: "node-nextjs-dynamic-route-param-authorization-bypass",
        },
      }),
    );
    expect(prompt).toContain("GHSA-492v-c6pp-mqqv");
    expect(prompt).toContain("15.5.16");
    expect(prompt).toContain("16.2.5");
    expect(prompt).toContain("nxtP plus the dynamic segment name");
    expect(prompt).toContain("disposable loopback server");
    expect(prompt).toContain("ordinary public request");
    expect(prompt).toContain(
      "Do not treat failure to reproduce under ordinary next start as repaired-version proof",
    );
    expect(prompt).toContain("CWE-288");
    expect(prompt).toContain("Do not infer account takeover");
  });
});
