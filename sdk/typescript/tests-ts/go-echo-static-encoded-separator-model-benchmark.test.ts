import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { buildResidualRiskInventory } from "../src/residual-risk.js";
import { scanQualityGatePrompt } from "../src/copilot-client.js";

interface EchoRecord {
  path: string;
  line: number;
  frameworkModel?: {
    id: string;
    source: { line: number };
    sink: { kind: string; path: string; line: number; cweIds: string[] };
    propagators: Array<{ kind: string; line: number; symbol?: string }>;
  };
}

const temporaryPaths: string[] = [];
const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

afterEach(async () => {
  await Promise.all(
    temporaryPaths.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

function records(inventory: string): EchoRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as EchoRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "go-echo-static-encoded-separator-auth-bypass",
    );
}

function application(
  module = "github.com/labstack/echo/v4",
  alias = "echo",
  groupMiddleware = ", requireSession",
  staticPrefix = '"/"',
  start = 'e.Start(":8080")',
): string {
  return `package main

import ${alias} "${module}"

func configure() error {
	e := ${alias}.New()
	admin := e.Group("/admin"${groupMiddleware})
	admin.GET("/*", protectedFile)
	e.StaticFS(${staticPrefix}, publicFiles)
	return ${start}
}
`;
}

async function scan(
  source: string,
  module = "github.com/labstack/echo/v4",
  version = "v4.15.2",
  goModSuffix = "",
): Promise<EchoRecord[]> {
  const root = await mkdtemp(join(tmpdir(), "copilot-security-echo-static-"));
  temporaryPaths.push(root);
  await writeFile(
    join(root, "go.mod"),
    `module example.test/echo-case\n\ngo 1.24\n\nrequire ${module} ${version}\n${goModSuffix}`,
  );
  await writeFile(join(root, "main.go"), source);
  return records(await buildResidualRiskInventory(root));
}

describe("Echo encoded static-separator authorization model", () => {
  test("keeps the real affected and repaired fixtures source-identical", async () => {
    const affectedRoot = join(
      benchmarkRoot,
      "fixtures",
      "go-echo-static-encoded-separator-bypass",
    );
    const repairedRoot = join(
      benchmarkRoot,
      "fixtures",
      "go-echo-static-encoded-separator-repaired",
    );
    expect(await readFile(join(affectedRoot, "src", "main.go"), "utf8")).toBe(
      await readFile(join(repairedRoot, "src", "main.go"), "utf8"),
    );
    const affected = records(await buildResidualRiskInventory(affectedRoot));
    const repaired = records(await buildResidualRiskInventory(repairedRoot));
    expect(affected).toHaveLength(1);
    expect(repaired).toHaveLength(0);
    expect(affected[0]?.line).toBe(24);
    expect(affected[0]?.frameworkModel?.source.line).toBe(22);
  });

  test("binds a protected wildcard prefix to a root static handler and live server", async () => {
    const found = await scan(application());
    expect(found).toHaveLength(1);
    expect(found[0]?.line).toBe(9);
    expect(found[0]?.frameworkModel?.source.line).toBe(7);
    expect(found[0]?.frameworkModel?.sink).toEqual({
      kind: "echo-root-static-file-handler",
      path: "main.go",
      line: 9,
      cweIds: ["CWE-22"],
    });
    expect(found[0]?.frameworkModel?.propagators.at(-1)?.symbol).toBe(
      "github.com/labstack/echo/v4@v4.15.2:go-mod-exact:encoded-separator-static-auth-bypass",
    );
  });

  test("supports aliased imports, Static, and group Use middleware", async () => {
    const source = application("github.com/labstack/echo/v4", "web", "")
      .replace(
        'admin := e.Group("/admin")',
        'admin := e.Group("/admin")\n\tadmin.Use(requireSession)',
      )
      .replace('e.StaticFS("/", publicFiles)', 'e.Static("/", "public")');
    const found = await scan(source);
    expect(found).toHaveLength(1);
    expect(
      found[0]?.frameworkModel?.propagators.some(
        (propagator) =>
          propagator.kind === "middleware-protected-prefix" &&
          propagator.line === 8,
      ),
    ).toBe(true);
  });

  test("requires an exact net/http import for standard-library server startup", async () => {
    const aliasedHttp = application(
      "github.com/labstack/echo/v4",
      "web",
      ", requireSession",
      '"/"',
      'transport.ListenAndServe(":8080", e)',
    ).replace(
      'import web "github.com/labstack/echo/v4"',
      'import (\n\ttransport "net/http"\n\tweb "github.com/labstack/echo/v4"\n)',
    );
    expect(await scan(aliasedHttp)).toHaveLength(1);
    expect(
      await scan(
        application(
          "github.com/labstack/echo/v4",
          "echo",
          ", requireSession",
          '"/"',
          'ListenAndServe(":8080", e)',
        ),
      ),
    ).toHaveLength(0);
  });

  test("enforces the patched v4 and v5 boundaries and stable releases", async () => {
    expect(await scan(application(), undefined, "v4.0.0")).toHaveLength(1);
    expect(await scan(application(), undefined, "v4.15.2")).toHaveLength(1);
    expect(await scan(application(), undefined, "v4.15.3")).toHaveLength(0);
    expect(await scan(application(), undefined, "v4.16.0-rc.1")).toHaveLength(
      0,
    );

    const v5Module = "github.com/labstack/echo/v5";
    const v5Source = application(v5Module);
    expect(await scan(v5Source, v5Module, "v5.1.0")).toHaveLength(1);
    expect(await scan(v5Source, v5Module, "v5.2.0")).toHaveLength(0);
  });

  test("supports the unpatched legacy v3 module with exact incompatible metadata", async () => {
    const module = "github.com/labstack/echo";
    expect(
      await scan(application(module), module, "v3.3.10+incompatible"),
    ).toHaveLength(1);
    expect(await scan(application(module), module, "v3.3.11")).toHaveLength(0);
  });

  test("rejects incomplete or intentionally public route topologies", async () => {
    const base = application();
    const cases = [
      base.replace(", requireSession", ""),
      base.replace(
        'admin.GET("/*", protectedFile)',
        'admin.GET("/profile", protectedFile)',
      ),
      base.replace(
        'e.StaticFS("/", publicFiles)',
        'e.StaticFS("/assets", publicFiles)',
      ),
      base.replace("\treturn e.Start", "\treturn other.Start"),
      base.replace('\treturn e.Start(":8080")', "\treturn nil"),
      base.replace(
        'import echo "github.com/labstack/echo/v4"',
        'import echo "example.test/echo"',
      ),
      base
        .replace(", requireSession", "")
        .replace(
          'admin.GET("/*", protectedFile)',
          'admin.GET("/*", protectedFile)\n\tadmin.Use(requireSession)',
        ),
    ];
    for (const source of cases) {
      expect(await scan(source)).toHaveLength(0);
    }
  });

  test("rejects instance, group, and module replacement", async () => {
    const base = application();
    expect(
      await scan(
        base.replace("\treturn e.Start", "\te = replacement\n\treturn e.Start"),
      ),
    ).toHaveLength(0);
    expect(
      await scan(
        base.replace(
          'admin.GET("/*", protectedFile)',
          'admin = replacement\n\tadmin.GET("/*", protectedFile)',
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scan(
        base,
        undefined,
        "v4.15.2",
        "\nreplace github.com/labstack/echo/v4 => ./local-echo\n",
      ),
    ).toHaveLength(0);
  });

  test("uses only the nearest exact go.mod and excludes tests and examples", async () => {
    const root = await mkdtemp(
      join(tmpdir(), "copilot-security-echo-nearest-"),
    );
    temporaryPaths.push(root);
    await writeFile(
      join(root, "go.mod"),
      "module example.test/root\n\nrequire github.com/labstack/echo/v4 v4.15.2\n",
    );
    await mkdir(join(root, "service"));
    await writeFile(
      join(root, "service", "go.mod"),
      "module example.test/service\n\nrequire github.com/labstack/echo/v4 v4.15.3\n",
    );
    await writeFile(join(root, "service", "main.go"), application());
    await writeFile(join(root, "main_test.go"), application());
    await mkdir(join(root, "examples"));
    await writeFile(join(root, "examples", "main.go"), application());
    expect(records(await buildResidualRiskInventory(root))).toHaveLength(0);
  });

  test("requires a bounded differential and file-policy impact proof", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("go-echo-static-encoded-separator-auth-bypass");
    expect(prompt).toContain("GHSA-vfp3-v2gw-7wfq");
    expect(prompt).toContain("github.com/labstack/echo/v4 before 4.15.3");
    expect(prompt).toContain("direct /protected/marker request");
    expect(prompt).toContain("httptest or a loopback-only listener");
    expect(prompt).toContain("Report CWE-22");
    expect(prompt).toContain("never read a real secret");
  });
});
