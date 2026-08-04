import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface GoTemplateRecord {
  path: string;
  line: number;
  categories: string[];
  frameworkModel?: {
    schemaVersion: string;
    id: string;
    language: string;
    scope: string;
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

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const caseIds = [
  "go-cross-file-template-injection",
  "go-cross-file-safe-template-data",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): GoTemplateRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as GoTemplateRecord)
    .filter(
      (record) => record.frameworkModel?.id === "go-http-template-injection",
    );
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<GoTemplateRecord[]> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-go-template-"),
  );
  temporaryPaths.push(repository);
  for (const [path, source] of Object.entries(files)) {
    const absolute = join(repository, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, source);
  }
  return models(await buildResidualRiskInventory(repository));
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

function handler(
  body: string,
  options: {
    templateAlias?: string;
    templateImport?: string;
    httpAlias?: string;
  } = {},
): string {
  const templateAlias = options.templateAlias ?? "template";
  const templateImport = options.templateImport ?? "text/template";
  const httpAlias = options.httpAlias ?? "http";
  const templateDeclaration =
    templateAlias === "template"
      ? `"${templateImport}"`
      : `${templateAlias} "${templateImport}"`;
  const httpDeclaration =
    httpAlias === "http" ? '"net/http"' : `${httpAlias} "net/http"`;
  return `package preview

import (
  ${httpDeclaration}
  ${templateDeclaration}
)

func Handler(w ${httpAlias}.ResponseWriter, r *${httpAlias}.Request) {
${body}
}
`;
}

describe("Go HTTP text/template framework-model benchmark", () => {
  test("keeps the exploit and fixed-template control under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "go-http-template-injection-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;
    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([...caseIds]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-1336"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves the exact cross-file parse-to-execute path", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "renderer.go",
      line: 16,
      categories: [
        "framework-dataflow:go-http-template-injection",
        "modeled-source:go-http-query-parameter",
        "modeled-sink:go-text-template-execution",
      ],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "go",
        scope: "cross-file-wrapper",
        source: {
          kind: "go-http-query-parameter",
          path: "handler.go",
          line: 6,
        },
        sink: {
          kind: "go-text-template-execution",
          path: "renderer.go",
          line: 16,
          cweIds: ["CWE-1336"],
        },
      },
    });
    expect(
      vulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "go-function-argument",
      "go-string-parameter",
      "go-text-template-construction",
      "go-template-function-map",
      "go-template-source-parse",
      "go-template-execution",
    ]);
    expect(safe).toEqual([]);
  });

  test("models typed query, form, path, and header sources", async () => {
    const sources = [
      ['r.URL.Query().Get("source")', "go-http-query-parameter"],
      ['r.URL.Query()["source"][0]', "go-http-query-parameter"],
      ['r.FormValue("source")', "go-http-form-value"],
      ['r.PathValue("source")', "go-http-path-value"],
      ['r.Header.Get("X-Template")', "go-http-header"],
    ] as const;
    for (const [expression, kind] of sources) {
      const rows = await repositoryInventory({
        "handler.go": handler(
          `  parsed, _ := template.New("page").Parse(${expression})
  parsed.Execute(w, nil)`,
        ),
      });
      expect(rows, expression).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.source.kind).toBe(kind);
    }
  });

  test("requires execution and preserves ExecuteTemplate argument roles", async () => {
    expect(
      await repositoryInventory({
        "handler.go": handler(
          `  parsed, _ := template.New("page").Parse(r.FormValue("source"))
  _ = parsed`,
        ),
      }),
    ).toEqual([]);

    const rows = await repositoryInventory({
      "handler.go": handler(
        `  parsed, _ := template.New("page").Parse(r.FormValue("source"))
  parsed.ExecuteTemplate(w, "page", struct{ Secret string }{"server secret"})`,
      ),
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.frameworkModel?.sink.kind).toBe(
      "go-text-template-named-execution",
    );
    expect(
      rows[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("go-template-execution-data");
  });

  test("rejects fixed template source even when request data is rendered", async () => {
    for (const source of [
      `  parsed, _ := template.New("page").Parse("Hello {{.}}")
  parsed.Execute(w, r.FormValue("name"))`,
      `  source := "Hello {{.}}"
  parsed, _ := template.New("page").Parse(source)
  parsed.Execute(w, r.FormValue("name"))`,
    ]) {
      expect(
        await repositoryInventory({ "handler.go": handler(source) }),
        source,
      ).toEqual([]);
    }
  });

  test("does not mistake escaping for a template-grammar sanitizer", async () => {
    for (const escapeCall of [
      "html.EscapeString(source)",
      "url.QueryEscape(source)",
      "url.PathEscape(source)",
    ]) {
      const rows = await repositoryInventory({
        "handler.go": `package preview
import (
  "html"
  "net/http"
  "net/url"
  "text/template"
)
func Handler(w http.ResponseWriter, r *http.Request) {
  source := r.FormValue("source")
  escaped := ${escapeCall}
  parsed, _ := template.New("page").Parse(escaped)
  parsed.Execute(w, nil)
}`,
      });
      expect(rows, escapeCall).toHaveLength(1);
    }
  });

  test("accepts fixed server-owned template selection", async () => {
    expect(
      await repositoryInventory({
        "handler.go": handler(
          `  sources := map[string]string{"welcome": "Hello {{.}}", "bye": "Bye {{.}}"}
  source := sources[r.FormValue("view")]
  parsed, _ := template.New("page").Parse(source)
  parsed.Execute(w, r.FormValue("name"))`,
        ),
      }),
    ).toEqual([]);
  });

  test("requires exact text/template identity and supports a package alias", async () => {
    expect(
      await repositoryInventory({
        "handler.go": handler(
          `  parsed, _ := tpl.New("page").Parse(r.FormValue("source"))
  parsed.Execute(w, nil)`,
          { templateAlias: "tpl" },
        ),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "handler.go": handler(
          `  parsed, _ := template.New("page").Parse(r.FormValue("source"))
  parsed.Execute(w, nil)`,
          { templateImport: "html/template" },
        ),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "handler.go": handler(
          `  parsed, _ := template.New("page").Parse(r.FormValue("source"))
  parsed.Execute(w, nil)`,
          { templateImport: "example.com/template" },
        ),
      }),
    ).toEqual([]);
  });

  test("rejects duplicate imports, local shadows, comments, and strings", async () => {
    expect(
      await repositoryInventory({
        "handler.go": `package preview
import (
  "net/http"
  first "text/template"
  second "text/template"
)
func Handler(w http.ResponseWriter, r *http.Request) {
  parsed, _ := first.New("page").Parse(r.FormValue("source"))
  parsed.Execute(w, nil)
}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "handler.go": handler(
          `  template := struct{}{}
  _ = template
  // template.New("page").Parse(r.FormValue("source")).Execute(w, nil)
  example := "template.New().Parse(r.FormValue()).Execute(w, nil)"
  _ = example`,
        ),
      }),
    ).toEqual([]);
  });

  test("clears source and parsed-template reassignment", async () => {
    expect(
      await repositoryInventory({
        "handler.go": handler(
          `  source := r.FormValue("source")
  source = "Hello {{.}}"
  parsed, _ := template.New("page").Parse(source)
  parsed.Execute(w, nil)`,
        ),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "handler.go": handler(
          `  parsed, _ := template.New("page").Parse(r.FormValue("source"))
  parsed = template.Must(template.New("page").Parse("Hello {{.}}"))
  parsed.Execute(w, nil)`,
        ),
      }),
    ).toEqual([]);
  });

  test("tracks separate builders, template aliases, direct chains, and FuncMap evidence", async () => {
    const cases = [
      `  builder := template.New("page")
  builder.Funcs(template.FuncMap{"secret": func() string { return "secret" }})
  parsed, _ := builder.Parse(r.FormValue("source"))
  parsed.Execute(w, nil)`,
      `  builder := template.New("page")
  builder = builder.Funcs(template.FuncMap{"secret": func() string { return "secret" }})
  parsed, _ := builder.Parse(r.FormValue("source"))
  parsed.Execute(w, nil)`,
      `  parsed, _ := template.New("page").Parse(r.FormValue("source"))
  alias := parsed
  alias.Execute(w, struct{ Secret string }{"secret"})`,
      `  template.Must(template.New("page").Funcs(template.FuncMap{"secret": func() string { return "secret" }}).Parse(r.FormValue("source"))).Execute(w, nil)`,
    ];
    for (const source of cases) {
      const rows = await repositoryInventory({ "handler.go": handler(source) });
      expect(rows, source).toHaveLength(1);
    }
    const withFunctions = await repositoryInventory({
      "handler.go": handler(cases[0]!),
    });
    expect(
      withFunctions[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("go-template-function-map");
  });

  test("follows only one unique same-package string wrapper", async () => {
    expect(
      await repositoryInventory({
        "handler.go": `package preview
import "net/http"
func Handler(w http.ResponseWriter, r *http.Request) { Render(w, r.FormValue("source")) }`,
        "render.go": `package preview
import (
  "io"
  "text/template"
)
func Render(w io.Writer, source string) {
  parsed, _ := template.New("page").Parse(source)
  parsed.Execute(w, nil)
}`,
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "handler.go": `package preview
import "net/http"
func Handler(w http.ResponseWriter, r *http.Request) { Render(w, "fixed") }`,
        "render.go": `package preview
import (
  "io"
  "text/template"
)
func Render(w io.Writer, source string) {
  parsed, _ := template.New("page").Parse(source)
  parsed.Execute(w, nil)
}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "handler.go": `package preview
import "net/http"
func Handler(w http.ResponseWriter, r *http.Request) { Render(w, r.FormValue("source")) }`,
        "render.go": `package preview
import (
  "io"
  "text/template"
)
func Render(w io.Writer, source string) {
  parsed, _ := template.New("page").Parse(source)
  parsed.Execute(w, nil)
}
func Render(w io.Writer, source string) { _ = source }`,
      }),
    ).toEqual([]);
  });

  test("gives reviewers Go-specific parse, execution, and capability guidance", () => {
    const prompt = scanQualityGatePrompt("", "");
    const lowerPrompt = prompt.toLowerCase();
    expect(prompt).toContain("go-http-template-injection");
    expect(prompt).toContain("text/template");
    expect(prompt).toContain("FuncMap");
    expect(lowerPrompt).toContain("parsing without execution is inert");
    expect(prompt).toContain("fixed server-owned template");
    expect(prompt).toContain("HTML escaping");
  });
});
