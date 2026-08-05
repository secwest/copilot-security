import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface GoPathRecord {
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
  "go-cross-file-path-traversal",
  "go-cross-file-safe-rooted-file",
  "go-relative-path-traversal",
  "go-relative-safe-containment",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): GoPathRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as GoPathRecord)
    .filter(
      (record) => record.frameworkModel?.id === "go-http-filesystem-path",
    );
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<GoPathRecord[]> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-go-path-"));
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
  options: { osAlias?: string; osImport?: string; httpAlias?: string } = {},
): string {
  const osAlias = options.osAlias ?? "os";
  const osImport = options.osImport ?? "os";
  const httpAlias = options.httpAlias ?? "http";
  const osDeclaration =
    osAlias === "os" ? `"${osImport}"` : `${osAlias} "${osImport}"`;
  const httpDeclaration =
    httpAlias === "http" ? '"net/http"' : `${httpAlias} "net/http"`;
  return `package documents

import (
  ${httpDeclaration}
  ${osDeclaration}
)

func Handler(w ${httpAlias}.ResponseWriter, r *${httpAlias}.Request) {
${body}
}
`;
}

describe("Go HTTP filesystem-path framework-model benchmark", () => {
  test("keeps the exploit and rooted control under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "go-http-filesystem-path-manifest.json"),
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
      cwe: ["CWE-22"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(manifest.cases[2]?.expected[0]).toMatchObject({
      cwe: ["CWE-22"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[3]?.expected).toEqual([]);
  });

  test("preserves the exact cross-file request-to-read path", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "document.go",
      line: 10,
      categories: [
        "framework-dataflow:go-http-filesystem-path",
        "modeled-source:go-http-query-parameter",
        "modeled-sink:go-filesystem-read-path",
      ],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "go",
        scope: "cross-file-wrapper",
        source: {
          kind: "go-http-query-parameter",
          path: "handler.go",
          line: 8,
        },
        sink: {
          kind: "go-filesystem-read-path",
          path: "document.go",
          line: 10,
          cweIds: ["CWE-22", "CWE-23", "CWE-36", "CWE-73"],
        },
      },
    });
    expect(
      vulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "go-function-argument",
      "go-string-parameter",
      "go-filesystem-path-construction",
      "go-filesystem-path-argument",
    ]);
    expect(safe).toEqual([]);
  });

  test("models typed query, form, path, and header request sources", async () => {
    const sources = [
      ['r.URL.Query().Get("name")', "go-http-query-parameter"],
      ['r.URL.Query()["name"][0]', "go-http-query-parameter"],
      ['r.FormValue("name")', "go-http-form-value"],
      ['r.PathValue("name")', "go-http-path-value"],
      ['r.Header.Get("X-Document")', "go-http-header"],
    ] as const;
    for (const [expression, kind] of sources) {
      const rows = await repositoryInventory({
        "document.go": handler(`  os.ReadFile(${expression})`),
      });
      expect(rows, expression).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.source.kind).toBe(kind);
    }
  });

  test("distinguishes read, open, write, delete, metadata, and walk effects", async () => {
    const cases = [
      ["os.ReadFile(name)", "go-filesystem-read-path"],
      ["os.OpenFile(name, 0, 0)", "go-filesystem-open-path"],
      ["os.WriteFile(name, nil, 0o600)", "go-filesystem-write-path"],
      ["os.RemoveAll(name)", "go-filesystem-delete-path"],
      ["os.Lstat(name)", "go-filesystem-metadata-path"],
    ] as const;
    for (const [call, kind] of cases) {
      const rows = await repositoryInventory({
        "document.go": handler(`  name := r.FormValue("name")
  ${call}`),
      });
      expect(rows, call).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.sink.kind).toBe(kind);
    }

    const walked = await repositoryInventory({
      "walk.go": `package documents
import (
  "net/http"
  "path/filepath"
)
func Handler(w http.ResponseWriter, r *http.Request) {
  root := r.PathValue("root")
  filepath.WalkDir(root, func(path string, entry interface{}, err error) error { return err })
}`,
    });
    expect(walked).toHaveLength(1);
    expect(walked[0]?.frameworkModel?.sink.kind).toBe(
      "go-filesystem-walk-root",
    );
  });

  test("preserves exact source and destination roles for move and link calls", async () => {
    for (const method of ["Rename", "Link", "Symlink"]) {
      const rows = await repositoryInventory({
        "document.go": handler(`  name := r.FormValue("name")
  os.${method}(name, name)`),
      });
      expect(rows, method).toHaveLength(2);
      expect(
        rows.map((row) => row.frameworkModel?.sink.kind),
        method,
      ).toEqual(
        method === "Rename"
          ? [
              "go-filesystem-move-source-path",
              "go-filesystem-move-destination-path",
            ]
          : [
              "go-filesystem-link-source-path",
              "go-filesystem-link-destination-path",
            ],
      );
      expect(
        rows.map((row) => row.frameworkModel?.propagators.at(-1)?.symbol),
      ).toEqual(
        method === "Rename"
          ? [`os.${method}[0] move source`, `os.${method}[1] move destination`]
          : [`os.${method}[0] link source`, `os.${method}[1] link destination`],
      );
    }
  });

  test("models legacy ioutil and exact net/http file-response arguments", async () => {
    const rows = await repositoryInventory({
      "legacy.go": `package documents
import (
  "io/ioutil"
  "net/http"
)
func Handler(w http.ResponseWriter, r *http.Request) {
  name := r.FormValue("name")
  ioutil.ReadFile(name)
  http.ServeFile(w, r, name)
  http.ServeFileFS(w, r, nil, name)
}`,
    });
    expect(rows.map((row) => row.frameworkModel?.sink.kind)).toEqual([
      "go-filesystem-read-path",
      "go-http-file-response-path",
      "go-http-file-response-path",
    ]);
    expect(
      rows.map((row) => row.frameworkModel?.propagators.at(-1)?.symbol),
    ).toEqual([
      "ioutil.ReadFile[0] read path",
      "http.ServeFile[2] response file path",
      "http.ServeFileFS[3] response filesystem path",
    ]);
  });

  test("retains normalization and resolution as tainted candidate evidence", async () => {
    const rows = await repositoryInventory({
      "document.go": `package documents
import (
  "io/fs"
  "net/http"
  "os"
  "path/filepath"
  "regexp"
  "strings"
)
func Handler(w http.ResponseWriter, r *http.Request) {
  name := r.FormValue("name")
  if filepath.IsAbs(name) { return }
  if !filepath.IsLocal(name) { return }
  if !fs.ValidPath(name) { return }
  if strings.Contains(name, "..") { return }
  if !regexp.MustCompile("^[A-Za-z0-9._/-]+$").MatchString(name) { return }
  clean := filepath.Clean(name)
  absolute, _ := filepath.Abs(clean)
  relative, _ := filepath.Rel("public", absolute)
  resolved, _ := filepath.EvalSymlinks(relative)
  os.ReadFile(resolved)
}`,
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("go-filesystem-path-construction");
    expect(
      rows[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual([
      "absolute-path-rejection",
      "path-locality-check",
      "slash-path-validation",
      "path-string-validation",
      "path-component-allowlist",
      "path-normalization-only",
      "path-normalization-only",
      "symlink-resolution",
    ]);
  });

  test("keeps filepath.Rel tainted and requires an exact parent boundary rejection", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[2]));
    const controlled = models(await fixtureInventory(caseIds[3]));
    expect(vulnerable).toHaveLength(1);
    expect(
      vulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("go-filesystem-path-construction");
    expect(
      vulnerable[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).not.toContain("relative-parent-boundary-rejection");
    expect(controlled).toHaveLength(1);
    expect(
      controlled[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toContain("relative-parent-boundary-rejection");
  });

  test("rejects partial, unrelated, and post-sink relative path checks", async () => {
    for (const body of [
      `  name := r.FormValue("name")
  candidate := filepath.Join("public", name)
  relative, _ := filepath.Rel("public", candidate)
  if relative == ".." { return }
  // strings.HasPrefix(relative, ".."+string(os.PathSeparator))
  os.ReadFile(filepath.Join("public", relative))`,
      `  name := r.FormValue("name")
  candidate := filepath.Join("public", name)
  relative, _ := filepath.Rel("public", candidate)
  if strings.HasPrefix(relative, ".."+string(os.PathSeparator)) { return }
  os.ReadFile(filepath.Join("public", relative))`,
      `  name := r.FormValue("name")
  candidate := filepath.Join("public", name)
  relative, _ := filepath.Rel("public", candidate)
  other := "report.txt"
  if other == ".." || strings.HasPrefix(other, ".."+string(os.PathSeparator)) { return }
  os.ReadFile(filepath.Join("public", relative))`,
      `  name := r.FormValue("name")
  candidate := filepath.Join("public", name)
  relative, _ := filepath.Rel("public", candidate)
  os.ReadFile(filepath.Join("public", relative))
  if relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) { return }`,
    ]) {
      const rows = await repositoryInventory({
        "document.go": `package documents
import (
  "net/http"
  "os"
  "path/filepath"
  "strings"
)
func Handler(w http.ResponseWriter, r *http.Request) {
${body}
}`,
      });
      expect(rows).toHaveLength(1);
      expect(
        rows[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
      ).not.toContain("relative-parent-boundary-rejection");
    }
  });

  test("requires exact standard-library identities and accepts their aliases", async () => {
    const aliased = await repositoryInventory({
      "document.go": `package documents
import (
  web "net/http"
  disk "os"
  paths "path/filepath"
  text "strings"
)
func Handler(w web.ResponseWriter, r *web.Request) {
  name := r.FormValue("name")
  candidate := paths.Join("public", name)
  relative, _ := paths.Rel("public", candidate)
  if relative == ".." || text.HasPrefix(relative, ".."+string(disk.PathSeparator)) { return }
  disk.ReadFile(paths.Join("public", relative))
}`,
    });
    expect(aliased).toHaveLength(1);
    expect(
      aliased[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toContain("relative-parent-boundary-rejection");

    const lookalike = await repositoryInventory({
      "document.go": `package documents
import (
  "net/http"
  "os"
  filepath "example.com/path/filepath"
  strings "example.com/strings"
)
func Handler(w http.ResponseWriter, r *http.Request) {
  name := r.FormValue("name")
  candidate := filepath.Join("public", name)
  relative, _ := filepath.Rel("public", candidate)
  if relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) { return }
  os.ReadFile(filepath.Join("public", relative))
}`,
    });
    expect(lookalike).toHaveLength(1);
    expect(
      lookalike[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).not.toContain("relative-parent-boundary-rejection");
  });

  test("accepts fixed server-owned selection and root-scoped filesystem APIs", async () => {
    expect(
      await repositoryInventory({
        "document.go": handler(`  key := r.FormValue("name")
  files := map[string]string{"report": "report.txt", "guide": "guide.txt"}
  name := files[key]
  os.ReadFile(name)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "document.go":
          handler(`  files := map[string]string{"report": "report.txt", "guide": "guide.txt"}
  os.ReadFile(files[r.FormValue("name")])`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "document.go": handler(`  name := r.FormValue("name")
  os.OpenInRoot("public", name)`),
      }),
    ).toEqual([]);

    for (const call of [
      'os.OpenRoot(r.FormValue("root"))',
      'os.OpenInRoot(r.FormValue("root"), "report.txt")',
    ]) {
      const rows = await repositoryInventory({
        "document.go": handler(`  ${call}`),
      });
      expect(rows, call).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.sink.kind).toBe(
        "go-filesystem-root-selection",
      );
      expect(rows[0]?.frameworkModel?.propagators.at(-1)?.symbol).toContain(
        "[0] filesystem root",
      );
      expect(rows[0]?.frameworkModel?.candidateControls).toEqual([]);
    }
  });

  test("supports exact aliases and rejects lookalikes or ambiguous imports", async () => {
    expect(
      await repositoryInventory({
        "document.go": handler(`  disk.ReadFile(r.FormValue("name"))`, {
          osAlias: "disk",
        }),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "document.go": handler(`  os.ReadFile(r.FormValue("name"))`, {
          osImport: "example.com/os",
        }),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "document.go": `package documents
import (
  "net/http"
  first "os"
  second "os"
)
func Handler(w http.ResponseWriter, r *http.Request) {
  first.ReadFile(r.FormValue("name"))
  second.ReadFile(r.FormValue("name"))
}`,
      }),
    ).toEqual([]);
  });

  test("clears reassignment and follows only one unique same-package wrapper", async () => {
    expect(
      await repositoryInventory({
        "document.go": handler(`  name := r.FormValue("name")
  name = "report.txt"
  os.ReadFile(name)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "handler.go": `package documents
import "net/http"
func Handler(w http.ResponseWriter, r *http.Request) { ReadDocument(r.FormValue("name")) }`,
        "document.go": `package documents
import "os"
func ReadDocument(name string) { os.ReadFile(name) }`,
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "handler.go": `package documents
import "net/http"
func Handler(w http.ResponseWriter, r *http.Request) { ReadDocument(r.FormValue("name")) }`,
        "document.go": `package documents
import "os"
func ReadDocument(name string) { os.ReadFile(name) }`,
        "duplicate.go": `package documents
import "os"
func ReadDocument(name string) { os.ReadFile(name) }`,
      }),
    ).toEqual([]);
  });

  test("rejects comments and string examples", async () => {
    expect(
      await repositoryInventory({
        "document.go": handler(`  // os.ReadFile(r.FormValue("name"))
  example := "os.ReadFile(r.FormValue(\\\"name\\\"))"
  _ = example`),
      }),
    ).toEqual([]);
  });

  test("teaches exact path roles, containment, runtime, and impact boundaries", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "", "");
    expect(prompt).toContain("For go-http-filesystem-path rows");
    expect(prompt).toContain("filepath.Join");
    expect(prompt).toContain("relative-parent-boundary-rejection");
    expect(prompt).toContain("string(os.PathSeparator)");
    expect(prompt).toContain("occur before and dominate the exact sink");
    expect(prompt).toContain("normalization");
    expect(prompt).toContain("filepath.IsLocal");
    expect(prompt).toContain("symbolic links");
    expect(prompt).toContain("os.OpenInRoot");
    expect(prompt).toContain("filesystem-root selection");
    expect(prompt).toContain("go1.25.12");
    expect(prompt).toContain("go1.26.5");
    expect(prompt).toContain("GO-2026-4970");
    expect(prompt).toContain("concrete unauthorized filesystem effect");
  });
});
