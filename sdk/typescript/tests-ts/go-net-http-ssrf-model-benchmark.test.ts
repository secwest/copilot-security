import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface GoSsrfRecord {
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
const caseIds = ["go-cross-file-ssrf", "go-cross-file-safe-fetch"] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): GoSsrfRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as GoSsrfRecord)
    .filter((record) => record.frameworkModel?.id === "go-net-http-ssrf");
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<GoSsrfRecord[]> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-go-net-http-ssrf-"),
  );
  temporaryPaths.push(repository);
  for (const [path, source] of Object.entries(files)) {
    const absolute = join(repository, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, source);
  }
  return models(await buildResidualRiskInventory(repository));
}

function handler(
  body: string,
  options: { alias?: string; importPath?: string } = {},
): string {
  const alias = options.alias ?? "http";
  const importPath = options.importPath ?? "net/http";
  const importDeclaration =
    alias === "http" ? `"${importPath}"` : `${alias} "${importPath}"`;
  return `package preview

import ${importDeclaration}

func Preview(w ${alias}.ResponseWriter, r *${alias}.Request) {
${body}
}
`;
}

describe("Go net/http SSRF framework-model benchmark", () => {
  test("keeps the exploit and fixed-selection control under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "go-net-http-ssrf-manifest.json"),
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
      cwe: ["CWE-918"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("preserves the exact handler-to-request-to-dispatch path", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "fetch.go",
      line: 15,
      categories: [
        "framework-dataflow:go-net-http-ssrf",
        "modeled-source:go-http-query-parameter",
        "modeled-sink:go-http-client-do",
      ],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "go",
        scope: "cross-file-wrapper",
        source: {
          kind: "go-http-query-parameter",
          path: "handler.go",
          line: 9,
        },
        sink: {
          kind: "go-http-client-do",
          path: "fetch.go",
          line: 15,
          cweIds: ["CWE-918"],
        },
        propagators: [
          {
            kind: "go-function-argument",
            path: "handler.go",
            line: 10,
            symbol: "Fetch[1]",
          },
          {
            kind: "go-string-parameter",
            path: "fetch.go",
            line: 9,
            symbol: "target",
          },
          {
            kind: "go-http-request-construction",
            path: "fetch.go",
            line: 10,
            symbol: "request",
          },
        ],
        candidateControls: [],
      },
    });
    expect(safe).toEqual([]);
  });

  test("recognizes standard and aliased package-level dispatch", async () => {
    for (const method of ["Get", "Head", "Post", "PostForm"]) {
      const arguments_ =
        method === "Post"
          ? `target, "text/plain", nil`
          : method === "PostForm"
            ? "target, nil"
            : "target";
      expect(
        await repositoryInventory({
          "preview.go": handler(
            `\ttarget := r.FormValue("url")
\t_, _ = http.${method}(${arguments_})`,
          ),
        }),
      ).toHaveLength(1);
    }
    const aliased = await repositoryInventory({
      "preview.go": handler(
        `\ttarget := r.FormValue("url")
\t_, _ = web.Get(target)`,
        { alias: "web" },
      ),
    });
    expect(aliased).toHaveLength(1);
    expect(aliased[0]?.frameworkModel?.sink.kind).toBe("go-http-client-url");
  });

  test("covers exact scalar request sources without accepting unrelated fields", async () => {
    for (const [expression, kind] of [
      ['r.URL.Query().Get("url")', "go-http-query-parameter"],
      ['r.FormValue("url")', "go-http-form-value"],
      ['r.PostFormValue("url")', "go-http-form-value"],
      ['r.PathValue("url")', "go-http-path-value"],
      ['r.Header.Get("X-Preview-URL")', "go-http-header"],
    ]) {
      const rows = await repositoryInventory({
        "preview.go": handler(`\t_, _ = http.Get(${expression})`),
      });
      expect(rows).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.source.kind).toBe(kind);
    }
    expect(
      await repositoryInventory({
        "preview.go": handler(`\t_, _ = http.Get(r.URL.Path)`),
      }),
    ).toEqual([]);
  });

  test("requires a typed or directly constructed Client receiver", async () => {
    const typed = `package preview

import "net/http"

func Preview(w http.ResponseWriter, r *http.Request, client *http.Client) {
	target := r.FormValue("url")
	_, _ = client.Get(target)
}`;
    expect(await repositoryInventory({ "preview.go": typed })).toHaveLength(1);
    expect(
      await repositoryInventory({
        "preview.go": handler(`\ttarget := r.FormValue("url")
\tclient := &http.Client{}
\t_, _ = client.Get(target)`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "preview.go": handler(`\ttarget := r.FormValue("url")
\t_, _ = http.DefaultClient.Get(target)`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "preview.go": handler(`\ttarget := r.FormValue("url")
\tclient := customClient()
\t_, _ = client.Get(target)`),
      }),
    ).toEqual([]);
  });

  test("requires request construction to close through Client.Do", async () => {
    const closed = await repositoryInventory({
      "preview.go": handler(`\ttarget := r.FormValue("url")
\trequest, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
\tclient := &http.Client{}
\t_, _ = client.Do(request)`),
    });
    expect(closed).toHaveLength(1);
    expect(closed[0]?.frameworkModel?.sink.kind).toBe("go-http-client-do");
    expect(
      closed[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("go-http-request-construction");
    expect(
      await repositoryInventory({
        "preview.go": handler(`\ttarget := r.FormValue("url")
\trequest, _ := http.NewRequest(http.MethodGet, target, nil)
\t_ = request`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "preview.go": handler(`\ttarget := r.FormValue("url")
\trequest, _ := http.NewRequest(http.MethodGet, "https://example.test", nil)
\tclient := &http.Client{}
\t_, _ = client.Do(request)
\t_ = target`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "preview.go": handler(`\ttarget := r.FormValue("url")
\trequest, _ := http.NewRequest(http.MethodGet, target, nil)
\trequest, _ = http.NewRequest(http.MethodGet, "https://example.test", nil)
\tclient := &http.Client{}
\t_, _ = client.Do(request)`),
      }),
    ).toEqual([]);
  });

  test("tracks only complete URL positions and not request bodies", async () => {
    expect(
      await repositoryInventory({
        "preview.go": handler(`\ttarget := r.FormValue("url")
\t_, _ = http.Post("https://example.test/upload", "text/plain", strings.NewReader(target))`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "preview.go": `package preview

import "net/http"

var destinations = map[string]string{"status": "https://example.test/status"}

func Preview(w http.ResponseWriter, r *http.Request) {
	destinations["dynamic"] = r.FormValue("url")
	key := r.FormValue("destination")
	target, ok := destinations[key]
	if !ok { return }
	_, _ = http.Get(target)
}`,
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "preview.go": handler(`\ttarget := r.FormValue("url")
\trequest, _ := http.NewRequest(http.MethodPost, "https://example.test/upload", strings.NewReader(target))
\tclient := &http.Client{}
\t_, _ = client.Do(request)`),
      }),
    ).toEqual([]);
  });

  test("clears reassigned values and fixed server-owned map selection", async () => {
    expect(
      await repositoryInventory({
        "preview.go": handler(`\ttarget := r.FormValue("url")
\ttarget = "https://example.test/status"
\t_, _ = http.Get(target)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "preview.go": `package preview

import "net/http"

var destinations = map[string]string{"status": "https://example.test/status"}

func Preview(w http.ResponseWriter, r *http.Request) {
	key := r.FormValue("destination")
	target, ok := destinations[key]
	if !ok { return }
	_, _ = http.Get(target)
}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "preview.go": handler(`\ttarget := r.FormValue("url")
\talias := target
\t_, _ = http.Get(alias)`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "preview.go": handler(`\ttarget := r.FormValue("url")
\tother := ""
\tother, target = target, "https://example.test/status"
\t_, _ = http.Get(target)`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "preview.go": handler(`\ttarget := r.FormValue("url")
\tother := ""
\tother, target = target, "https://example.test/status"
\t_, _ = http.Get(other)`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "preview.go": `${handler(`\ttarget := r.FormValue("url")
\trequest, _ := http.NewRequest(http.MethodGet, target, nil)
\tfixed, _ := http.NewRequest(http.MethodGet, "https://example.test/status", nil)
\tother := request
\tother, request = request, fixed
\tclient := &http.Client{}
\t_, _ = client.Do(request)`)}
func customClient() (*http.Client, error) { return http.DefaultClient, nil }`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "preview.go": `${handler(`\ttarget := r.FormValue("url")
\tclient := &http.Client{}
\tvar err error
\tclient, err = customClient()
\t_, _ = client.Get(target)
\t_ = err`)}
func customClient() (*http.Client, error) { return http.DefaultClient, nil }`,
      }),
    ).toEqual([]);
  });

  test("follows one exact same-package function boundary", async () => {
    const caller = handler(`\ttarget := r.FormValue("url")
\t_, _ = Fetch(target)`);
    const wrapper = `package preview

import "net/http"

func Fetch(target string) (*http.Response, error) {
	return http.Get(target)
}`;
    const crossFile = await repositoryInventory({
      "handler.go": caller,
      "fetch.go": wrapper,
    });
    expect(crossFile).toHaveLength(1);
    expect(crossFile[0]?.frameworkModel?.scope).toBe("cross-file-wrapper");
    expect(
      crossFile[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual(["go-function-argument", "go-string-parameter"]);

    const sameFile = await repositoryInventory({
      "preview.go": `${caller}\n${wrapper.replace(
        'package preview\n\nimport "net/http"\n\n',
        "",
      )}`,
    });
    expect(sameFile).toHaveLength(1);
    expect(sameFile[0]?.frameworkModel?.scope).toBe("same-file");
  });

  test("rejects ambiguous or cross-package wrapper identity", async () => {
    const caller = handler(`\ttarget := r.FormValue("url")
\t_, _ = Fetch(target)`);
    const wrapper = `package preview
import "net/http"
func Fetch(target string) (*http.Response, error) { return http.Get(target) }`;
    expect(
      await repositoryInventory({
        "handler.go": caller,
        "fetch.go": wrapper,
        "duplicate.go": wrapper,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "handler.go": caller,
        "fetch.go": wrapper,
        "duplicate.go": "package preview\nfunc Fetch(_ int) {}",
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "api/handler.go": caller,
        "service/fetch.go": wrapper,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "handler.go": caller,
        "fetch.go": wrapper.replace("package preview", "package service"),
      }),
    ).toEqual([]);
  });

  test("rejects lookalike imports, dot imports, comments, and strings", async () => {
    expect(
      await repositoryInventory({
        "preview.go": handler(
          `\ttarget := r.FormValue("url")
\t_, _ = http.Get(target)`,
          { importPath: "example.com/net/http" },
        ),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "preview.go": `package preview
import . "net/http"
func Preview(w ResponseWriter, r *Request) { _, _ = Get(r.FormValue("url")) }`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "preview.go": `package preview
import "net/http"
func Preview(w http.ResponseWriter, r *http.Request) {
	// _, _ = http.Get(r.FormValue("url"))
	example := "http.Get(r.FormValue(\\\"url\\\"))"
	_ = example
}`,
      }),
    ).toEqual([]);
  });

  test("retains redirect, host, address, dialer, and scheme control leads", async () => {
    const rows = await repositoryInventory({
      "preview.go": `package preview

import "net/http"

func Preview(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("url")
	parsed, _ := url.Parse(target)
	if !allowedHosts[parsed.Hostname()] { return }
	if parsed.Scheme != "https" { return }
	_, _ = net.LookupIP(parsed.Hostname())
	transport := &http.Transport{DialContext: dialApprovedAddress}
	_ = transport
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	_, _ = client.Get(target)
}`,
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual([
      "parsed-host-exact-allowlist",
      "allowed-url-scheme",
      "network-address-validation",
      "custom-network-dialer",
      "redirects-disabled",
    ]);
  });

  test("teaches exact Go construction, dispatch, and network validation boundaries", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "", "");
    expect(prompt).toContain("For go-net-http-ssrf rows");
    expect(prompt).toContain("exact standard-library net/http import alias");
    expect(prompt).toContain("only construct data and require a later Do");
    expect(prompt).toContain("URL data used only as a Post body");
    expect(prompt).toContain("fixed map from an attacker selector");
    expect(prompt).toContain("http.ErrUseLastResponse");
    expect(prompt).toContain("actual socket address");
  });
});
