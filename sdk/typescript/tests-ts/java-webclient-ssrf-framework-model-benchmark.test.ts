import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface FrameworkRecord {
  path: string;
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
    findingsPaths: string[];
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
  "java-webclient-multi-hop-ssrf",
  "java-webclient-multi-hop-safe-fetch",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function parseRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord);
}

function webClientRecords(inventory: string): FrameworkRecord[] {
  return parseRecords(inventory).filter(
    (record) => record.frameworkModel?.id === "spring-http-ssrf",
  );
}

async function writeRepositoryFile(
  repository: string,
  relativePath: string,
  contents: string,
): Promise<void> {
  const path = join(repository, relativePath);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, contents);
}

async function temporaryRepository(): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-java-webclient-"),
  );
  temporaryPaths.push(repository);
  return repository;
}

describe("Spring WebClient SSRF framework-model effectiveness benchmark", () => {
  test("keeps the reactive exploit and fixed-destination control under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "java-webclient-ssrf-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;

    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.thresholds["maxFalsePositivesPerRun"]).toBe(0);
    expect(manifest.cases.map(({ id }) => id)).toEqual([...caseIds]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-918"],
      acceptableSeverities: ["critical", "high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(
      manifest.cases.every((entry) => entry.findingsPaths.length === 1),
    ).toBeTrue();

    const vulnerableWitness = await readFile(
      join(
        benchmarkRoot,
        "witnesses",
        "java-webclient-ssrf",
        "src",
        "main",
        "java",
        "example",
        "VulnerableWebClientWitness.java",
      ),
      "utf8",
    );
    expect(vulnerableWitness).toContain("HttpClient.Redirect.ALWAYS");
    expect(vulnerableWitness).toContain('"private-metadata"');
    expect(vulnerableWitness).toContain(".uri(attackerControlled)");
    const safeWitness = await readFile(
      join(
        benchmarkRoot,
        "witnesses",
        "java-webclient-safe-fetch",
        "src",
        "main",
        "java",
        "example",
        "SafeWebClientWitness.java",
      ),
      "utf8",
    );
    expect(safeWitness).toContain("HttpClient.Redirect.NEVER");
    expect(safeWitness).toContain('Map.of("status", fixedStatus)');
    expect(safeWitness).toContain(
      "fetch(client, allowedDestinations, attackerUri.toString())",
    );
  });

  test("preserves two typed service boundaries into WebClient uri", async () => {
    const vulnerable = webClientRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[0]),
      ),
    );
    const safe = webClientRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[1]),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.path).toBe(
      "src/main/java/example/PreviewTransport.java",
    );
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      schemaVersion: "1.2",
      id: "spring-http-ssrf",
      language: "java-kotlin",
      scope: "cross-file-multi-hop-wrapper",
      source: {
        kind: "spring-bound-parameter",
        path: "src/main/java/example/PreviewController.java",
        line: 19,
      },
      sink: {
        kind: "outbound-http-url",
        path: "src/main/java/example/PreviewTransport.java",
        line: 16,
        cweIds: ["CWE-918"],
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toHaveLength(6);
    expect(
      vulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "java-type-binding",
      "wrapper-call-argument",
      "wrapper-parameter",
      "java-type-binding",
      "wrapper-call-argument",
      "wrapper-parameter",
    ]);

    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "fixed-destination-allowlist" }),
        expect.objectContaining({ kind: "redirects-disabled" }),
      ]),
    );
  });

  test("recognizes imported, fully qualified, constructed, and request-spec clients", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "src/InjectedController.java",
      `
import org.springframework.web.reactive.function.client.WebClient;
public final class InjectedController {
  private final WebClient client;
  public Object get(@RequestParam String target) {
    return client.get().uri(target).retrieve();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/ConstructedController.java",
      `
import org.springframework.web.reactive.function.client.WebClient;
public final class ConstructedController {
  public Object get(@RequestParam String target) {
    return WebClient.builder().build().post().uri(target).retrieve();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/FullyQualifiedController.java",
      `
public final class FullyQualifiedController {
  public Object get(@RequestParam String target) {
    return org.springframework.web.reactive.function.client.WebClient
      .create().get().uri(target).retrieve();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/AliasController.java",
      `
import org.springframework.web.reactive.function.client.WebClient;
public final class AliasController {
  private final WebClient client;
  public Object get(@RequestParam String target) {
    WebClient.RequestHeadersUriSpec<?> request = client.get();
    return request.uri(target).retrieve();
  }
}
`,
    );

    const records = webClientRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(4);
    expect(records.map(({ path }) => path).sort()).toEqual([
      "src/AliasController.java",
      "src/ConstructedController.java",
      "src/FullyQualifiedController.java",
      "src/InjectedController.java",
    ]);
  });

  test("tracks only the URI template argument and rejects unrelated or shadowed uri calls", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "src/TemplateController.java",
      `
import org.springframework.web.reactive.function.client.WebClient;
public final class TemplateController {
  private final WebClient client;
  public Object get(@RequestParam String target) {
    return client.get().uri("/profiles/{id}", target).retrieve();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/UnrelatedController.java",
      `
public final class UnrelatedController {
  private final Router client;
  public Object get(@RequestParam String target) {
    return client.get().uri(target);
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/ShadowController.java",
      `
final class WebClient {
  static WebClient create() { return new WebClient(); }
  WebClient get() { return this; }
  Object uri(String value) { return value; }
}
public final class ShadowController {
  public Object get(@RequestParam String target) {
    return WebClient.create().get().uri(target);
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/ReassignedController.java",
      `
import org.springframework.web.reactive.function.client.WebClient;
public final class ReassignedController {
  private final WebClient client;
  public Object get(@RequestParam String target) {
    target = "https://fixed.example.invalid/";
    return client.get().uri(target).retrieve();
  }
}
`,
    );

    expect(
      webClientRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("teaches the reviewer the reactive URI and connector boundary", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({ frameworkModel: { id: "spring-http-ssrf" } }),
    );
    expect(prompt).toContain("WebClient");
    expect(prompt).toContain("UriSpec.uri");
    expect(prompt).toContain("configured ClientHttpConnector");
    expect(prompt).toContain("URI template variable");
    expect(prompt).toContain(
      "locally shadowed HttpClient, RestTemplate, or WebClient types",
    );
  });
});
