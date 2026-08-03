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
const caseIds = ["java-multi-hop-ssrf", "java-multi-hop-safe-fetch"] as const;
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

function javaSsrfRecords(inventory: string): FrameworkRecord[] {
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
    join(tmpdir(), "copilot-security-java-ssrf-"),
  );
  temporaryPaths.push(repository);
  return repository;
}

describe("Spring Java SSRF framework-model effectiveness benchmark", () => {
  test("keeps the exploit and fixed-destination control under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "java-multi-hop-ssrf-manifest.json"),
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
        caseIds[0],
        "VulnerableSsrfWitness.java",
      ),
      "utf8",
    );
    expect(vulnerableWitness).toContain("HttpClient.Redirect.ALWAYS");
    expect(vulnerableWitness).toContain('"private-metadata"');
    const safeWitness = await readFile(
      join(benchmarkRoot, "witnesses", caseIds[1], "SafeFetchWitness.java"),
      "utf8",
    );
    expect(safeWitness).toContain("HttpClient.Redirect.NEVER");
    expect(safeWitness).toContain(
      "fetch(client, allowedDestinations, fixedStatus.toString())",
    );
    expect(safeWitness).toContain('Map.of("status", fixedStatus)');
  });

  test("preserves both typed Java service boundaries into JDK HttpClient", async () => {
    const vulnerable = javaSsrfRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[0]),
      ),
    );
    const safe = javaSsrfRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[1]),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.path).toBe(
      "src/main/java/example/PreviewTransport.java",
    );
    expect(vulnerable[0]?.frameworkModel).toEqual({
      schemaVersion: "1.2",
      id: "spring-http-ssrf",
      language: "java-kotlin",
      scope: "cross-file-multi-hop-wrapper",
      source: {
        kind: "spring-bound-parameter",
        path: "src/main/java/example/PreviewController.java",
        line: 18,
      },
      sink: {
        kind: "outbound-http-url",
        path: "src/main/java/example/PreviewTransport.java",
        line: 22,
        cweIds: ["CWE-918"],
      },
      propagators: [
        {
          kind: "java-type-binding",
          path: "src/main/java/example/PreviewController.java",
          line: 11,
          symbol: "previews:PreviewService",
        },
        {
          kind: "wrapper-call-argument",
          path: "src/main/java/example/PreviewController.java",
          line: 19,
          symbol: "previews.fetch[0]",
        },
        {
          kind: "wrapper-parameter",
          path: "src/main/java/example/PreviewService.java",
          line: 13,
          symbol: "target",
        },
        {
          kind: "java-type-binding",
          path: "src/main/java/example/PreviewService.java",
          line: 7,
          symbol: "transport:PreviewTransport",
        },
        {
          kind: "wrapper-call-argument",
          path: "src/main/java/example/PreviewService.java",
          line: 14,
          symbol: "transport.fetch[0]",
        },
        {
          kind: "wrapper-parameter",
          path: "src/main/java/example/PreviewTransport.java",
          line: 17,
          symbol: "target",
        },
      ],
      candidateControls: [],
    });

    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual(
      expect.arrayContaining([
        {
          kind: "redirects-disabled",
          path: "src/main/java/example/PreviewTransport.java",
          line: 22,
        },
        {
          kind: "fixed-destination-allowlist",
          path: "src/main/java/example/PreviewTransport.java",
          line: 25,
        },
      ]),
    );
  });

  test("recognizes typed same-file JDK and Spring clients without matching unrelated send methods", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "src/JdkPreviewController.java",
      `
import java.net.URI;
import java.net.http.*;
public final class JdkPreviewController {
  private final HttpClient client = HttpClient.newHttpClient();
  public String get(@RequestParam String target) throws Exception {
    if (!URI.create(target).getScheme().equals("https")) throw new SecurityException();
    HttpRequest request = HttpRequest.newBuilder(URI.create(target)).build();
    return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/SpringPreviewController.java",
      `
import org.springframework.web.client.RestTemplate;
public final class SpringPreviewController {
  private final RestTemplate rest = new RestTemplate();
  public String get(@RequestParam String target) {
    return rest.getForObject(target, String.class);
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/NoiseController.java",
      `
import java.net.http.HttpClient;
final class QueueClient { String send(String value) { return value; } }
public final class NoiseController {
  private final HttpClient unused = HttpClient.newHttpClient();
  private final QueueClient queue = new QueueClient();
  public String get(@RequestParam String target) { return queue.send(target); }
}
`,
    );

    const records = javaSsrfRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(2);
    expect(records.map(({ path }) => path).sort()).toEqual([
      "src/JdkPreviewController.java",
      "src/SpringPreviewController.java",
    ]);
    expect(
      records.every(
        (record) => record.frameworkModel?.sink.cweIds[0] === "CWE-918",
      ),
    ).toBeTrue();
    const jdk = records.find(
      (record) => record.path === "src/JdkPreviewController.java",
    );
    expect(jdk?.frameworkModel?.candidateControls).toContainEqual(
      expect.objectContaining({ kind: "allowed-uri-scheme" }),
    );
    expect(jdk?.frameworkModel?.candidateControls).not.toContainEqual(
      expect.objectContaining({ kind: "parsed-host-exact-allowlist" }),
    );
  });

  test("supports fully qualified, wildcard, and constructed outbound clients", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "src/ImportedChainController.java",
      `
import java.net.URI;
import java.net.http.*;
public final class ImportedChainController {
  public Object get(@RequestParam String target) throws Exception {
    return HttpClient.newHttpClient().send(
      HttpRequest.newBuilder(URI.create(target)).build(),
      HttpResponse.BodyHandlers.ofString());
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/FullyQualifiedController.java",
      `
public final class FullyQualifiedController {
  public Object get(@RequestParam String target) throws Exception {
    return java.net.http.HttpClient.newHttpClient().send(
      java.net.http.HttpRequest.newBuilder(java.net.URI.create(target)).build(),
      java.net.http.HttpResponse.BodyHandlers.ofString());
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/ConstructedTemplateController.java",
      `
import org.springframework.web.client.*;
public final class ConstructedTemplateController {
  public String get(@RequestParam String target) {
    return new RestTemplate().getForObject(target, String.class);
  }
}
`,
    );

    expect(
      javaSsrfRecords(await buildResidualRiskInventory(repository)),
    ).toHaveLength(3);
  });

  test("preserves an inline constructed HttpClient sink across a service boundary", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "src/PreviewTransport.java",
      `
import java.net.URI;
import java.net.http.*;
public final class PreviewTransport {
  public Object fetch(String target) throws Exception {
    return HttpClient.newHttpClient().send(
      HttpRequest.newBuilder(URI.create(target)).build(),
      HttpResponse.BodyHandlers.ofString());
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/PreviewController.java",
      `
public final class PreviewController {
  private final PreviewTransport transport;
  public Object get(@RequestParam String target) throws Exception {
    return transport.fetch(target);
  }
}
`,
    );

    const records = javaSsrfRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-wrapper",
      sink: { kind: "outbound-http-url", cweIds: ["CWE-918"] },
    });
  });

  test("does not truncate a reachable wrapper behind many unrelated summaries", async () => {
    const repository = await temporaryRepository();
    for (let index = 0; index < 65; index += 1) {
      await writeRepositoryFile(
        repository,
        `a-decoys/Decoy${index.toString().padStart(2, "0")}.java`,
        `
import java.net.URI;
import java.net.http.*;
public final class Decoy${index} {
  private final HttpClient client = HttpClient.newHttpClient();
  public Object fetch(String target) throws Exception {
    HttpRequest request = HttpRequest.newBuilder(URI.create(target)).build();
    return client.send(request, HttpResponse.BodyHandlers.discarding());
  }
}
`,
      );
    }
    await writeRepositoryFile(
      repository,
      "z/PreviewTransport.java",
      `
import java.net.URI;
import java.net.http.*;
public final class PreviewTransport {
  private final HttpClient client = HttpClient.newHttpClient();
  public Object fetch(String target) throws Exception {
    HttpRequest request = HttpRequest.newBuilder(URI.create(target)).build();
    return client.send(request, HttpResponse.BodyHandlers.discarding());
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "z/PreviewController.java",
      `
public final class PreviewController {
  private final PreviewTransport transport;
  public PreviewController(PreviewTransport transport) { this.transport = transport; }
  public Object get(@RequestParam String target) throws Exception {
    return transport.fetch(target);
  }
}
`,
    );

    const records = javaSsrfRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.path).toBe("z/PreviewTransport.java");
    expect(records[0]?.frameworkModel).toMatchObject({
      scope: "cross-file-wrapper",
      source: { path: "z/PreviewController.java" },
      sink: { path: "z/PreviewTransport.java", cweIds: ["CWE-918"] },
    });
  });

  test("rejects shadows, fixed and reassigned values, comments, and duplicate service types", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "src/ShadowTransport.java",
      `
final class HttpClient { Object send(Object request, Object handler) { return request; } }
public final class ShadowTransport {
  private final HttpClient client = new HttpClient();
  public Object fetch(String target) { return client.send(target, null); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/ShadowService.java",
      `
public final class ShadowService {
  private final ShadowTransport transport;
  public Object fetch(String target) { return transport.fetch(target); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/ShadowController.java",
      `
public final class ShadowController {
  private final ShadowService previews;
  public Object get(@RequestParam String target) {
    // previews.fetch(target);
    String example = "previews.fetch(target)";
    return previews.fetch(target);
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "one/DuplicateService.java",
      `public final class DuplicateService { public Object fetch(String target) { return target; } }`,
    );
    await writeRepositoryFile(
      repository,
      "two/DuplicateService.java",
      `public final class DuplicateService { public Object fetch(String target) { return target; } }`,
    );
    await writeRepositoryFile(
      repository,
      "src/DuplicateController.java",
      `
public final class DuplicateController {
  private final DuplicateService previews;
  public Object get(@RequestParam String target) {
    target = "https://fixed.example.invalid/";
    return previews.fetch(target);
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/SecondArgumentTransport.java",
      `
import java.net.http.*;
public final class SecondArgumentTransport {
  private final HttpClient client = HttpClient.newHttpClient();
  private final HttpRequest fixedRequest;
  public Object fetch(String target) throws Exception {
    return client.send(fixedRequest, target);
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/SecondArgumentController.java",
      `
public final class SecondArgumentController {
  private final SecondArgumentTransport transport;
  public Object get(@RequestParam String target) throws Exception {
    return transport.fetch(target);
  }
}
`,
    );

    expect(
      javaSsrfRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("teaches the reviewer the Java destination and redirect boundary", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({ frameworkModel: { id: "spring-http-ssrf" } }),
    );
    expect(prompt).toContain(
      "HttpClient.Redirect.NEVER or Reactor Netty followRedirect(false) constrains only responses after the initial request",
    );
    expect(prompt).toContain(
      "exact request-key selection from fixed server-owned complete destinations",
    );
    expect(prompt).toContain(
      "every DNS A/AAAA answer, connection-time resolution and reuse",
    );
    expect(prompt).toContain(
      "locally shadowed HttpClient, RestTemplate, or WebClient types",
    );
  });
});
