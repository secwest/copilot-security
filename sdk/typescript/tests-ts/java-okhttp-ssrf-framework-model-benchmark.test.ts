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
    propagators: Array<{ kind: string; path: string; line: number }>;
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
  "java-okhttp-multi-hop-ssrf",
  "java-okhttp-multi-hop-safe-fetch",
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

function okHttpRecords(inventory: string): FrameworkRecord[] {
  return parseRecords(inventory).filter(
    (record) => record.frameworkModel?.id === "spring-http-ssrf",
  );
}

async function temporaryRepository(): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-java-okhttp-"),
  );
  temporaryPaths.push(repository);
  return repository;
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

describe("OkHttp SSRF framework-model effectiveness benchmark", () => {
  test("keeps the executable exploit and fixed-destination control under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "java-okhttp-ssrf-manifest.json"),
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
        "java-okhttp-ssrf",
        "src/main/java/example/VulnerableOkHttpWitness.java",
      ),
      "utf8",
    );
    expect(vulnerableWitness).toContain(".url(attackerControlled)");
    expect(vulnerableWitness).toContain("client.newCall(request).execute()");
    expect(vulnerableWitness).toContain('"private-metadata"');

    const safeWitness = await readFile(
      join(
        benchmarkRoot,
        "witnesses",
        "java-okhttp-safe-fetch",
        "src/main/java/example/SafeOkHttpWitness.java",
      ),
      "utf8",
    );
    expect(safeWitness).toContain(".followRedirects(false)");
    expect(safeWitness).toContain(".followSslRedirects(false)");
    expect(safeWitness).toContain('Map.of("status", fixedStatus)');
    expect(safeWitness).toContain(
      "fetch(client, allowedDestinations, attackerUrl)",
    );
  });

  test("preserves two typed service boundaries into an executed OkHttp request", async () => {
    const vulnerable = okHttpRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[0]),
      ),
    );
    const safe = okHttpRecords(
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
        line: 18,
      },
      sink: {
        kind: "outbound-http-url",
        path: "src/main/java/example/PreviewTransport.java",
        line: 17,
        cweIds: ["CWE-918"],
      },
    });
    expect(vulnerable[0]?.frameworkModel?.propagators).toHaveLength(6);

    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "fixed-destination-allowlist" }),
        expect.objectContaining({ kind: "redirects-disabled" }),
      ]),
    );
  });

  test("recognizes imported, fully qualified, builder-alias, and inline execution", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "src/ImportedController.java",
      `
import okhttp3.OkHttpClient;
import okhttp3.Request;
public final class ImportedController {
  private final OkHttpClient client = new OkHttpClient();
  public Object get(@RequestParam String target) throws Exception {
    Request request = new Request.Builder().url(target).build();
    return client.newCall(request).execute();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/FullyQualifiedController.java",
      `
public final class FullyQualifiedController {
  private final okhttp3.OkHttpClient client = new okhttp3.OkHttpClient();
  public Object get(@RequestParam String target) throws Exception {
    okhttp3.Request request = new okhttp3.Request.Builder()
      .url(target).build();
    return client.newCall(request).execute();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/BuilderAliasController.java",
      `
import okhttp3.OkHttpClient;
import okhttp3.Request;
public final class BuilderAliasController {
  private final OkHttpClient client = new OkHttpClient();
  public Object get(@RequestParam String target) throws Exception {
    Request.Builder builder = new Request.Builder();
    builder.url(target);
    Request request = builder.build();
    return client.newCall(request).execute();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/InlineController.java",
      `
import okhttp3.OkHttpClient;
import okhttp3.Request;
public final class InlineController {
  private final OkHttpClient client = new OkHttpClient();
  public Object get(@RequestParam String target) throws Exception {
    return client.newCall(new Request.Builder().url(target).build()).execute();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/DirectConstructionController.java",
      `
import okhttp3.OkHttpClient;
import okhttp3.Request;
public final class DirectConstructionController {
  public Object get(@RequestParam String target) throws Exception {
    return new OkHttpClient().newCall(
      new Request.Builder().url(target).build()
    ).execute();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/PreparedCallController.java",
      `
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
public final class PreparedCallController {
  private final OkHttpClient client = new OkHttpClient();
  public Object get(@RequestParam String target) throws Exception {
    Request request = new Request.Builder().url(target).build();
    Call prepared = client.newCall(request);
    audit();
    return prepared.execute();
  }
}
`,
    );

    const records = okHttpRecords(await buildResidualRiskInventory(repository));
    expect(records).toHaveLength(6);
    expect(records.map(({ path }) => path).sort()).toEqual([
      "src/BuilderAliasController.java",
      "src/DirectConstructionController.java",
      "src/FullyQualifiedController.java",
      "src/ImportedController.java",
      "src/InlineController.java",
      "src/PreparedCallController.java",
    ]);
  });

  test("rejects inert, merely prepared, reassigned, unrelated, and shadowed requests", async () => {
    const repository = await temporaryRepository();
    const cases: Record<string, string> = {
      InertController: `
import okhttp3.Request;
public final class InertController {
  public Object get(@RequestParam String target) {
    return new Request.Builder().url(target).build();
  }
}`,
      PreparedController: `
import okhttp3.OkHttpClient;
import okhttp3.Request;
public final class PreparedController {
  private final OkHttpClient client = new OkHttpClient();
  public Object get(@RequestParam String target) {
    Request request = new Request.Builder().url(target).build();
    return client.newCall(request);
  }
}`,
      SeparatedDispatchController: `
import okhttp3.OkHttpClient;
import okhttp3.Request;
public final class SeparatedDispatchController {
  private final OkHttpClient client = new OkHttpClient();
  private final Worker worker = new Worker();
  public Object get(@RequestParam String target) {
    Request request = new Request.Builder().url(target).build();
    client.newCall(request);
    return worker.execute();
  }
}`,
      SeparatedBuilderController: `
import okhttp3.OkHttpClient;
import okhttp3.Request;
public final class SeparatedBuilderController {
  private final OkHttpClient client = new OkHttpClient();
  private final UrlBuilder helper = new UrlBuilder();
  public Object get(@RequestParam String target) throws Exception {
    Request request = new Request.Builder().build();
    helper.url(target).build();
    return client.newCall(request).execute();
  }
}`,
      ReassignedPreparedCallController: `
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
public final class ReassignedPreparedCallController {
  private final OkHttpClient client = new OkHttpClient();
  public Object get(@RequestParam String target) throws Exception {
    Request request = new Request.Builder().url(target).build();
    Call prepared = client.newCall(request);
    Request fixed = new Request.Builder().url("https://fixed.example.invalid/").build();
    prepared = client.newCall(fixed);
    return prepared.execute();
  }
}`,
      ReassignedController: `
import okhttp3.OkHttpClient;
import okhttp3.Request;
public final class ReassignedController {
  private final OkHttpClient client = new OkHttpClient();
  public Object get(@RequestParam String target) throws Exception {
    target = "https://fixed.example.invalid/";
    Request request = new Request.Builder().url(target).build();
    return client.newCall(request).execute();
  }
}`,
      UnrelatedController: `
public final class UnrelatedController {
  public Object get(@RequestParam String target) {
    UrlBuilder request = new UrlBuilder().url(target);
    return request.execute();
  }
}`,
      ShadowController: `
final class Request {
  static final class Builder {
    Builder url(String value) { return this; }
    Request build() { return new Request(); }
  }
}
final class OkHttpClient {
  Call newCall(Request request) { return new Call(); }
}
final class Call { Object execute() { return null; } }
public final class ShadowController {
  private final OkHttpClient client = new OkHttpClient();
  public Object get(@RequestParam String target) {
    Request request = new Request.Builder().url(target).build();
    return client.newCall(request).execute();
  }
}`,
    };
    await Promise.all(
      Object.entries(cases).map(([name, contents]) =>
        writeRepositoryFile(repository, `src/${name}.java`, contents),
      ),
    );

    expect(okHttpRecords(await buildResidualRiskInventory(repository))).toEqual(
      [],
    );
  });

  test("teaches the reviewer OkHttp's destination and dispatch boundary", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({ frameworkModel: { id: "spring-http-ssrf" } }),
    );
    expect(prompt).toContain("OkHttp Request.Builder.url");
    expect(prompt).toContain("OkHttpClient.newCall");
    expect(prompt).toContain("execute/enqueue");
    expect(prompt).toContain("unexecuted builder is counterevidence");
    expect(prompt).toContain("locally shadowed HttpClient");
  });
});
