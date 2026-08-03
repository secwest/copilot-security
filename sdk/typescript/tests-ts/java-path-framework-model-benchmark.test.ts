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
  "java-multi-hop-path-traversal",
  "java-multi-hop-safe-path",
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

function javaPathRecords(inventory: string): FrameworkRecord[] {
  return parseRecords(inventory).filter(
    (record) => record.frameworkModel?.id === "spring-http-path",
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
    join(tmpdir(), "copilot-security-java-path-"),
  );
  temporaryPaths.push(repository);
  return repository;
}

describe("Spring Java path framework-model effectiveness benchmark", () => {
  test("keeps the exploit and real-filesystem containment control under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "java-multi-hop-path-manifest.json"),
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
      cwe: ["CWE-22"],
      acceptableSeverities: ["high", "medium"],
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
        "VulnerablePathWitness.java",
      ),
      "utf8",
    );
    expect(vulnerableWitness).toContain('read(documents, "../private.txt")');
    expect(vulnerableWitness).toContain(
      "read(documents, privateFile.toString())",
    );
    const safeWitness = await readFile(
      join(benchmarkRoot, "witnesses", caseIds[1], "SafePathWitness.java"),
      "utf8",
    );
    expect(safeWitness).toContain("candidate.toRealPath()");
    expect(safeWitness).toContain(
      'expectRejected(documents, "../documents-backup/backup.txt")',
    );
    expect(safeWitness).toContain("Files.createSymbolicLink");
  });

  test("preserves both typed Java service boundaries into java.nio.file.Files", async () => {
    const vulnerable = javaPathRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[0]),
      ),
    );
    const safe = javaPathRecords(
      await buildResidualRiskInventory(
        join(benchmarkRoot, "fixtures", caseIds[1]),
      ),
    );

    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.path).toBe(
      "src/main/java/example/DocumentStore.java",
    );
    expect(vulnerable[0]?.frameworkModel).toEqual({
      schemaVersion: "1.2",
      id: "spring-http-path",
      language: "java-kotlin",
      scope: "cross-file-multi-hop-wrapper",
      source: {
        kind: "spring-bound-parameter",
        path: "src/main/java/example/DocumentController.java",
        line: 17,
      },
      sink: {
        kind: "filesystem-path",
        path: "src/main/java/example/DocumentStore.java",
        line: 17,
        cweIds: ["CWE-22"],
      },
      propagators: [
        {
          kind: "java-type-binding",
          path: "src/main/java/example/DocumentController.java",
          line: 10,
          symbol: "documents:DocumentService",
        },
        {
          kind: "wrapper-call-argument",
          path: "src/main/java/example/DocumentController.java",
          line: 18,
          symbol: "documents.read[0]",
        },
        {
          kind: "wrapper-parameter",
          path: "src/main/java/example/DocumentService.java",
          line: 14,
          symbol: "path",
        },
        {
          kind: "java-type-binding",
          path: "src/main/java/example/DocumentService.java",
          line: 8,
          symbol: "store:DocumentStore",
        },
        {
          kind: "wrapper-call-argument",
          path: "src/main/java/example/DocumentService.java",
          line: 15,
          symbol: "store.read[0]",
        },
        {
          kind: "wrapper-parameter",
          path: "src/main/java/example/DocumentStore.java",
          line: 16,
          symbol: "path",
        },
      ],
      candidateControls: [],
    });
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual(
      expect.arrayContaining([
        {
          kind: "absolute-path-rejection",
          path: "src/main/java/example/DocumentStore.java",
          line: 18,
        },
        {
          kind: "normalized-path",
          path: "src/main/java/example/DocumentStore.java",
          line: 22,
        },
        {
          kind: "filesystem-canonical-path",
          path: "src/main/java/example/DocumentStore.java",
          line: 27,
        },
        {
          kind: "component-aware-root-containment",
          path: "src/main/java/example/DocumentStore.java",
          line: 28,
        },
      ]),
    );
  });

  test("recognizes typed same-file and fully qualified sinks with control leads", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "src/DocumentController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class DocumentController {
  public String read(@RequestParam String path) throws Exception {
    Path relative = Path.of(path);
    if (relative.isAbsolute()) throw new SecurityException();
    Path root = Path.of("documents").toRealPath();
    Path candidate = root.resolve(relative).normalize();
    if (!candidate.startsWith(root)) throw new SecurityException();
    return Files.readString(candidate);
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/FullyQualifiedController.java",
      `
public final class FullyQualifiedController {
  public String read(@RequestParam String path) throws Exception {
    return java.nio.file.Files.readString(java.nio.file.Path.of(path));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/WildcardController.java",
      `
import java.nio.file.*;
public final class WildcardController {
  public String read(@RequestParam String path) throws Exception {
    return Files.readString(Path.of(path));
  }
}
`,
    );

    const records = javaPathRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(records).toHaveLength(3);
    const modeled = records.find(
      (record) => record.path === "src/DocumentController.java",
    );
    expect(modeled?.frameworkModel?.candidateControls).toEqual(
      expect.arrayContaining([
        {
          kind: "absolute-path-rejection",
          path: "src/DocumentController.java",
          line: 7,
        },
        {
          kind: "filesystem-canonical-path",
          path: "src/DocumentController.java",
          line: 8,
        },
        {
          kind: "normalized-path",
          path: "src/DocumentController.java",
          line: 9,
        },
        {
          kind: "component-aware-root-containment",
          path: "src/DocumentController.java",
          line: 10,
        },
      ]),
    );
  });

  test("rejects shadow types, fixed values, comments, strings, and reassigned relays", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "src/DocumentStore.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class DocumentStore {
  public String read(String path) throws Exception {
    return Files.readString(Path.of(path));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/DocumentService.java",
      `
public final class DocumentService {
  private final DocumentStore store;
  public String read(String path) throws Exception {
    path = "fixed.txt";
    return store.read(path);
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/DocumentController.java",
      `
public final class DocumentController {
  private final DocumentService documents;
  public String read(@RequestParam String path) throws Exception {
    // documents.read(path);
    String example = "documents.read(path)";
    return documents.read(path);
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/ShadowController.java",
      `
import java.nio.file.Files;
final class Files { public static String readString(Object path) { return path.toString(); } }
public final class ShadowController {
  public String read(@RequestParam String path) { return Files.readString(path); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/ShadowStore.java",
      `
final class Files { public static String readString(Object path) { return path.toString(); } }
public final class ShadowStore {
  public String read(String path) { return Files.readString(path); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/ShadowService.java",
      `
public final class ShadowService {
  private final ShadowStore store;
  public String read(String path) { return store.read(path); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/ShadowPathController.java",
      `
public final class ShadowPathController {
  private final ShadowService documents;
  public String read(@RequestParam String path) { return documents.read(path); }
}
`,
    );

    expect(
      javaPathRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("rejects duplicate Java service types instead of guessing a receiver", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "one/DocumentStore.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class DocumentStore {
  public String read(String path) throws Exception { return Files.readString(Path.of(path)); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "two/DocumentStore.java",
      `public final class DocumentStore { public String read(String path) { return path; } }`,
    );
    await writeRepositoryFile(
      repository,
      "DocumentService.java",
      `
public final class DocumentService {
  private final DocumentStore store;
  public String read(String path) throws Exception { return store.read(path); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "DocumentController.java",
      `
public final class DocumentController {
  private final DocumentService documents;
  public String read(@RequestParam String path) throws Exception { return documents.read(path); }
}
`,
    );

    expect(
      javaPathRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("teaches the reviewer the Java path and two-hop service contract", () => {
    const prompt = scanQualityGatePrompt(
      JSON.stringify({ frameworkModel: { id: "spring-http-path" } }),
    );
    expect(prompt).toContain(
      "Path.resolve returns an absolute later operand without the trusted root",
    );
    expect(prompt).toContain(
      "Path.normalize is syntactic and does not resolve filesystem links",
    );
    expect(prompt).toContain(
      "Java uses the same exact type resolution at both service boundaries",
    );
    expect(prompt).toContain(
      "String.startsWith can accept a sibling directory prefix",
    );
    expect(prompt).toContain("values reassigned before either service call");
  });
});
