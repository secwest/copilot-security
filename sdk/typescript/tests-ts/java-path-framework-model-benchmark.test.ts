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
  "java-file-getname-path-traversal",
  "java-file-getname-safe-path",
  "java-path-getfilename-path-traversal",
  "java-path-getfilename-safe-path",
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

function javaFileGetNameRecords(inventory: string): FrameworkRecord[] {
  return parseRecords(inventory).filter(
    (record) => record.frameworkModel?.id === "java-file-getname-path-boundary",
  );
}

function javaPathGetFileNameRecords(inventory: string): FrameworkRecord[] {
  return parseRecords(inventory).filter(
    (record) =>
      record.frameworkModel?.id === "java-path-getfilename-path-boundary",
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
    expect(manifest.cases[2]?.expected[0]).toMatchObject({
      cwe: ["CWE-22"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[3]?.expected).toEqual([]);
    expect(manifest.cases[4]?.expected[0]).toMatchObject({
      cwe: ["CWE-22"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[5]?.expected).toEqual([]);
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
    const getNameVulnerableWitness = await readFile(
      join(
        benchmarkRoot,
        "witnesses",
        caseIds[2],
        "VulnerableFileGetNameWitness.java",
      ),
      "utf8",
    );
    expect(getNameVulnerableWitness).toContain('read(documents, "..")');
    expect(getNameVulnerableWitness).toContain("new File(requested).getName()");
    const getNameSafeWitness = await readFile(
      join(
        benchmarkRoot,
        "witnesses",
        caseIds[3],
        "SafeFileGetNameWitness.java",
      ),
      "utf8",
    );
    expect(getNameSafeWitness).toContain('expectRejected(documents, "..")');
    expect(getNameSafeWitness).toContain(
      'expectRejected(documents, "nested/..")',
    );
    const pathGetFileNameVulnerableWitness = await readFile(
      join(
        benchmarkRoot,
        "witnesses",
        caseIds[4],
        "VulnerablePathGetFileNameWitness.java",
      ),
      "utf8",
    );
    expect(pathGetFileNameVulnerableWitness).toContain(
      'Path.of("..").getFileName()',
    );
    expect(pathGetFileNameVulnerableWitness).toContain('read(documents, "..")');
    const pathGetFileNameSafeWitness = await readFile(
      join(
        benchmarkRoot,
        "witnesses",
        caseIds[5],
        "SafePathGetFileNameWitness.java",
      ),
      "utf8",
    );
    expect(pathGetFileNameSafeWitness).toContain(
      'expectRejected(documents, "..")',
    );
    expect(pathGetFileNameSafeWitness).toContain(
      'expectRejected(documents, "nested/..")',
    );
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
    const getNameVulnerableInventory = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", caseIds[2]),
    );
    const getNameSafeInventory = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", caseIds[3]),
    );
    const pathGetFileNameVulnerableInventory = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", caseIds[4]),
    );
    const pathGetFileNameSafeInventory = await buildResidualRiskInventory(
      join(benchmarkRoot, "fixtures", caseIds[5]),
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
    expect(javaPathRecords(getNameVulnerableInventory)).toHaveLength(1);
    const getNameVulnerable = javaFileGetNameRecords(
      getNameVulnerableInventory,
    );
    expect(getNameVulnerable).toHaveLength(1);
    expect(getNameVulnerable[0]?.path).toBe(
      "src/main/java/example/DocumentStore.java",
    );
    expect(getNameVulnerable[0]?.frameworkModel?.sink.line).toBe(19);
    expect(
      getNameVulnerable[0]?.frameworkModel?.candidateControls.map(
        ({ kind }) => kind,
      ),
    ).toEqual(["incomplete-java-io-file-getname-reduction"]);

    expect(javaPathRecords(getNameSafeInventory)).toHaveLength(1);
    const getNameSafe = javaFileGetNameRecords(getNameSafeInventory);
    expect(getNameSafe).toHaveLength(1);
    expect(getNameSafe[0]?.frameworkModel?.sink.line).toBe(22);
    expect(
      getNameSafe[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual(
      expect.arrayContaining([
        "incomplete-java-io-file-getname-reduction",
        "parent-path-component-rejection",
      ]),
    );

    expect(javaPathRecords(pathGetFileNameVulnerableInventory)).toHaveLength(1);
    const pathGetFileNameVulnerable = javaPathGetFileNameRecords(
      pathGetFileNameVulnerableInventory,
    );
    expect(pathGetFileNameVulnerable).toHaveLength(1);
    expect(pathGetFileNameVulnerable[0]?.path).toBe(
      "src/main/java/example/DocumentStore.java",
    );
    expect(pathGetFileNameVulnerable[0]?.frameworkModel?.sink.line).toBe(18);
    expect(
      pathGetFileNameVulnerable[0]?.frameworkModel?.candidateControls.map(
        ({ kind }) => kind,
      ),
    ).toEqual(["incomplete-java-nio-path-getfilename-reduction"]);

    expect(javaPathRecords(pathGetFileNameSafeInventory)).toHaveLength(1);
    const pathGetFileNameSafe = javaPathGetFileNameRecords(
      pathGetFileNameSafeInventory,
    );
    expect(pathGetFileNameSafe).toHaveLength(1);
    expect(pathGetFileNameSafe[0]?.frameworkModel?.sink.line).toBe(21);
    expect(
      pathGetFileNameSafe[0]?.frameworkModel?.candidateControls.map(
        ({ kind }) => kind,
      ),
    ).toEqual(
      expect.arrayContaining([
        "incomplete-java-nio-path-getfilename-reduction",
        "parent-path-component-rejection",
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

  test("derives exact java.io.File.getName boundary evidence from a proven path", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "src/ImportedController.java",
      `
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
public final class ImportedController {
  public String read(@RequestParam String path) throws Exception {
    File requested = new File(path);
    String basename = requested.getName();
    Path candidate = Path.of("documents").resolve(basename).resolve("content.txt");
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
    String basename = new java.io.File(path).getName();
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(basename).resolve("content.txt"));
  }
}
`,
    );

    const inventory = await buildResidualRiskInventory(repository);
    expect(javaPathRecords(inventory)).toHaveLength(2);
    const specialized = javaFileGetNameRecords(inventory);
    expect(specialized).toHaveLength(2);
    expect(
      specialized.map((record) => record.frameworkModel?.candidateControls),
    ).toEqual(
      expect.arrayContaining([
        expect.arrayContaining([
          expect.objectContaining({
            kind: "incomplete-java-io-file-getname-reduction",
          }),
        ]),
      ]),
    );
    expect(
      specialized.every((record) =>
        record.frameworkModel?.candidateControls.every(
          (control) => control.kind !== "parent-path-component-rejection",
        ),
      ),
    ).toBeTrue();
  });

  test("derives exact java.nio.file.Path.getFileName boundary evidence from a proven path", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "src/ImportedPathController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class ImportedPathController {
  public String read(@RequestParam String path) throws Exception {
    Path requested = Path.of(path);
    Path copy = requested;
    Path basename = copy.getFileName();
    Path candidate = Path.of("documents").resolve(basename).resolve("content.txt");
    return Files.readString(candidate);
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/ImportedPathsController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
public final class ImportedPathsController {
  public String read(@RequestParam String path) throws Exception {
    Path basename = Paths.get(path).getFileName();
    return Files.readString(Path.of("documents").resolve(basename).resolve("content.txt"));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/FullyQualifiedPathController.java",
      `
public final class FullyQualifiedPathController {
  public String read(@RequestParam String path) throws Exception {
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(java.nio.file.Path.of(path).getFileName()).resolve("content.txt"));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/PathParameterController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class PathParameterController {
  public String read(@RequestParam Path path) throws Exception {
    Path basename = path.getFileName();
    return Files.readString(Path.of("documents").resolve(basename).resolve("content.txt"));
  }
}
`,
    );

    const inventory = await buildResidualRiskInventory(repository);
    expect(javaPathRecords(inventory)).toHaveLength(4);
    const specialized = javaPathGetFileNameRecords(inventory);
    expect(specialized).toHaveLength(4);
    expect(
      specialized.map((record) => record.frameworkModel?.candidateControls),
    ).toEqual(
      expect.arrayContaining([
        expect.arrayContaining([
          expect.objectContaining({
            kind: "incomplete-java-nio-path-getfilename-reduction",
          }),
        ]),
      ]),
    );
    expect(
      specialized.every((record) =>
        record.frameworkModel?.candidateControls.every(
          (control) =>
            control.kind !== "single-path-component-validation" &&
            control.kind !== "parent-path-component-rejection",
        ),
      ),
    ).toBeTrue();
  });

  test("retains only exact pre-sink Path parent rejection", async () => {
    const repository = await temporaryRepository();
    const controller = (guard: string): string => `
import java.nio.file.Files;
import java.nio.file.Path;
public final class DocumentController {
  public String read(@RequestParam String path) throws Exception {
    Path basename = Path.of(path).getFileName();
    Path candidate = Path.of("documents").resolve(basename).resolve("content.txt");
${guard}
    return Files.readString(candidate);
  }
}
`;
    await writeRepositoryFile(
      repository,
      "safe/DocumentController.java",
      controller(
        `    if (Path.of("..").equals(basename)) { throw new SecurityException("parent"); }`,
      ),
    );
    await writeRepositoryFile(
      repository,
      "reverse/DocumentController.java",
      controller(
        `    if (basename.equals(Path.of(".."))) { return "rejected"; }`,
      ),
    );
    await writeRepositoryFile(
      repository,
      "weak/DocumentController.java",
      controller(
        `    if (basename.toString().contains("..")) { System.out.println("parent"); }`,
      ),
    );
    await writeRepositoryFile(
      repository,
      "other/DocumentController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class DocumentController {
  public String read(@RequestParam String path) throws Exception {
    Path checked = Path.of(path).getFileName();
    Path basename = Path.of(path).getFileName();
    if (Path.of("..").equals(checked)) { throw new SecurityException("parent"); }
    return Files.readString(Path.of("documents").resolve(basename).resolve("content.txt"));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "late/DocumentController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class DocumentController {
  public String read(@RequestParam String path) throws Exception {
    Path basename = Path.of(path).getFileName();
    String result = Files.readString(Path.of("documents").resolve(basename).resolve("content.txt"));
    if (Path.of("..").equals(basename)) { throw new SecurityException("parent"); }
    return result;
  }
}
`,
    );

    const specialized = javaPathGetFileNameRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(specialized).toHaveLength(5);
    const controls = new Map(
      specialized.map((record) => [
        record.path,
        record.frameworkModel?.candidateControls.map(({ kind }) => kind),
      ]),
    );
    for (const path of [
      "safe/DocumentController.java",
      "reverse/DocumentController.java",
    ]) {
      expect(controls.get(path)).toContain("parent-path-component-rejection");
    }
    for (const path of [
      "weak/DocumentController.java",
      "other/DocumentController.java",
      "late/DocumentController.java",
    ]) {
      expect(controls.get(path)).not.toContain(
        "parent-path-component-rejection",
      );
    }
  });

  test("rejects Path lookalikes, unrelated reductions, fixed values, tests, and reassignment", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "src/ShadowPathController.java",
      `
import java.nio.file.Files;
final class Path {
  static Path of(String value) { return new Path(); }
  Path getFileName() { return this; }
  Path resolve(Path value) { return this; }
}
public final class ShadowPathController {
  public String read(@RequestParam String path) throws Exception {
    Path basename = Path.of(path).getFileName();
    return Files.readString(java.nio.file.Path.of("documents").resolve(basename.toString()));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/ShadowPathsController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
final class Paths { static Path get(String value) { return Path.of("fixed"); } }
public final class ShadowPathsController {
  public String read(@RequestParam String path) throws Exception {
    Path basename = Paths.get(path).getFileName();
    return Files.readString(Path.of("documents").resolve(basename));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/UnrelatedController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class UnrelatedController {
  public String read(@RequestParam String path) throws Exception {
    Object basename = metadata.getFileName();
    return Files.readString(Path.of(path));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/FixedReductionController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class FixedReductionController {
  public String read(@RequestParam String path) throws Exception {
    Path basename = Path.of("guide").getFileName();
    return Files.readString(Path.of(path).resolve(basename));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/ClearedController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class ClearedController {
  public String read(@RequestParam String path) throws Exception {
    Path basename = Path.of(path).getFileName();
    basename = Path.of("guide");
    return Files.readString(Path.of("documents").resolve(basename));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/test/FixtureTest.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class FixtureTest {
  public String read(@RequestParam String path) throws Exception {
    return Files.readString(Path.of("documents").resolve(Path.of(path).getFileName()));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "cross/MixedController.java",
      `
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
@RestController
public final class MixedController {
  private final MixedStore store;
  public MixedController(MixedStore store) { this.store = store; }
  public String read(@RequestParam String path) throws Exception {
    return store.read(path, "guide");
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "cross/MixedStore.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class MixedStore {
  public String read(String path, String trusted) throws Exception {
    Path basename = Path.of(trusted).getFileName();
    return Files.readString(Path.of(path).resolve(basename));
  }
}
`,
    );

    expect(
      javaPathGetFileNameRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
  });

  test("preserves exact parent rejection and rejects weak or post-sink checks", async () => {
    const repository = await temporaryRepository();
    const controller = (guard: string): string => `
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
public final class DocumentController {
  public String read(@RequestParam String path) throws Exception {
    String basename = new File(path).getName();
    Path candidate = Path.of("documents").resolve(basename).resolve("content.txt");
${guard}
    return Files.readString(candidate);
  }
}
`;
    await writeRepositoryFile(
      repository,
      "safe/DocumentController.java",
      controller(
        `    if ("..".equals(basename)) { throw new SecurityException("parent"); }`,
      ),
    );
    await writeRepositoryFile(
      repository,
      "weak/DocumentController.java",
      controller(
        `    if (basename.contains("..")) { System.out.println("parent"); }`,
      ),
    );
    await writeRepositoryFile(
      repository,
      "other/DocumentController.java",
      controller(
        `    String other = "guide";
    if ("..".equals(other)) { throw new SecurityException("parent"); }`,
      ),
    );
    await writeRepositoryFile(
      repository,
      "late/DocumentController.java",
      `
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
public final class DocumentController {
  public String read(@RequestParam String path) throws Exception {
    String basename = new File(path).getName();
    Path candidate = Path.of("documents").resolve(basename).resolve("content.txt");
    String result = Files.readString(candidate);
    if ("..".equals(basename)) { throw new SecurityException("parent"); }
    return result;
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "parallel/DocumentController.java",
      `
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
public final class DocumentController {
  public String read(@RequestParam String path) throws Exception {
    String checked = new File(path).getName();
    String basename = new File(path).getName();
    if ("..".equals(checked)) { throw new SecurityException("parent"); }
    return Files.readString(Path.of("documents").resolve(basename));
  }
}
`,
    );

    const specialized = javaFileGetNameRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(specialized).toHaveLength(5);
    const controlKinds = new Map(
      specialized.map((record) => [
        record.path,
        record.frameworkModel?.candidateControls.map(({ kind }) => kind),
      ]),
    );
    expect(controlKinds.get("safe/DocumentController.java")).toContain(
      "parent-path-component-rejection",
    );
    for (const path of [
      "weak/DocumentController.java",
      "other/DocumentController.java",
      "late/DocumentController.java",
      "parallel/DocumentController.java",
    ]) {
      expect(controlKinds.get(path)).not.toContain(
        "parent-path-component-rejection",
      );
    }
  });

  test("rejects File lookalikes, unrelated getName calls, tests, and cleared values", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "src/ShadowController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
final class File { File(String value) {} String getName() { return "fixed"; } }
public final class ShadowController {
  public String read(@RequestParam String path) throws Exception {
    String basename = new File(path).getName();
    return Files.readString(Path.of("documents").resolve(basename));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/UnrelatedController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class UnrelatedController {
  public String read(@RequestParam String path) throws Exception {
    String label = metadata.getName();
    return Files.readString(Path.of(path));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/ClearedController.java",
      `
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
public final class ClearedController {
  public String read(@RequestParam String path) throws Exception {
    String basename = new File(path).getName();
    basename = "guide";
    return Files.readString(Path.of("documents").resolve(basename));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/FixedReductionController.java",
      `
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
public final class FixedReductionController {
  public String read(@RequestParam String path) throws Exception {
    String basename = new File("guide").getName();
    return Files.readString(Path.of(path).resolve(basename));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "cross/MixedController.java",
      `
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
@RestController
public final class MixedController {
  private final MixedStore store;
  public MixedController(MixedStore store) { this.store = store; }
  public String read(@RequestParam String path) throws Exception {
    return store.read(path, "guide");
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "cross/MixedStore.java",
      `
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
public final class MixedStore {
  public String read(String path, String trusted) throws Exception {
    String basename = new File(trusted).getName();
    return Files.readString(Path.of(path).resolve(basename));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/test/FixtureTest.java",
      `
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
public final class FixtureTest {
  public String read(@RequestParam String path) throws Exception {
    String basename = new File(path).getName();
    return Files.readString(Path.of("documents").resolve(basename));
  }
}
`,
    );

    expect(
      javaFileGetNameRecords(await buildResidualRiskInventory(repository)),
    ).toEqual([]);
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
    expect(prompt).toContain(
      'new File("..").getName() returns the exact parent component ".."',
    );
    expect(prompt).toContain(
      'Path.of("..").getFileName() preserves the exact parent component',
    );
    expect(prompt).toContain(
      "getFileName and getNameCount are not standalone traversal controls",
    );
    expect(prompt).toContain("A check on another reduction");
    expect(prompt).toContain("a check after the operation is insufficient");
  });
});
