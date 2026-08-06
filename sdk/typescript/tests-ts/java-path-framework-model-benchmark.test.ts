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
    expect(getNameVulnerableWitness).toContain("new File(input).getName()");
    expect(getNameVulnerableWitness).toContain("basename(requested)");
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
    expect(getNameVulnerable[0]?.frameworkModel?.sink.line).toBe(18);
    expect(getNameVulnerable[0]?.frameworkModel?.candidateControls).toEqual([
      {
        kind: "incomplete-java-io-file-getname-reduction",
        path: "src/main/java/example/DocumentNames.java",
        line: 9,
      },
    ]);

    expect(javaPathRecords(getNameSafeInventory)).toHaveLength(1);
    const getNameSafe = javaFileGetNameRecords(getNameSafeInventory);
    expect(getNameSafe).toHaveLength(1);
    expect(getNameSafe[0]?.frameworkModel?.sink.line).toBe(21);
    expect(getNameSafe[0]?.frameworkModel?.candidateControls).toEqual(
      expect.arrayContaining([
        {
          kind: "incomplete-java-io-file-getname-reduction",
          path: "src/main/java/example/DocumentNames.java",
          line: 9,
        },
        {
          kind: "parent-path-component-rejection",
          path: "src/main/java/example/DocumentStore.java",
          line: 18,
        },
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
    expect(pathGetFileNameVulnerable[0]?.frameworkModel?.sink.line).toBe(24);
    expect(
      pathGetFileNameVulnerable[0]?.frameworkModel?.candidateControls,
    ).toEqual([
      {
        kind: "incomplete-java-nio-path-getfilename-reduction",
        path: "src/main/java/example/DocumentNames.java",
        line: 9,
      },
    ]);

    expect(javaPathRecords(pathGetFileNameSafeInventory)).toHaveLength(1);
    const pathGetFileNameSafe = javaPathGetFileNameRecords(
      pathGetFileNameSafeInventory,
    );
    expect(pathGetFileNameSafe).toHaveLength(1);
    expect(pathGetFileNameSafe[0]?.frameworkModel?.sink.line).toBe(21);
    expect(pathGetFileNameSafe[0]?.frameworkModel?.candidateControls).toEqual(
      expect.arrayContaining([
        {
          kind: "incomplete-java-nio-path-getfilename-reduction",
          path: "src/main/java/example/DocumentNames.java",
          line: 9,
        },
        {
          kind: "parent-path-component-rejection",
          path: "src/main/java/example/DocumentStore.java",
          line: 18,
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

  test("summarizes exact same-file File basename helpers", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "src/DirectFileHelperController.java",
      `
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
public final class DirectFileHelperController {
  @Deprecated
  private static String basename(String input) {
    return new File(input).getName();
  }
  public String read(@RequestParam String path) throws Exception {
    String name = basename(path);
    return Files.readString(Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/FileParameterHelperController.java",
      `
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
public final class FileParameterHelperController {
  private String basename(File input) {
    File copy = input;
    String name = copy.getName();
    String result = name;
    return result;
  }
  public String read(@RequestParam String path) throws Exception {
    File requested = new File(path);
    String name = this.basename(requested);
    if ("..".equals(name)) throw new SecurityException("parent");
    return Files.readString(Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/MultiParameterFileHelperController.java",
      `
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
public final class MultiParameterFileHelperController {
  private static String selectName(String ignored, String input) {
    return new File(input).getName();
  }
  public String read(@RequestParam String path) throws Exception {
    String name = MultiParameterFileHelperController.selectName("fixed", path);
    return Files.readString(Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "qualified/example/String.java",
      `package qualified.example; final class String {}`,
    );
    await writeRepositoryFile(
      repository,
      "qualified/example/QualifiedFileHelperController.java",
      `
package qualified.example;
public final class QualifiedFileHelperController {
  static java.lang.String basename(java.lang.String input) {
    java.io.File requested = new java.io.File(input);
    java.io.File copy = requested;
    java.lang.String name = copy.getName();
    return name;
  }
  public java.lang.String read(@RequestParam java.lang.String path) throws Exception {
    java.lang.String name = basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );

    const inventory = await buildResidualRiskInventory(repository);
    expect(javaPathRecords(inventory)).toHaveLength(4);
    const specialized = javaFileGetNameRecords(inventory);
    expect(specialized).toHaveLength(4);
    expect(
      specialized
        .find(
          (record) => record.path === "src/FileParameterHelperController.java",
        )
        ?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toContain("parent-path-component-rejection");
    expect(
      specialized.every((record) =>
        record.frameworkModel?.candidateControls.some(
          ({ kind }) => kind === "incomplete-java-io-file-getname-reduction",
        ),
      ),
    ).toBeTrue();
  });

  test("rejects ambiguous or transformed File basename helpers", async () => {
    const repository = await temporaryRepository();
    const controller = (
      className: string,
      helpers: string,
      call: string,
    ): string => `
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
public final class ${className} {
${helpers}
  public String read(@RequestParam String path) throws Exception {
    String name = ${call};
    return Files.readString(Path.of("documents").resolve(name));
  }
}
`;
    await writeRepositoryFile(
      repository,
      "src/OverloadedFileHelperController.java",
      controller(
        "OverloadedFileHelperController",
        `  private static String basename(String input) { return new File(input).getName(); }
  private static String basename(File input) { return input.getName(); }`,
        "basename(path)",
      ),
    );
    await writeRepositoryFile(
      repository,
      "src/BranchFileHelperController.java",
      controller(
        "BranchFileHelperController",
        `  private static String basename(String input) {
    if (input.isEmpty()) return "guide";
    return new File(input).getName();
  }`,
        "basename(path)",
      ),
    );
    await writeRepositoryFile(
      repository,
      "src/TransformedFileHelperController.java",
      controller(
        "TransformedFileHelperController",
        `  private static String basename(String input) {
    return new File(input + ".txt").getName();
  }`,
        "basename(path)",
      ),
    );
    await writeRepositoryFile(
      repository,
      "src/TransformedFileCallController.java",
      controller(
        "TransformedFileCallController",
        `  private static String basename(String input) {
    return new File(input).getName();
  }`,
        'basename("prefix/" + path)',
      ),
    );
    await writeRepositoryFile(
      repository,
      "src/ReassignedFileHelperController.java",
      controller(
        "ReassignedFileHelperController",
        `  private static String basename(String input) {
    input = "guide";
    return new File(input).getName();
  }`,
        "basename(path)",
      ),
    );
    await writeRepositoryFile(
      repository,
      "src/NestedFileHelperController.java",
      controller(
        "NestedFileHelperController",
        `  private static String reduce(String input) { return new File(input).getName(); }
  private static String basename(String input) { return reduce(input); }`,
        "basename(path)",
      ),
    );
    await writeRepositoryFile(
      repository,
      "src/ForeignFileReceiverController.java",
      `
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
final class FileReducer {
  String basename(String input) { return new File(input).getName(); }
}
public final class ForeignFileReceiverController {
  private final FileReducer reducer = new FileReducer();
  public String read(@RequestParam String path) throws Exception {
    String name = reducer.basename(path);
    return Files.readString(Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "wildcard/file/File.java",
      `
package wildcard.file;
final class File {
  File(String ignored) {}
  String getName() { return "guide"; }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "wildcard/file/WildcardFileHelperController.java",
      `
package wildcard.file;
import java.io.*;
public final class WildcardFileHelperController {
  private static String basename(String input) {
    return new File(input).getName();
  }
  public String read(@RequestParam String path) throws Exception {
    String name = basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );

    const inventory = await buildResidualRiskInventory(repository);
    expect(javaPathRecords(inventory)).toHaveLength(8);
    expect(javaFileGetNameRecords(inventory)).toEqual([]);
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

  test("summarizes exact same-file Path basename helpers", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "src/DirectHelperController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class DirectHelperController {
  private static Path basename(String input) {
    return Path.of(input).getFileName();
  }
  public String read(@RequestParam String path) throws Exception {
    Path name = basename(path);
    return Files.readString(Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/PathParameterHelperController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class PathParameterHelperController {
  private Path basename(Path input) {
    Path copy = input;
    Path name = copy.getFileName();
    return name;
  }
  public String read(@RequestParam String path) throws Exception {
    Path requested = Path.of(path);
    Path name = this.basename(requested);
    if (Path.of("..").equals(name)) throw new SecurityException("parent");
    return Files.readString(Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/MultiParameterHelperController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
public final class MultiParameterHelperController {
  private static Path selectName(String ignored, String input) {
    return Paths.get(input).getFileName();
  }
  public String read(@RequestParam String path) throws Exception {
    Path name = MultiParameterHelperController.selectName("fixed", path);
    return Files.readString(Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/AliasHelperController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class AliasHelperController {
  static Path basename(String input) {
    String copy = input;
    Path requested = Path.of(copy);
    Path name = requested.getFileName();
    Path result = name;
    return result;
  }
  public String read(@RequestParam String path) throws Exception {
    Path name = basename(path);
    return Files.readString(Path.of("documents").resolve(name));
  }
}
`,
    );

    const inventory = await buildResidualRiskInventory(repository);
    expect(javaPathRecords(inventory)).toHaveLength(4);
    const specialized = javaPathGetFileNameRecords(inventory);
    expect(specialized).toHaveLength(4);
    expect(
      specialized
        .find(
          (record) => record.path === "src/PathParameterHelperController.java",
        )
        ?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toContain("parent-path-component-rejection");
    expect(
      specialized.every((record) =>
        record.frameworkModel?.candidateControls.some(
          ({ kind }) =>
            kind === "incomplete-java-nio-path-getfilename-reduction",
        ),
      ),
    ).toBeTrue();
  });

  test("summarizes exact project-local cross-file Java basename helpers", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "pom.xml",
      `<project><modelVersion>4.0.0</modelVersion></project>`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/example/PathNames.java",
      `
package example;
import java.nio.file.Path;
final class PathNames {
  static Path basename(String input) {
    return Path.of(input).getFileName();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/example/DocumentController.java",
      `
package example;
import java.nio.file.Files;
import java.nio.file.Path;
public final class DocumentController {
  public String read(@RequestParam String path) throws Exception {
    Path name = PathNames.basename(path);
    return Files.readString(Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/example/FileNames.java",
      `
package example;
import java.io.File;
final class FileNames {
  static String basename(String input) {
    return new File(input).getName();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/example/FileDocumentController.java",
      `
package example;
import java.nio.file.Files;
import java.nio.file.Path;
public final class FileDocumentController {
  public String read(@RequestParam String path) throws Exception {
    String name = FileNames.basename(path);
    if ("..".equals(name)) throw new SecurityException("parent");
    return Files.readString(Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/helpers/ImportedPathNames.java",
      `
package helpers;
import java.nio.file.Path;
public final class ImportedPathNames {
  public static Path basename(String input) {
    return Path.of(input).getFileName();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/client/ImportedController.java",
      `
package client;
import helpers.ImportedPathNames;
import java.nio.file.Files;
import java.nio.file.Path;
public final class ImportedController {
  public String read(@RequestParam String path) throws Exception {
    Path name = ImportedPathNames.basename(path);
    return Files.readString(Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/helpers/QualifiedFileNames.java",
      `
package helpers;
public final class QualifiedFileNames {
  public static java.lang.String basename(java.lang.String input) {
    return new java.io.File(input).getName();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/client/QualifiedController.java",
      `
package client;
public final class QualifiedController {
  public String read(@RequestParam String path) throws Exception {
    String name = helpers.QualifiedFileNames.basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );

    const inventory = await buildResidualRiskInventory(repository);
    expect(javaPathRecords(inventory)).toHaveLength(4);
    const pathSpecialized = javaPathGetFileNameRecords(inventory);
    const fileSpecialized = javaFileGetNameRecords(inventory);
    expect(pathSpecialized).toHaveLength(2);
    expect(fileSpecialized).toHaveLength(2);
    expect(
      pathSpecialized.flatMap(
        (record) => record.frameworkModel?.candidateControls ?? [],
      ),
    ).toContainEqual({
      kind: "incomplete-java-nio-path-getfilename-reduction",
      path: "src/main/java/example/PathNames.java",
      line: 6,
    });
    expect(
      pathSpecialized.flatMap(
        (record) => record.frameworkModel?.candidateControls ?? [],
      ),
    ).toContainEqual({
      kind: "incomplete-java-nio-path-getfilename-reduction",
      path: "src/main/java/helpers/ImportedPathNames.java",
      line: 6,
    });
    expect(
      fileSpecialized.flatMap(
        (record) => record.frameworkModel?.candidateControls ?? [],
      ),
    ).toEqual(
      expect.arrayContaining([
        {
          kind: "incomplete-java-io-file-getname-reduction",
          path: "src/main/java/example/FileNames.java",
          line: 6,
        },
        {
          kind: "incomplete-java-io-file-getname-reduction",
          path: "src/main/java/helpers/QualifiedFileNames.java",
          line: 5,
        },
        expect.objectContaining({ kind: "parent-path-component-rejection" }),
      ]),
    );
  });

  test("rejects ambiguous, inaccessible, or inexact cross-file basename helpers", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "pom.xml",
      `<project><modelVersion>4.0.0</modelVersion></project>`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/duplicate/PathNames.java",
      `
package duplicate;
import java.nio.file.Path;
final class PathNames {
  static Path basename(String input) { return Path.of(input).getFileName(); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/duplicate/Other.java",
      `package duplicate; final class PathNames {}`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/duplicate/DuplicateController.java",
      `
package duplicate;
public final class DuplicateController {
  public String read(@RequestParam String path) throws Exception {
    java.nio.file.Path name = PathNames.basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/overload/PathNames.java",
      `
package overload;
import java.nio.file.Path;
final class PathNames {
  static Path basename(String input) { return Path.of(input).getFileName(); }
  static Path basename(Path input) { return input.getFileName(); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/overload/OverloadController.java",
      `
package overload;
public final class OverloadController {
  public String read(@RequestParam String path) throws Exception {
    java.nio.file.Path name = PathNames.basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/privatecase/FileNames.java",
      `
package privatecase;
import java.io.File;
final class FileNames {
  private static String basename(String input) { return new File(input).getName(); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/privatecase/PrivateController.java",
      `
package privatecase;
public final class PrivateController {
  public String read(@RequestParam String path) throws Exception {
    String name = FileNames.basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/hidden/HiddenPathNames.java",
      `
package hidden;
import java.nio.file.Path;
final class HiddenPathNames {
  public static Path basename(String input) { return Path.of(input).getFileName(); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/client/HiddenController.java",
      `
package client;
import hidden.HiddenPathNames;
public final class HiddenController {
  public String read(@RequestParam String path) throws Exception {
    java.nio.file.Path name = HiddenPathNames.basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/transform/FileNames.java",
      `
package transform;
public final class FileNames {
  public static String basename(String input) { return new java.io.File(input).getName(); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/client/TransformController.java",
      `
package client;
import transform.FileNames;
public final class TransformController {
  public String read(@RequestParam String path) throws Exception {
    String name = FileNames.basename("prefix/" + path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/receiver/PathNames.java",
      `
package receiver;
import java.nio.file.Path;
final class PathNames {
  Path basename(String input) { return Path.of(input).getFileName(); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/receiver/ReceiverController.java",
      `
package receiver;
public final class ReceiverController {
  private final PathNames names = new PathNames();
  public String read(@RequestParam String path) throws Exception {
    java.nio.file.Path name = names.basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/shadow/File.java",
      `package shadow; final class File { File(String ignored) {} String getName() { return "guide"; } }`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/shadow/FileNames.java",
      `
package shadow;
import java.io.*;
final class FileNames {
  static String basename(String input) { return new File(input).getName(); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/shadow/ShadowController.java",
      `
package shadow;
public final class ShadowController {
  public String read(@RequestParam String path) throws Exception {
    String name = FileNames.basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "nested/pom.xml",
      `<project><modelVersion>4.0.0</modelVersion></project>`,
    );
    await writeRepositoryFile(
      repository,
      "nested/src/main/java/nested/NestedController.java",
      `
package nested;
import child.ChildPathNames;
public final class NestedController {
  public String read(@RequestParam String path) throws Exception {
    java.nio.file.Path name = ChildPathNames.basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "nested/module/pom.xml",
      `<project><modelVersion>4.0.0</modelVersion></project>`,
    );
    await writeRepositoryFile(
      repository,
      "nested/module/src/main/java/child/ChildPathNames.java",
      `
package child;
public final class ChildPathNames {
  public static java.nio.file.Path basename(String input) {
    return java.nio.file.Path.of(input).getFileName();
  }
}
`,
    );

    const inventory = await buildResidualRiskInventory(repository);
    expect(javaPathRecords(inventory)).toHaveLength(8);
    expect(javaPathGetFileNameRecords(inventory)).toEqual([]);
    expect(javaFileGetNameRecords(inventory)).toEqual([]);
  });

  test("isolates exact Gradle modules when resolving Java basename helpers", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "settings.gradle.kts",
      `rootProject.name = "basename-modules"
include("app", "peer", "isolated", "library")
`,
    );
    for (const [module, buildFile] of [
      ["app", "build.gradle.kts"],
      ["peer", "build.gradle"],
      ["isolated", "build.gradle.kts"],
      ["library", "build.gradle"],
    ] as const) {
      await writeRepositoryFile(
        repository,
        `${module}/${buildFile}`,
        `${
          buildFile.endsWith(".kts")
            ? "plugins { java }"
            : "plugins { id 'java' }"
        }
`,
      );
    }
    await writeRepositoryFile(
      repository,
      "app/src/main/java/example/PathNames.java",
      `
package example;
import java.nio.file.Path;
final class PathNames {
  static Path basename(String input) {
    return Path.of(input).getFileName();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "app/src/main/java/example/AppController.java",
      `
package example;
public final class AppController {
  public String read(@RequestParam String path) throws Exception {
    java.nio.file.Path name = PathNames.basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "peer/src/main/java/example/PathNames.java",
      `
package example;
final class PathNames {
  static java.nio.file.Path basename(String input) {
    return java.nio.file.Path.of(input).getFileName();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "library/src/main/java/example/FileNames.java",
      `
package example;
final class FileNames {
  static String basename(String input) {
    return new java.io.File(input).getName();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "isolated/src/main/java/example/IsolatedController.java",
      `
package example;
public final class IsolatedController {
  public String read(@RequestParam String path) throws Exception {
    String name = FileNames.basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "src/main/java/composite/PathNames.java",
      `
package composite;
final class PathNames {
  static java.nio.file.Path basename(String input) {
    return java.nio.file.Path.of(input).getFileName();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "included/settings.gradle",
      `rootProject.name = 'included-build'
`,
    );
    await writeRepositoryFile(
      repository,
      "included/src/main/java/composite/PathNames.java",
      `
package composite;
final class PathNames {
  static java.nio.file.Path basename(String input) {
    return java.nio.file.Path.of(input).getFileName();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "included/src/main/java/composite/IncludedController.java",
      `
package composite;
public final class IncludedController {
  public String read(@RequestParam String path) throws Exception {
    java.nio.file.Path name = PathNames.basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );

    const inventory = await buildResidualRiskInventory(repository);
    expect(javaPathRecords(inventory)).toHaveLength(3);
    const pathSpecialized = javaPathGetFileNameRecords(inventory);
    expect(pathSpecialized).toHaveLength(2);
    expect(pathSpecialized.map(({ path }) => path)).toEqual(
      expect.arrayContaining([
        "app/src/main/java/example/AppController.java",
        "included/src/main/java/composite/IncludedController.java",
      ]),
    );
    expect(
      pathSpecialized.flatMap(
        (record) => record.frameworkModel?.candidateControls ?? [],
      ),
    ).toContainEqual({
      kind: "incomplete-java-nio-path-getfilename-reduction",
      path: "app/src/main/java/example/PathNames.java",
      line: 6,
    });
    expect(
      pathSpecialized.flatMap(
        (record) => record.frameworkModel?.candidateControls ?? [],
      ),
    ).toContainEqual({
      kind: "incomplete-java-nio-path-getfilename-reduction",
      path: "included/src/main/java/composite/PathNames.java",
      line: 5,
    });
    expect(javaFileGetNameRecords(inventory)).toHaveLength(0);
  });

  test("follows only literal compile-time Gradle project dependencies for Java basename helpers", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "settings.gradle.kts",
      `rootProject.name = "basename-dependencies"
include("app", "api-app", "compile-only-app", "compile-only-api-app", "shared", "groovy-app", "libraries:filelib", "ambiguous-app", "duplicate", "nonstandard-app", "nonstandard-lib", "undeclared", "wrong-direction", "test-only", "runtime-only", "dynamic", "empty")
`,
    );
    const builds = new Map<string, string>([
      [
        "app/build.gradle.kts",
        `plugins { java }
dependencies {
  implementation(project(":shared"))
}
`,
      ],
      [
        "api-app/build.gradle.kts",
        `plugins { \`java-library\` }
dependencies {
  api(project(":shared"))
}
`,
      ],
      [
        "compile-only-app/build.gradle",
        `plugins { id 'java' }
dependencies {
  compileOnly project(':shared')
}
`,
      ],
      [
        "compile-only-api-app/build.gradle.kts",
        `plugins { \`java-library\` }
dependencies {
  compileOnlyApi(project(":shared"))
}
`,
      ],
      [
        "groovy-app/build.gradle",
        `plugins { id 'java' }
dependencies {
  implementation project(':libraries:filelib')
}
`,
      ],
      [
        "shared/build.gradle.kts",
        `plugins { java }
dependencies {
  implementation(project(":wrong-direction"))
}
`,
      ],
      ["libraries/filelib/build.gradle", "plugins { id 'java' }\n"],
      [
        "ambiguous-app/build.gradle.kts",
        `plugins { java }
dependencies {
  implementation(project(":shared"))
  implementation(project(":duplicate"))
}
`,
      ],
      ["duplicate/build.gradle.kts", "plugins { java }\n"],
      [
        "nonstandard-app/build.gradle.kts",
        `plugins { java }
dependencies {
  implementation(project(":nonstandard-lib"))
}
`,
      ],
      ["nonstandard-lib/build.gradle.kts", "plugins { java }\n"],
      ["undeclared/build.gradle.kts", "plugins { java }\n"],
      ["wrong-direction/build.gradle.kts", "plugins { java }\n"],
      [
        "test-only/build.gradle.kts",
        `plugins { java }
dependencies {
  testImplementation(project(":shared"))
}
`,
      ],
      [
        "runtime-only/build.gradle",
        `plugins { id 'java' }
dependencies {
  runtimeOnly project(':shared')
}
`,
      ],
      [
        "dynamic/build.gradle.kts",
        `plugins { java }
val helperProject = ":shared"
dependencies {
  implementation(project(helperProject))
}
`,
      ],
    ]);
    for (const [path, contents] of builds) {
      await writeRepositoryFile(repository, path, contents);
    }
    await writeRepositoryFile(
      repository,
      "shared/src/main/java/shared/names/PathNames.java",
      `
package shared.names;
public final class PathNames {
  public static java.nio.file.Path basename(String input) {
    return java.nio.file.Path.of(input).getFileName();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "libraries/filelib/src/main/java/filelib/names/FileNames.java",
      `
package filelib.names;
public final class FileNames {
  public static String basename(String input) {
    return new java.io.File(input).getName();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "duplicate/src/main/java/shared/names/PathNames.java",
      `
package shared.names;
public final class PathNames {
  public static java.nio.file.Path basename(String input) {
    return java.nio.file.Path.of(input).getFileName();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "nonstandard-lib/code/relocated/names/PathNames.java",
      `
package relocated.names;
public final class PathNames {
  public static java.nio.file.Path basename(String input) {
    return java.nio.file.Path.of(input).getFileName();
  }
}
`,
    );
    const pathController = (className: string): string => `
package consumer;
import shared.names.PathNames;
public final class ${className} {
  public String read(@RequestParam String path) throws Exception {
    java.nio.file.Path name = PathNames.basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`;
    for (const [module, className] of [
      ["app", "DeclaredController"],
      ["api-app", "ApiController"],
      ["compile-only-app", "CompileOnlyController"],
      ["compile-only-api-app", "CompileOnlyApiController"],
      ["ambiguous-app", "AmbiguousController"],
      ["undeclared", "UndeclaredController"],
      ["wrong-direction", "WrongDirectionController"],
      ["test-only", "TestOnlyController"],
      ["runtime-only", "RuntimeOnlyController"],
      ["dynamic", "DynamicController"],
    ] as const) {
      await writeRepositoryFile(
        repository,
        `${module}/src/main/java/consumer/${className}.java`,
        pathController(className),
      );
    }
    await writeRepositoryFile(
      repository,
      "groovy-app/src/main/java/consumer/GroovyDeclaredController.java",
      `
package consumer;
import filelib.names.FileNames;
public final class GroovyDeclaredController {
  public String read(@RequestParam String path) throws Exception {
    String name = FileNames.basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "nonstandard-app/src/main/java/consumer/NonstandardSourceController.java",
      `
package consumer;
import relocated.names.PathNames;
public final class NonstandardSourceController {
  public String read(@RequestParam String path) throws Exception {
    java.nio.file.Path name = PathNames.basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "custom/settings.gradle.kts",
      `include("app", "shared")
project(":shared").projectDir = file("renamed-shared")
`,
    );
    await writeRepositoryFile(
      repository,
      "custom/app/build.gradle.kts",
      `plugins { java }
dependencies {
  implementation(project(":shared"))
}
`,
    );
    await writeRepositoryFile(
      repository,
      "custom/renamed-shared/build.gradle.kts",
      "plugins { java }\n",
    );
    await writeRepositoryFile(
      repository,
      "custom/renamed-shared/src/main/java/custom/names/PathNames.java",
      `
package custom.names;
public final class PathNames {
  public static java.nio.file.Path basename(String input) {
    return java.nio.file.Path.of(input).getFileName();
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "custom/app/src/main/java/consumer/CustomLayoutController.java",
      `
package consumer;
import custom.names.PathNames;
public final class CustomLayoutController {
  public String read(@RequestParam String path) throws Exception {
    java.nio.file.Path name = PathNames.basename(path);
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(name));
  }
}
`,
    );

    const inventory = await buildResidualRiskInventory(repository);
    expect(javaPathRecords(inventory)).toHaveLength(13);
    expect(
      javaPathGetFileNameRecords(inventory)
        .map(({ path }) => path)
        .sort(),
    ).toEqual([
      "api-app/src/main/java/consumer/ApiController.java",
      "app/src/main/java/consumer/DeclaredController.java",
      "compile-only-api-app/src/main/java/consumer/CompileOnlyApiController.java",
      "compile-only-app/src/main/java/consumer/CompileOnlyController.java",
    ]);
    expect(javaFileGetNameRecords(inventory).map(({ path }) => path)).toEqual([
      "groovy-app/src/main/java/consumer/GroovyDeclaredController.java",
    ]);
  });

  test("rejects ambiguous or transformed Path basename helpers", async () => {
    const repository = await temporaryRepository();
    const controller = (
      className: string,
      helpers: string,
      call: string,
    ): string => `
import java.nio.file.Files;
import java.nio.file.Path;
public final class ${className} {
${helpers}
  public String read(@RequestParam String path) throws Exception {
    Path name = ${call};
    return Files.readString(Path.of("documents").resolve(name));
  }
}
`;
    await writeRepositoryFile(
      repository,
      "src/OverloadedHelperController.java",
      controller(
        "OverloadedHelperController",
        `  private static Path basename(String input) { return Path.of(input).getFileName(); }
  private static Path basename(Path input) { return input.getFileName(); }`,
        "basename(path)",
      ),
    );
    await writeRepositoryFile(
      repository,
      "src/BranchHelperController.java",
      controller(
        "BranchHelperController",
        `  private static Path basename(String input) {
    if (input.isEmpty()) return Path.of("guide");
    return Path.of(input).getFileName();
  }`,
        "basename(path)",
      ),
    );
    await writeRepositoryFile(
      repository,
      "src/TransformedHelperController.java",
      controller(
        "TransformedHelperController",
        `  private static Path basename(String input) {
    return Path.of(input + ".txt").getFileName();
  }`,
        "basename(path)",
      ),
    );
    await writeRepositoryFile(
      repository,
      "src/TransformedCallController.java",
      controller(
        "TransformedCallController",
        `  private static Path basename(String input) {
    return Path.of(input).getFileName();
  }`,
        'basename("prefix/" + path)',
      ),
    );
    await writeRepositoryFile(
      repository,
      "src/ReassignedHelperController.java",
      controller(
        "ReassignedHelperController",
        `  private static Path basename(String input) {
    input = "guide";
    return Path.of(input).getFileName();
  }`,
        "basename(path)",
      ),
    );
    await writeRepositoryFile(
      repository,
      "src/NestedHelperController.java",
      controller(
        "NestedHelperController",
        `  private static Path reduce(String input) { return Path.of(input).getFileName(); }
  private static Path basename(String input) { return reduce(input); }`,
        "basename(path)",
      ),
    );
    await writeRepositoryFile(
      repository,
      "src/ForeignReceiverController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
final class Reducer {
  Path basename(String input) { return Path.of(input).getFileName(); }
}
public final class ForeignReceiverController {
  private final Reducer reducer = new Reducer();
  public String read(@RequestParam String path) throws Exception {
    Path name = reducer.basename(path);
    return Files.readString(Path.of("documents").resolve(name));
  }
}
`,
    );

    const inventory = await buildResidualRiskInventory(repository);
    expect(javaPathRecords(inventory)).toHaveLength(7);
    expect(javaPathGetFileNameRecords(inventory)).toEqual([]);
  });

  test("resolves same-package Path and Paths shadows under Java import precedence", async () => {
    const repository = await temporaryRepository();
    await writeRepositoryFile(
      repository,
      "exact/example/Path.java",
      `package exact.example; final class Path {}`,
    );
    await writeRepositoryFile(
      repository,
      "exact/example/ExactImportController.java",
      `
package exact.example;
import java.nio.file.Files;
import java.nio.file.Path;
public final class ExactImportController {
  public String read(@RequestParam String path) throws Exception {
    Path basename = Path.of(path).getFileName();
    return Files.readString(Path.of("documents").resolve(basename));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "wildcard/example/Path.java",
      `
package wildcard.example;
final class Path {
  static Path of(String value) { return new Path(); }
  Path getFileName() { return this; }
  java.nio.file.Path toOfficial() { return java.nio.file.Path.of("guide"); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "wildcard/example/WildcardController.java",
      `
package wildcard.example;
import java.nio.file.*;
public final class WildcardController {
  public String read(@RequestParam String path) throws Exception {
    Path basename = Path.of(path).getFileName();
    return Files.readString(java.nio.file.Path.of("documents").resolve(basename.toOfficial()));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "wildcardpaths/example/Paths.java",
      `
package wildcardpaths.example;
final class Paths {
  static java.nio.file.Path get(String value) { return java.nio.file.Path.of("guide"); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "wildcardpaths/example/WildcardPathsController.java",
      `
package wildcardpaths.example;
import java.nio.file.*;
public final class WildcardPathsController {
  public String read(@RequestParam String path) throws Exception {
    Path basename = Paths.get(path).getFileName();
    return Files.readString(Path.of("documents").resolve(basename));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "nested/example/Holder.java",
      `package nested.example; final class Holder { static final class Path {} }`,
    );
    await writeRepositoryFile(
      repository,
      "nested/example/NestedController.java",
      `
package nested.example;
import java.nio.file.*;
public final class NestedController {
  public String read(@RequestParam String path) throws Exception {
    Path basename = Path.of(path).getFileName();
    return Files.readString(Path.of("documents").resolve(basename));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "other/shadow/Path.java",
      `package other.shadow; final class Path {}`,
    );
    await writeRepositoryFile(
      repository,
      "different/example/DifferentPackageController.java",
      `
package different.example;
import java.nio.file.*;
public final class DifferentPackageController {
  public String read(@RequestParam String path) throws Exception {
    Path basename = Path.of(path).getFileName();
    return Files.readString(Path.of("documents").resolve(basename));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "qualified/example/Path.java",
      `package qualified.example; final class Path {}`,
    );
    await writeRepositoryFile(
      repository,
      "qualified/example/QualifiedController.java",
      `
package qualified.example;
public final class QualifiedController {
  public String read(@RequestParam String path) throws Exception {
    java.nio.file.Path basename = java.nio.file.Path.of(path).getFileName();
    return java.nio.file.Files.readString(java.nio.file.Path.of("documents").resolve(basename));
  }
}
`,
    );

    const inventory = await buildResidualRiskInventory(repository);
    expect(javaPathRecords(inventory)).toHaveLength(6);
    expect(
      javaPathGetFileNameRecords(inventory).map((record) => record.path),
    ).toEqual([
      "different/example/DifferentPackageController.java",
      "exact/example/ExactImportController.java",
      "nested/example/NestedController.java",
      "qualified/example/QualifiedController.java",
    ]);
  });

  test("accepts exact static Path factories and rejects local or ambiguous owners", async () => {
    const repository = await temporaryRepository();
    const staticController = (
      packageName: string,
      staticImport: string,
      factory: string,
      guard = "",
    ): string => `
package ${packageName};
import java.nio.file.Files;
${staticImport}
public final class StaticController {
  public String read(@RequestParam String path) throws Exception {
    var basename = ${factory}(path).getFileName();
${guard}
    return Files.readString(java.nio.file.Path.of("documents").resolve(basename));
  }
}
`;
    await writeRepositoryFile(
      repository,
      "staticof/exact/StaticController.java",
      staticController(
        "staticof.exact",
        "import static java.nio.file.Path.of;",
        "of",
        `    if (basename.equals(of(".."))) throw new SecurityException("parent");`,
      ),
    );
    await writeRepositoryFile(
      repository,
      "staticof/wildcard/StaticController.java",
      staticController(
        "staticof.wildcard",
        "import static java.nio.file.Path.*;",
        "of",
      ),
    );
    await writeRepositoryFile(
      repository,
      "staticget/exact/StaticController.java",
      staticController(
        "staticget.exact",
        "import static java.nio.file.Paths.get;",
        "get",
      ),
    );
    await writeRepositoryFile(
      repository,
      "staticget/wildcard/StaticController.java",
      staticController(
        "staticget.wildcard",
        "import static java.nio.file.Paths.*;",
        "get",
      ),
    );
    await writeRepositoryFile(
      repository,
      "shadow/local/StaticController.java",
      `
package shadow.local;
import java.nio.file.Files;
import java.nio.file.Path;
import static java.nio.file.Path.of;
public final class StaticController {
  private static Path of(String ignored) { return Path.of("guide"); }
  public String read(@RequestParam String path) throws Exception {
    Path basename = of(path).getFileName();
    return Files.readString(Path.of("documents").resolve(basename));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "shadow/qualified/StaticController.java",
      `
package shadow.qualified;
import java.nio.file.Files;
import static java.nio.file.Path.of;
final class Evil { static java.nio.file.Path of(String value) { return java.nio.file.Path.of("guide"); } }
public final class StaticController {
  public String read(@RequestParam String path) throws Exception {
    var basename = Evil.of(path).getFileName();
    return Files.readString(java.nio.file.Path.of("documents").resolve(basename));
  }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "shadow/ambiguous/Factory.java",
      `
package shadow.ambiguous;
public final class Factory {
  public static java.nio.file.Path of(String value) { return java.nio.file.Path.of("guide"); }
}
`,
    );
    await writeRepositoryFile(
      repository,
      "shadow/ambiguous/StaticController.java",
      `
package shadow.ambiguous;
import java.nio.file.Files;
import static java.nio.file.Path.*;
import static shadow.ambiguous.Factory.*;
public final class StaticController {
  public String read(@RequestParam String path) throws Exception {
    var basename = of(path).getFileName();
    return Files.readString(java.nio.file.Path.of("documents").resolve(basename));
  }
}
`,
    );

    const inventory = await buildResidualRiskInventory(repository);
    expect(javaPathRecords(inventory)).toHaveLength(7);
    const specialized = javaPathGetFileNameRecords(inventory);
    expect(specialized.map((record) => record.path)).toEqual([
      "staticget/exact/StaticController.java",
      "staticget/wildcard/StaticController.java",
      "staticof/exact/StaticController.java",
      "staticof/wildcard/StaticController.java",
    ]);
    expect(
      specialized
        .find(
          (record) => record.path === "staticof/exact/StaticController.java",
        )
        ?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toContain("parent-path-component-rejection");
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

  test("credits only branch-local dominating Path parent rejection", async () => {
    const repository = await temporaryRepository();
    const controller = (guard: string): string => `
import java.nio.file.Files;
import java.nio.file.Path;
public final class DocumentController {
  private static void audit() {}
  public String read(@RequestParam String path) throws Exception {
    Path basename = Path.of(path).getFileName();
    boolean strict = System.nanoTime() > 0;
${guard}
    return Files.readString(Path.of("documents").resolve(basename));
  }
}
`;
    const cases = new Map<string, { guard: string; controlled: boolean }>([
      [
        "dominant/DocumentController.java",
        {
          guard: `    if (Path.of("..").equals(basename)) {
      audit();
      throw new SecurityException("parent");
    }`,
          controlled: true,
        },
      ],
      [
        "negated/DocumentController.java",
        {
          guard: `    if (!Path.of("..").equals(basename)) {
      throw new SecurityException("not parent");
    }`,
          controlled: false,
        },
      ],
      [
        "conjoined/DocumentController.java",
        {
          guard: `    if (Path.of("..").equals(basename) && strict) {
      throw new SecurityException("conditional parent");
    }`,
          controlled: false,
        },
      ],
      [
        "nearby/DocumentController.java",
        {
          guard: `    if (Path.of("..").equals(basename)) {
      audit();
    }
    if (strict) throw new SecurityException("unrelated");`,
          controlled: false,
        },
      ],
      [
        "nested/DocumentController.java",
        {
          guard: `    if (strict) {
      if (Path.of("..").equals(basename)) {
        throw new SecurityException("optional parent");
      }
    }`,
          controlled: false,
        },
      ],
      [
        "caught/DocumentController.java",
        {
          guard: `    try {
      if (Path.of("..").equals(basename)) {
        throw new SecurityException("caught parent");
      }
    } catch (SecurityException ignored) {
      audit();
    }`,
          controlled: false,
        },
      ],
    ]);
    for (const [path, { guard }] of cases) {
      await writeRepositoryFile(repository, path, controller(guard));
    }
    const longSwitchSelector = Array.from({ length: 220 }, () => "+ 0").join(
      " ",
    );
    await writeRepositoryFile(
      repository,
      "switch-case/DocumentController.java",
      `
import java.nio.file.Files;
import java.nio.file.Path;
public final class DocumentController {
  public String read(@RequestParam String path) throws Exception {
    Path basename = Path.of(path).getFileName();
    switch (path.length() ${longSwitchSelector}) {
      case 1:
        if (Path.of("..").equals(basename)) {
          throw new SecurityException("different case");
        }
        return "short";
      default:
        return Files.readString(Path.of("documents").resolve(basename));
    }
  }
}
`,
    );

    const specialized = javaPathGetFileNameRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(specialized).toHaveLength(cases.size + 1);
    const controls = new Map(
      specialized.map((record) => [
        record.path,
        record.frameworkModel?.candidateControls.map(({ kind }) => kind),
      ]),
    );
    for (const [path, { controlled }] of cases) {
      expect(
        controls.get(path)?.includes("parent-path-component-rejection"),
      ).toBe(controlled);
    }
    expect(
      controls
        .get("switch-case/DocumentController.java")
        ?.includes("parent-path-component-rejection"),
    ).toBeFalse();
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

  test("credits only branch-local dominating File parent rejection", async () => {
    const repository = await temporaryRepository();
    const controller = (guard: string): string => `
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
public final class DocumentController {
  private static void audit() {}
  public String read(@RequestParam String path) throws Exception {
    String basename = new File(path).getName();
    boolean strict = System.nanoTime() > 0;
${guard}
    return Files.readString(Path.of("documents").resolve(basename));
  }
}
`;
    const cases = new Map<string, { guard: string; controlled: boolean }>([
      [
        "dominant-file/DocumentController.java",
        {
          guard: `    if ("..".equals(basename)) {
      audit();
      return "rejected";
    }`,
          controlled: true,
        },
      ],
      [
        "negated-file/DocumentController.java",
        {
          guard: `    if (!"..".equals(basename)) {
      throw new SecurityException("not parent");
    }`,
          controlled: false,
        },
      ],
      [
        "nearby-file/DocumentController.java",
        {
          guard: `    if ("..".equals(basename)) audit();
    if (strict) throw new SecurityException("unrelated");`,
          controlled: false,
        },
      ],
      [
        "nested-file/DocumentController.java",
        {
          guard: `    if (strict) {
      if ("..".equals(basename)) throw new SecurityException("optional parent");
    }`,
          controlled: false,
        },
      ],
    ]);
    for (const [path, { guard }] of cases) {
      await writeRepositoryFile(repository, path, controller(guard));
    }

    const specialized = javaFileGetNameRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(specialized).toHaveLength(cases.size);
    const controls = new Map(
      specialized.map((record) => [
        record.path,
        record.frameworkModel?.candidateControls.map(({ kind }) => kind),
      ]),
    );
    for (const [path, { controlled }] of cases) {
      expect(
        controls.get(path)?.includes("parent-path-component-rejection"),
      ).toBe(controlled);
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
    expect(prompt).toContain(
      "Exact single-type imports remain authoritative over another top-level Path or Paths in the same package",
    );
    expect(prompt).toContain(
      "Exact or wildcard static imports of Path.of and Paths.get are eligible only without a local method declaration",
    );
    expect(prompt).toContain(
      "A cross-file call must remain in the nearest Maven or Gradle project or module",
    );
    expect(prompt).toContain(
      "resolve exactly one top-level helper owner through the same package, one exact single-type import, or its fully qualified name",
    );
    expect(prompt).toContain(
      "The reduction evidence belongs to the helper file",
    );
    expect(prompt).toContain(
      "an undeclared sibling module is not a source of helper code",
    );
    expect(prompt).toContain(
      "a direct literal api, implementation, compileOnly, or compileOnlyApi project dependency",
    );
    expect(prompt).toContain("dependency direction matters");
    expect(prompt).toContain(
      "Do not infer test or runtime-only configurations, transitive reachability, variables, nonstandard production source sets, custom project mappings, composite builds, or ambiguous ownership",
    );
    expect(prompt).toContain(
      "the exact equality is not negated or conditionally conjoined",
    );
    expect(prompt).toContain(
      "the abrupt completion is not caught before the sink",
    );
    expect(prompt).toContain("an unrelated nearby return or throw");
    expect(prompt).toContain("A check on another reduction");
    expect(prompt).toContain("a check after the operation is insufficient");
  });
});
