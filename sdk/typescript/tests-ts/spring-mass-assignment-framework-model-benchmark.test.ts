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
  "java-cross-file-mass-assignment",
  "java-cross-file-safe-binding",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function records(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord);
}

function massAssignmentRecords(inventory: string): FrameworkRecord[] {
  return records(inventory).filter(
    (record) => record.frameworkModel?.id === "spring-mvc-jpa-mass-assignment",
  );
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function temporaryRepository(
  files: Readonly<Record<string, string>>,
): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-spring-mass-assignment-"),
  );
  temporaryPaths.push(repository);
  const withProject = { "pom.xml": "<project />", ...files };
  for (const [relativePath, contents] of Object.entries(withProject)) {
    const path = join(repository, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents);
  }
  return repository;
}

const entitySource = `
package example;
import jakarta.persistence.Entity;
@Entity
public class Account {
  public String displayName;
  public boolean administrator;
}
`;

const repositorySource = `
package example;
import org.springframework.data.jpa.repository.JpaRepository;
public interface AccountRepository extends JpaRepository<Account, Long> {}
`;

const serviceSource = `
package example;
import org.springframework.stereotype.Service;
@Service
public class AccountService {
  private final AccountRepository repository;
  public AccountService(AccountRepository repository) { this.repository = repository; }
  public Account create(Account account) {
    return repository.save(account);
  }
}
`;

function controllerSource(
  options: {
    parameter?: string;
    mapping?: string;
    prelude?: string;
    body?: string;
  } = {},
): string {
  return `
package example;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.${options.mapping ?? "PostMapping"};
import org.springframework.web.bind.annotation.RestController;
@RestController
public class AccountController {
  private final AccountService accounts;
  public AccountController(AccountService accounts) { this.accounts = accounts; }
  ${options.prelude ?? ""}
  @${options.mapping ?? "PostMapping"}("/accounts")
  public Account create(${options.parameter ?? "@ModelAttribute Account account"}) {
    ${options.body ?? "return accounts.create(account);"}
  }
}
`;
}

async function modeledRepository(
  controller: string,
  extra: Readonly<Record<string, string>> = {},
): Promise<FrameworkRecord[]> {
  const repository = await temporaryRepository({
    "src/Account.java": entitySource,
    "src/AccountRepository.java": repositorySource,
    "src/AccountService.java": serviceSource,
    "src/AccountController.java": controller,
    ...extra,
  });
  return massAssignmentRecords(await buildResidualRiskInventory(repository));
}

describe("Spring MVC JPA mass-assignment framework-model benchmark", () => {
  test("keeps the real exploit and protected twin under strict benchmark gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "spring-mass-assignment-manifest.json"),
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
      cwe: ["CWE-915"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
    for (const id of caseIds) {
      const pom = await readFile(
        join(benchmarkRoot, "fixtures", id, "pom.xml"),
        "utf8",
      );
      expect(pom).toContain("<version>4.1.0</version>");
      expect(pom).toContain("<artifactId>spring-boot-webmvc-test</artifactId>");
    }
  });

  test("preserves the exact typed controller-to-service save path and binder control", async () => {
    const vulnerable = massAssignmentRecords(
      await fixtureInventory(caseIds[0]),
    );
    const safe = massAssignmentRecords(await fixtureInventory(caseIds[1]));

    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toEqual({
      schemaVersion: "1.2",
      id: "spring-mvc-jpa-mass-assignment",
      language: "java-kotlin",
      scope: "cross-file-wrapper",
      source: {
        kind: "spring-bound-domain-object",
        path: "src/main/java/example/AccountController.java",
        line: 16,
      },
      sink: {
        kind: "jpa-bound-entity-save",
        path: "src/main/java/example/AccountService.java",
        line: 14,
        cweIds: ["CWE-915"],
      },
      propagators: [
        {
          kind: "java-type-binding",
          path: "src/main/java/example/AccountController.java",
          line: 9,
          symbol: "accounts:AccountService",
        },
        {
          kind: "wrapper-call-argument",
          path: "src/main/java/example/AccountController.java",
          line: 17,
          symbol: "accounts.create[0]",
        },
        {
          kind: "wrapper-parameter",
          path: "src/main/java/example/AccountService.java",
          line: 13,
          symbol: "account",
        },
      ],
      candidateControls: [],
    });
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual([
      {
        kind: "explicit-binding-allowlist",
        path: "src/main/java/example/AccountController.java",
        line: 19,
      },
    ]);
  });

  test("models same-file fully-qualified binding and persistence types", async () => {
    const repository = await temporaryRepository({
      "src/AccountController.java": `
package example;
@jakarta.persistence.Entity
class Account { public boolean administrator; }
@org.springframework.web.bind.annotation.RestController
public class AccountController {
  private final org.springframework.data.repository.CrudRepository<Account, Long> repository;
  AccountController(org.springframework.data.repository.CrudRepository<Account, Long> repository) {
    this.repository = repository;
  }
  @org.springframework.web.bind.annotation.PostMapping("/accounts")
  public Account create(
      @org.springframework.web.bind.annotation.ModelAttribute Account account) {
    return repository.save(account);
  }
}
`,
    });
    const found = massAssignmentRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      scope: "same-file",
      source: { kind: "spring-bound-domain-object" },
      sink: { kind: "jpa-bound-entity-save", cweIds: ["CWE-915"] },
    });
  });

  test("follows a bounded two-service typed relay", async () => {
    const found = await modeledRepository(
      controllerSource({ body: "return accounts.create(account);" }),
      {
        "src/AccountService.java": `
package example;
import org.springframework.stereotype.Service;
@Service
public class AccountService {
  private final AccountWriter writer;
  public AccountService(AccountWriter writer) { this.writer = writer; }
  public Account create(Account account) { return writer.persist(account); }
}
`,
        "src/AccountWriter.java": `
package example;
import org.springframework.stereotype.Service;
@Service
public class AccountWriter {
  private final AccountRepository repository;
  public AccountWriter(AccountRepository repository) { this.repository = repository; }
  public Account persist(Account account) { return repository.save(account); }
}
`,
      },
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel?.scope).toBe(
      "cross-file-multi-hop-wrapper",
    );
    expect(
      found[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "java-type-binding",
      "wrapper-call-argument",
      "wrapper-parameter",
      "java-type-binding",
      "wrapper-call-argument",
      "wrapper-parameter",
    ]);
  });

  test("recognizes exact allowlist and constructor-only controls but not denylists", async () => {
    const allowed = await modeledRepository(
      controllerSource({
        prelude: `
  @InitBinder("account")
  void bind(WebDataBinder binder) { binder.setAllowedFields("displayName"); }`,
      }),
    );
    expect(allowed[0]?.frameworkModel?.candidateControls).toEqual([
      expect.objectContaining({ kind: "explicit-binding-allowlist" }),
    ]);

    const declarative = await modeledRepository(
      controllerSource({
        parameter: '@ModelAttribute("account") example.Account account',
        prelude: `
  @org.springframework.web.bind.annotation.InitBinder("account")
  void bind(org.springframework.web.bind.WebDataBinder binder) {
    binder.setDeclarativeBinding(true);
  }`,
      }),
    );
    expect(declarative[0]?.frameworkModel?.candidateControls).toEqual([
      expect.objectContaining({ kind: "constructor-only-binding" }),
    ]);

    const denied = await modeledRepository(
      controllerSource({
        prelude: `
  @InitBinder("account")
  void bind(WebDataBinder binder) { binder.setDisallowedFields("administrator"); }`,
      }),
    );
    expect(denied[0]?.frameworkModel?.candidateControls).toEqual([]);

    const wrongAttribute = await modeledRepository(
      controllerSource({
        prelude: `
  @InitBinder("profile")
  void bind(WebDataBinder binder) { binder.setAllowedFields("displayName"); }`,
      }),
    );
    expect(wrongAttribute[0]?.frameworkModel?.candidateControls).toEqual([]);

    const multilineWrongAttribute = await modeledRepository(
      controllerSource({
        prelude: `
  @InitBinder(
      "profile")
  void bind(WebDataBinder binder) { binder.setAllowedFields("displayName"); }`,
      }),
    );
    expect(
      multilineWrongAttribute[0]?.frameworkModel?.candidateControls,
    ).toEqual([]);
  });

  test("rejects disabled binding, read handlers, DTO projection, and replaced values", async () => {
    const disabled = await modeledRepository(
      controllerSource({
        parameter: "@ModelAttribute(binding = false) Account account",
      }),
    );
    expect(disabled).toEqual([]);

    const getOnly = await modeledRepository(
      controllerSource({ mapping: "GetMapping" }),
    );
    expect(getOnly).toEqual([]);

    const dto = await modeledRepository(
      controllerSource({
        parameter: "@ModelAttribute AccountForm account",
        body: `Account entity = new Account();
    entity.displayName = account.displayName;
    return accounts.create(entity);`,
      }),
      {
        "src/AccountForm.java":
          "package example; public class AccountForm { public String displayName; }",
      },
    );
    expect(dto).toEqual([]);

    const replaced = await modeledRepository(
      controllerSource({
        body: "account = new Account(); return accounts.create(account);",
      }),
    );
    expect(replaced).toEqual([]);

    const annotationFromPreviousMethod = await modeledRepository(`
package example;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
public class AccountController {
  private final AccountService accounts;
  public AccountController(AccountService accounts) { this.accounts = accounts; }
  @PostMapping("/preview")
  public Account preview(@ModelAttribute Account preview) { return preview; }
  public Account create(@ModelAttribute Account account) {
    return accounts.create(account);
  }
}
`);
    expect(annotationFromPreviousMethod).toEqual([]);
  });

  test("rejects local framework, persistence, and repository shadows", async () => {
    const localAnnotations = await temporaryRepository({
      "src/Everything.java": `
package example;
@interface Entity {}
@interface RestController {}
@interface PostMapping { String value(); }
@interface ModelAttribute {}
interface JpaRepository<T, K> { T save(T value); }
@Entity class Account { public boolean administrator; }
@RestController class AccountController {
  JpaRepository<Account, Long> repository;
  @PostMapping("/accounts") Account create(@ModelAttribute Account account) {
    return repository.save(account);
  }
}
`,
    });
    expect(
      massAssignmentRecords(await buildResidualRiskInventory(localAnnotations)),
    ).toEqual([]);

    const repositoryShadow = await modeledRepository(controllerSource(), {
      "src/AccountRepository.java": `
package example;
public interface AccountRepository extends JpaRepository<Account, Long> {}
interface JpaRepository<T, K> { T save(T value); }
`,
    });
    expect(repositoryShadow).toEqual([]);
  });

  test("rejects domain mismatches, missing entities, and ambiguous typed services", async () => {
    const mismatch = await modeledRepository(controllerSource(), {
      "src/AccountRepository.java": `
package example;
import org.springframework.data.jpa.repository.JpaRepository;
public interface AccountRepository extends JpaRepository<Profile, Long> {}
`,
      "src/Profile.java":
        "package example; import jakarta.persistence.Entity; @Entity public class Profile {}",
    });
    expect(mismatch).toEqual([]);

    const noEntity = await modeledRepository(controllerSource(), {
      "src/Account.java":
        "package example; public class Account { public boolean administrator; }",
    });
    expect(noEntity).toEqual([]);

    const duplicateService = await modeledRepository(controllerSource(), {
      "other/AccountService.java": serviceSource.replace(
        "package example;",
        "package duplicate;",
      ),
    });
    expect(duplicateService).toEqual([]);
  });

  test("teaches property authorization and exact binder applicability", () => {
    const prompt = scanQualityGatePrompt("scan", "/repo", "inventory-row", "");
    expect(prompt).toContain("spring-mvc-jpa-mass-assignment");
    expect(prompt).toContain("administrator or role state");
    expect(prompt).toContain("dedicated request DTO");
    expect(prompt).toContain("setDisallowedFields is fragile");
    expect(prompt).toContain("@ModelAttribute(binding=false)");
    expect(prompt).toContain("exact @InitBinder/WebDataBinder allowed-fields");
  });
});
