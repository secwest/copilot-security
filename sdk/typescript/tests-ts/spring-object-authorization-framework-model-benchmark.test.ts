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
  "java-cross-file-idor",
  "java-cross-file-safe-authorization",
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

function authorizationRecords(inventory: string): FrameworkRecord[] {
  return records(inventory).filter(
    (record) =>
      record.frameworkModel?.id === "spring-http-object-authorization",
  );
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

async function temporaryRepository(
  files: Readonly<Record<string, string>>,
): Promise<string> {
  const repository = await mkdtemp(
    join(tmpdir(), "copilot-security-spring-authorization-"),
  );
  temporaryPaths.push(repository);
  for (const [relativePath, contents] of Object.entries(files)) {
    const path = join(repository, relativePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, contents);
  }
  return repository;
}

const repositorySource = `
package example;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
public interface InvoiceRepository extends JpaRepository<Invoice, Long> {
  Optional<Invoice> findByIdAndCustomerId(Long invoiceId, String customerId);
}
`;

const controllerSource = `
package example;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
@RestController
public class InvoiceController {
  private final InvoiceService invoices;
  public InvoiceController(InvoiceService invoices) { this.invoices = invoices; }
  public Invoice get(
      @PathVariable long invoiceId,
      Authentication authentication) {
    return invoices.load(invoiceId, authentication);
  }
}
`;

describe("Spring object-authorization framework-model effectiveness benchmark", () => {
  test("keeps the Spring Data exploit and principal-bound control under strict gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "spring-object-authorization-manifest.json"),
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
      cwe: ["CWE-639", "CWE-862"],
      acceptableSeverities: ["high", "medium"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
    for (const id of caseIds) {
      expect(
        await readFile(join(benchmarkRoot, "fixtures", id, "pom.xml"), "utf8"),
      ).toContain("<version>4.1.0</version>");
    }
  });

  test("preserves the exact typed controller-to-service lookup and query control", async () => {
    const vulnerable = authorizationRecords(await fixtureInventory(caseIds[0]));
    const safe = authorizationRecords(await fixtureInventory(caseIds[1]));

    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toEqual({
      schemaVersion: "1.2",
      id: "spring-http-object-authorization",
      language: "java-kotlin",
      scope: "cross-file-wrapper",
      source: {
        kind: "spring-object-reference",
        path: "src/main/java/example/InvoiceController.java",
        line: 19,
      },
      sink: {
        kind: "spring-data-object-record-lookup",
        path: "src/main/java/example/InvoiceService.java",
        line: 14,
        cweIds: ["CWE-639", "CWE-862"],
      },
      propagators: [
        {
          kind: "java-type-binding",
          path: "src/main/java/example/InvoiceController.java",
          line: 11,
          symbol: "invoices:InvoiceService",
        },
        {
          kind: "wrapper-call-argument",
          path: "src/main/java/example/InvoiceController.java",
          line: 21,
          symbol: "invoices.loadInvoice[0]",
        },
        {
          kind: "wrapper-parameter",
          path: "src/main/java/example/InvoiceService.java",
          line: 13,
          symbol: "invoiceId",
        },
      ],
      candidateControls: [],
    });
    expect(safe).toHaveLength(1);
    expect(safe[0]?.frameworkModel?.candidateControls).toEqual([
      {
        kind: "principal-bound-object-query",
        line: 16,
        path: "src/main/java/example/InvoiceService.java",
      },
    ]);
  });

  test("retains PostAuthorize only for an active exact return-object read policy", async () => {
    const enabled = await temporaryRepository({
      "pom.xml": "<project />",
      "src/InvoiceController.java": controllerSource,
      "src/InvoiceRepository.java": repositorySource,
      "src/InvoiceService.java": `
package example;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
@Service
public class InvoiceService {
  private final InvoiceRepository repository;
  @PostAuthorize("returnObject.customerId == authentication.name")
  public Invoice load(long invoiceId, Authentication authentication) {
    return repository.findById(invoiceId).orElseThrow();
  }
}
`,
      "src/SecurityConfig.java": `
package example;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
@Configuration
@EnableMethodSecurity
public class SecurityConfig {}
`,
    });
    const found = authorizationRecords(
      await buildResidualRiskInventory(enabled),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel?.candidateControls).toEqual([
      {
        kind: "enabled-return-object-authorization",
        line: 9,
        path: "src/InvoiceService.java",
      },
    ]);

    const inactive = await temporaryRepository({
      "src/InvoiceController.java": controllerSource,
      "src/InvoiceRepository.java": repositorySource,
      "src/InvoiceService.java": `
package example;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
@Service
public class InvoiceService {
  private final InvoiceRepository repository;
  @PostAuthorize("returnObject.customerId == authentication.name")
  public Invoice load(long invoiceId, Authentication authentication) {
    return repository.findById(invoiceId).orElseThrow();
  }
}
`,
    });
    const inactiveRows = authorizationRecords(
      await buildResidualRiskInventory(inactive),
    );
    expect(inactiveRows).toHaveLength(1);
    expect(inactiveRows[0]?.frameworkModel?.candidateControls).toEqual([]);
  });

  test("rejects role-only, disabled, and post-write annotation controls", async () => {
    const repository = await temporaryRepository({
      "src/InvoiceController.java": controllerSource,
      "src/InvoiceRepository.java": repositorySource,
      "src/InvoiceService.java": `
package example;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
@Service
public class InvoiceService {
  private final InvoiceRepository repository;
  @PostAuthorize("hasRole('USER')")
  public Invoice load(long invoiceId, Authentication authentication) {
    var invoice = repository.findById(invoiceId).orElseThrow();
    repository.save(invoice);
    return invoice;
  }
}
`,
      "src/SecurityConfig.java": `
package example;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
@Configuration
@EnableMethodSecurity(prePostEnabled = false)
public class SecurityConfig {}
`,
    });
    const found = authorizationRecords(
      await buildResidualRiskInventory(repository),
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel?.candidateControls).toEqual([]);
  });

  test("rejects local method-security and stereotype annotation shadows", async () => {
    const localMethodSecurity = await temporaryRepository({
      "src/InvoiceController.java": controllerSource,
      "src/InvoiceRepository.java": repositorySource,
      "src/InvoiceService.java": `
package example;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
@Service
public class InvoiceService {
  private final InvoiceRepository repository;
  @PostAuthorize("returnObject.customerId == authentication.name")
  public Invoice load(long invoiceId, Authentication authentication) {
    return repository.findById(invoiceId).orElseThrow();
  }
}
`,
      "src/SecurityConfig.java": `
package example;
@EnableMethodSecurity
public class SecurityConfig {}
@interface EnableMethodSecurity {}
`,
    });
    const methodRows = authorizationRecords(
      await buildResidualRiskInventory(localMethodSecurity),
    );
    expect(methodRows).toHaveLength(1);
    expect(methodRows[0]?.frameworkModel?.candidateControls).toEqual([]);

    const localStereotype = await temporaryRepository({
      "src/InvoiceController.java": controllerSource,
      "src/InvoiceRepository.java": repositorySource,
      "src/InvoiceService.java": `
package example;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
@Component
public class InvoiceService {
  private final InvoiceRepository repository;
  @PostAuthorize("returnObject.customerId == authentication.name")
  public Invoice load(long invoiceId, Authentication authentication) {
    return repository.findById(invoiceId).orElseThrow();
  }
}
@interface Component {}
`,
      "src/SecurityConfig.java": `
package example;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
@EnableMethodSecurity
public class SecurityConfig {}
`,
    });
    const stereotypeRows = authorizationRecords(
      await buildResidualRiskInventory(localStereotype),
    );
    expect(stereotypeRows).toHaveLength(1);
    expect(stereotypeRows[0]?.frameworkModel?.candidateControls).toEqual([]);
  });

  test("accepts only a typed authenticated principal in the same derived query", async () => {
    const safe = await temporaryRepository({
      "src/InvoiceController.java": controllerSource,
      "src/InvoiceRepository.java": repositorySource,
      "src/InvoiceService.java": `
package example;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
@Service
public class InvoiceService {
  private final InvoiceRepository repository;
  public Invoice load(long invoiceId, Authentication authentication) {
    return repository.findByIdAndCustomerId(invoiceId, authentication.getName()).orElseThrow();
  }
}
`,
    });
    const safeRows = authorizationRecords(
      await buildResidualRiskInventory(safe),
    );
    expect(safeRows).toHaveLength(1);
    expect(safeRows[0]?.frameworkModel?.candidateControls).toHaveLength(1);

    const attackerOwner = await temporaryRepository({
      "src/InvoiceController.java": `
package example;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
@RestController
public class InvoiceController {
  private final InvoiceService invoices;
  public Invoice get(@PathVariable long invoiceId, @RequestParam String customerId) {
    return invoices.load(invoiceId, customerId);
  }
}
`,
      "src/InvoiceRepository.java": repositorySource,
      "src/InvoiceService.java": `
package example;
import org.springframework.stereotype.Service;
@Service
public class InvoiceService {
  private final InvoiceRepository repository;
  public Invoice load(long invoiceId, String customerId) {
    return repository.findByIdAndCustomerId(invoiceId, customerId).orElseThrow();
  }
}
`,
    });
    const attackerRows = authorizationRecords(
      await buildResidualRiskInventory(attackerOwner),
    );
    expect(attackerRows).toHaveLength(1);
    expect(attackerRows[0]?.frameworkModel?.candidateControls).toEqual([]);
  });

  test("rejects untyped repositories, fixed IDs, and reassigned route IDs", async () => {
    const reassigned = await temporaryRepository({
      "src/InvoiceController.java": `
package example;
import org.springframework.web.bind.annotation.PathVariable;
public class InvoiceController {
  private final InvoiceService invoices;
  public Invoice get(@PathVariable long invoiceId) {
    invoiceId = 42L;
    return invoices.load(invoiceId);
  }
}
`,
      "src/InvoiceService.java": `
package example;
public class InvoiceService {
  private final InvoiceStore repository;
  public Invoice load(long invoiceId) {
    return repository.findById(invoiceId);
  }
}
class InvoiceStore { Invoice findById(long id) { return null; } }
`,
    });
    expect(
      authorizationRecords(await buildResidualRiskInventory(reassigned)),
    ).toEqual([]);

    const fixed = await temporaryRepository({
      "src/InvoiceController.java": `
package example;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.web.bind.annotation.PathVariable;
public class InvoiceController {
  private final InvoiceRepository repository;
  public Invoice get(@PathVariable long invoiceId) {
    return repository.findById(42L).orElseThrow();
  }
}
interface InvoiceRepository extends JpaRepository<Invoice, Long> {}
`,
    });
    expect(
      authorizationRecords(await buildResidualRiskInventory(fixed)),
    ).toEqual([]);
  });

  test("rejects a typed local Spring Data repository shadow", async () => {
    const shadow = await temporaryRepository({
      "src/InvoiceController.java": controllerSource,
      "src/InvoiceRepository.java": `
package example;
public interface InvoiceRepository extends JpaRepository<Invoice, Long> {}
interface JpaRepository<T, ID> {
  java.util.Optional<T> findById(ID id);
}
`,
      "src/InvoiceService.java": `
package example;
public class InvoiceService {
  private final InvoiceRepository repository;
  public Invoice load(long invoiceId, Object authentication) {
    return repository.findById(invoiceId).orElseThrow();
  }
}
`,
    });
    expect(
      authorizationRecords(await buildResidualRiskInventory(shadow)),
    ).toEqual([]);
  });

  test("preserves typed same-file and two-service object-reference paths", async () => {
    const sameFile = await temporaryRepository({
      "src/InvoiceController.java": `
package example;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.web.bind.annotation.PathVariable;
public class InvoiceController {
  private final InvoiceRepository repository;
  public Invoice get(@PathVariable long invoiceId) {
    return repository.findById(invoiceId).orElseThrow();
  }
}
interface InvoiceRepository extends JpaRepository<Invoice, Long> {}
`,
    });
    const sameFileRows = authorizationRecords(
      await buildResidualRiskInventory(sameFile),
    );
    expect(sameFileRows).toHaveLength(1);
    expect(sameFileRows[0]?.frameworkModel?.scope).toBe("same-file");

    const multiHop = await temporaryRepository({
      "src/InvoiceController.java": `
package example;
import org.springframework.web.bind.annotation.PathVariable;
public class InvoiceController {
  private final InvoiceFacade invoices;
  public Invoice get(@PathVariable long invoiceId) {
    return invoices.load(invoiceId);
  }
}
`,
      "src/InvoiceFacade.java": `
package example;
public class InvoiceFacade {
  private final InvoiceService invoices;
  public Invoice load(long invoiceId) {
    return invoices.load(invoiceId);
  }
}
`,
      "src/InvoiceRepository.java": repositorySource,
      "src/InvoiceService.java": `
package example;
public class InvoiceService {
  private final InvoiceRepository repository;
  public Invoice load(long invoiceId) {
    return repository.findById(invoiceId).orElseThrow();
  }
}
`,
    });
    const multiHopRows = authorizationRecords(
      await buildResidualRiskInventory(multiHop),
    );
    expect(multiHopRows).toHaveLength(1);
    expect(multiHopRows[0]?.frameworkModel?.scope).toBe(
      "cross-file-multi-hop-wrapper",
    );
    expect(multiHopRows[0]?.frameworkModel?.propagators).toHaveLength(6);
  });

  test("teaches active Spring object policy rather than authentication folklore", () => {
    const prompt = scanQualityGatePrompt("{}");
    expect(prompt).toContain("spring-http-object-authorization");
    expect(prompt).toContain("@EnableMethodSecurity");
    expect(prompt).toContain("returnObject");
    expect(prompt).toContain("post-authorization after save");
  });
});
