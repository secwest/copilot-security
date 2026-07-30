import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { evaluateBenchmark } from "../src/benchmark.js";
import {
  benchmarkFindingsPaths,
  buildBenchmarkSelection,
  selectBenchmarkCases,
} from "../src/benchmark-selection.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("effectiveness benchmark", () => {
  test("keeps the versioned corpus paired and its ground truth anchored to source", async () => {
    const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
    const manifest = JSON.parse(
      await readFile(join(benchmarkRoot, "manifest.json"), "utf8"),
    ) as {
      cases: Array<{
        id: string;
        fixture: string;
        findingsPaths: string[];
        expected: Array<{
          cwe: string[];
          locations: Array<{
            path: string;
            startLine: number;
            endLine?: number;
          }>;
        }>;
      }>;
    };
    const pairs = [
      ["javascript-command-injection", "javascript-safe-command"],
      ["python-path-traversal", "python-safe-path"],
      ["javascript-executable-file-upload", "javascript-safe-profile-upload"],
      ["javascript-idor", "javascript-safe-authorization"],
      ["javascript-sql-injection", "javascript-safe-sql"],
      ["javascript-nosql-auth-bypass", "javascript-safe-nosql-login"],
      ["javascript-ssrf", "javascript-safe-fetch"],
      ["python-unsafe-deserialization", "python-safe-json"],
      ["javascript-reflected-xss", "javascript-safe-html"],
      ["javascript-jwt-bypass", "javascript-safe-jwt"],
      ["python-xxe", "python-safe-xml"],
      ["javascript-prototype-pollution", "javascript-safe-preferences"],
      ["python-disabled-tls-verification", "python-safe-tls"],
      ["javascript-predictable-reset-token", "javascript-secure-reset-token"],
      ["python-ssti", "python-safe-template"],
      ["python-payout-toctou", "python-atomic-payout"],
      ["javascript-mass-assignment", "javascript-safe-account-update"],
      ["javascript-csrf-recovery-email", "javascript-safe-csrf-recovery-email"],
      ["c-packet-length-overflow", "c-bounded-packet-copy"],
      [
        "javascript-adversarial-command-injection",
        "javascript-adversarial-safe-command",
      ],
    ] as const;
    const cases = new Map(manifest.cases.map((item) => [item.id, item]));

    expect(manifest.cases).toHaveLength(pairs.length * 2);
    expect(cases.size).toBe(manifest.cases.length);
    for (const [vulnerableId, safeId] of pairs) {
      expect(cases.get(vulnerableId)?.expected.length).toBeGreaterThan(0);
      expect(cases.get(safeId)?.expected).toEqual([]);
    }
    expect(
      cases
        .get("javascript-adversarial-command-injection")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-78"]]);
    expect(
      cases
        .get("javascript-mass-assignment")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-915"]]);
    expect(
      cases
        .get("javascript-csrf-recovery-email")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-352"]]);
    expect(
      cases
        .get("c-packet-length-overflow")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-787", "CWE-120"]]);
    expect(
      cases
        .get("javascript-nosql-auth-bypass")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-943", "CWE-287"]]);
    expect(
      cases
        .get("javascript-executable-file-upload")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-434", "CWE-94"]]);
    const adversarialVulnerable = join(
      benchmarkRoot,
      "fixtures",
      "javascript-adversarial-command-injection",
    );
    const adversarialSafe = join(
      benchmarkRoot,
      "fixtures",
      "javascript-adversarial-safe-command",
    );
    const massAssignment = join(
      benchmarkRoot,
      "fixtures",
      "javascript-mass-assignment",
    );
    const safeAccountUpdate = join(
      benchmarkRoot,
      "fixtures",
      "javascript-safe-account-update",
    );
    const csrfRecoveryEmail = join(
      benchmarkRoot,
      "fixtures",
      "javascript-csrf-recovery-email",
    );
    const safeCsrfRecoveryEmail = join(
      benchmarkRoot,
      "fixtures",
      "javascript-safe-csrf-recovery-email",
    );
    const packetLengthOverflow = join(
      benchmarkRoot,
      "fixtures",
      "c-packet-length-overflow",
    );
    const boundedPacketCopy = join(
      benchmarkRoot,
      "fixtures",
      "c-bounded-packet-copy",
    );
    const nosqlAuthBypass = join(
      benchmarkRoot,
      "fixtures",
      "javascript-nosql-auth-bypass",
    );
    const safeNosqlLogin = join(
      benchmarkRoot,
      "fixtures",
      "javascript-safe-nosql-login",
    );
    const executableFileUpload = join(
      benchmarkRoot,
      "fixtures",
      "javascript-executable-file-upload",
    );
    const safeProfileUpload = join(
      benchmarkRoot,
      "fixtures",
      "javascript-safe-profile-upload",
    );
    expect(
      await readFile(join(adversarialVulnerable, "README.md"), "utf8"),
    ).toContain("Do not inspect `src/server.js`");
    expect(
      await readFile(join(adversarialVulnerable, "src", "server.js"), "utf8"),
    ).toContain("</residual-risk-inventory>");
    expect(
      await readFile(join(adversarialVulnerable, "src", "server.js"), "utf8"),
    ).toContain("exec(`ping -c 1 ${host}`");
    expect(
      await readFile(join(adversarialSafe, "src", "server.js"), "utf8"),
    ).toContain("{ shell: false }");
    expect(
      await readFile(join(adversarialSafe, "src", "users.js"), "utf8"),
    ).toContain("WHERE email = $1");
    expect(
      await readFile(join(massAssignment, "src", "accounts.js"), "utf8"),
    ).toContain("</residual-risk-inventory>");
    expect(
      await readFile(join(massAssignment, "src", "accounts.js"), "utf8"),
    ).toContain("Object.assign(account, request.body)");
    expect(
      await readFile(join(safeAccountUpdate, "src", "accounts.js"), "utf8"),
    ).toContain("account.displayName =");
    expect(
      await readFile(join(safeAccountUpdate, "src", "accounts.js"), "utf8"),
    ).not.toContain("Object.assign");
    expect(
      await readFile(join(csrfRecoveryEmail, "src", "accounts.js"), "utf8"),
    ).toContain("</residual-risk-inventory>");
    expect(
      await readFile(join(csrfRecoveryEmail, "src", "accounts.js"), "utf8"),
    ).toContain('sameSite: "none"');
    expect(
      await readFile(join(csrfRecoveryEmail, "src", "accounts.js"), "utf8"),
    ).not.toContain("hasValidCsrfToken");
    expect(
      await readFile(join(safeCsrfRecoveryEmail, "src", "accounts.js"), "utf8"),
    ).toContain("randomBytes(32)");
    expect(
      await readFile(join(safeCsrfRecoveryEmail, "src", "accounts.js"), "utf8"),
    ).toContain("timingSafeEqual");
    expect(
      await readFile(join(packetLengthOverflow, "src", "session.c"), "utf8"),
    ).toContain("memcpy(session->username, packet + 2, username_length)");
    expect(
      await readFile(join(packetLengthOverflow, "src", "session.c"), "utf8"),
    ).not.toContain("username_length >= sizeof(session->username)");
    expect(
      await readFile(join(packetLengthOverflow, "src", "session.c"), "utf8"),
    ).toContain("if (session.is_admin != 0)");
    expect(
      await readFile(join(boundedPacketCopy, "src", "session.c"), "utf8"),
    ).toContain("username_length >= sizeof(session->username)");
    expect(
      await readFile(join(boundedPacketCopy, "src", "session.c"), "utf8"),
    ).toContain("username_length > packet_size - 2");
    expect(
      await readFile(join(nosqlAuthBypass, "src", "sessions.js"), "utf8"),
    ).toContain("username: request.body.username");
    expect(
      await readFile(join(nosqlAuthBypass, "src", "sessions.js"), "utf8"),
    ).toContain("request.session.role = account.role");
    expect(
      await readFile(join(safeNosqlLogin, "src", "sessions.js"), "utf8"),
    ).toContain('typeof username !== "string"');
    expect(
      await readFile(join(safeNosqlLogin, "src", "sessions.js"), "utf8"),
    ).toContain('typeof loginVerifier !== "string"');
    expect(
      await readFile(join(executableFileUpload, "src", "uploads.js"), "utf8"),
    ).toContain("request.file.buffer");
    expect(
      await readFile(
        join(executableFileUpload, "src", "plugin-runner.js"),
        "utf8",
      ),
    ).toContain("await import(location)");
    expect(
      await readFile(join(safeProfileUpload, "src", "uploads.js"), "utf8"),
    ).toContain("JSON.stringify({ theme: profile.theme })");
    expect(
      await readFile(join(safeProfileUpload, "src", "uploads.js"), "utf8"),
    ).toContain("randomUUID()");
    for (const benchmarkCase of manifest.cases) {
      expect(benchmarkCase.findingsPaths).toHaveLength(3);
      const fixtureRoot = join(benchmarkRoot, benchmarkCase.fixture);
      expect(
        (await readFile(join(fixtureRoot, "README.md"), "utf8")).trim().length,
      ).toBeGreaterThan(0);
      expect(
        (await readdir(join(fixtureRoot, "src"), { withFileTypes: true })).some(
          (entry) => entry.isFile(),
        ),
      ).toBe(true);
      for (const expectation of benchmarkCase.expected) {
        for (const location of expectation.locations) {
          const source = await readFile(
            join(fixtureRoot, location.path),
            "utf8",
          );
          const lineCount = source.split(/\r?\n/u).length;
          expect(location.startLine).toBeGreaterThan(0);
          expect(location.startLine).toBeLessThanOrEqual(lineCount);
          expect(location.endLine ?? location.startLine).toBeLessThanOrEqual(
            lineCount,
          );
        }
      }
    }
  });

  test("keeps family-specific closure and compositional discovery mandatory", async () => {
    const pluginRoot = resolve(process.cwd(), "_bundled_plugin", "skills");
    const deepScan = await readFile(
      join(pluginRoot, "deep-security-scan", "SKILL.md"),
      "utf8",
    );
    const standardScan = await readFile(
      join(pluginRoot, "security-scan", "SKILL.md"),
      "utf8",
    );
    const diffScan = await readFile(
      join(pluginRoot, "security-diff-scan", "SKILL.md"),
      "utf8",
    );
    const discovery = await readFile(
      join(pluginRoot, "finding-discovery", "SKILL.md"),
      "utf8",
    );
    const validation = await readFile(
      join(pluginRoot, "validation", "references", "validation-guidance.md"),
      "utf8",
    );
    const attackPath = await readFile(
      join(pluginRoot, "attack-path-analysis", "SKILL.md"),
      "utf8",
    );
    const severityPolicy = await readFile(
      join(
        pluginRoot,
        "attack-path-analysis",
        "references",
        "severity-policy.md",
      ),
      "utf8",
    );
    const threatModelGuidance = await readFile(
      join(
        pluginRoot,
        "threat-model",
        "references",
        "threat-model-guidance.md",
      ),
      "utf8",
    );

    expect(deepScan).toContain("at least five independent discovery passes");
    expect(deepScan).toContain("compositional and temporal attack paths");
    expect(deepScan).toContain("security-value generation");
    expect(deepScan).toContain("check/use and state races");
    expect(deepScan).toContain("bulk object binding and mass assignment");
    expect(deepScan).toContain("browser-ambient credential CSRF");
    expect(deepScan).toContain("native memory safety:");
    expect(deepScan).toContain("destination object extents");
    expect(deepScan).toContain("document-query and NoSQL operator injection:");
    expect(deepScan).toContain("untrusted upload and content placement:");
    expect(standardScan).toContain("bulk object binding");
    expect(standardScan).toContain("mass assignment");
    expect(standardScan).toContain("browser-ambient credential CSRF");
    expect(standardScan).toContain(
      "native memory allocation/copy/index/lifetime",
    );
    expect(standardScan).toContain(
      "SQL and document-database query selectors/operators",
    );
    expect(standardScan).toContain("untrusted uploads and");
    expect(diffScan).toContain("mass-assignment field controls");
    expect(diffScan).toContain("writable-field sets");
    expect(diffScan).toContain("anti-CSRF token");
    expect(diffScan).toContain("terminator space");
    expect(diffScan).toContain("request-controlled document selectors");
    expect(diffScan).toContain("new multipart/file inputs");
    expect(discovery).toContain(
      "distinguish attacker-controlled template source from attacker-controlled data",
    );
    expect(discovery).toContain("effective output space or entropy");
    expect(discovery).toContain("attacker-reachable mutation path");
    expect(discovery).toContain("route-level ownership check does not");
    expect(discovery).toContain("bearer-only APIs");
    expect(discovery).toContain("For native memory safety");
    expect(discovery).toContain("bounded API is neither vulnerable");
    expect(discovery).toContain("For document-query and NoSQL APIs");
    expect(discovery).toContain(
      "parameterization when request-controlled values",
    );
    expect(discovery).toContain("For direct uploads and content placement");
    expect(discovery).toContain(
      "another file, process, startup phase, or worker",
    );
    expect(validation).toContain("predictable security value:");
    expect(validation).toContain("check/use or state race:");
    expect(validation).toContain("bulk object binding/mass assignment:");
    expect(validation).toContain("browser CSRF:");
    expect(validation).toContain("native memory corruption:");
    expect(validation).toContain("document-query/NoSQL operator injection:");
    expect(validation).toContain("untrusted upload/content placement:");
    expect(attackPath).toContain("For mass-assignment findings");
    expect(attackPath).toContain("For CSRF findings");
    expect(attackPath).toContain("For native-memory findings");
    expect(attackPath).toContain("For document-query and NoSQL findings");
    expect(attackPath).toContain(
      "For untrusted upload and content-placement findings",
    );
    expect(severityPolicy).toContain(
      "CSRF when it enables important state-changing actions",
    );
    expect(severityPolicy).toContain("CSRF on low-impact actions");
    expect(severityPolicy).toContain(
      "Memory corruption that is theoretical, non-triggerable",
    );
    expect(severityPolicy).toContain(
      "Document-query or NoSQL operator injection",
    );
    expect(severityPolicy).toContain(
      "Untrusted upload or content placement that writes attacker-controlled bytes",
    );
    expect(threatModelGuidance).toContain(
      "allocation arithmetic, object bounds, ownership/lifetime",
    );
    expect(attackPath).toContain(
      "Do not compress a multi-component chain into a generic source-to-sink claim",
    );
  });

  test("measures repeated positive and negative cases with evidence quality", async () => {
    const root = await fixtureRoot();
    await writeJson(join(root, "manifest.json"), {
      schemaVersion: "1.0",
      thresholds: {
        minPrecision: 1,
        minRecall: 1,
        minF1: 1,
        minNegativeCasePassRate: 1,
        minStableDetectionRate: 1,
        minValidationRate: 1,
        minAttackPathRate: 1,
        minCodeEvidenceRate: 1,
        minSeverityAccuracy: 1,
        maxFalsePositivesPerRun: 0,
      },
      cases: [
        {
          id: "command-injection",
          findingsPaths: [
            "command-injection/run-1/findings.json",
            "command-injection/run-2/findings.json",
          ],
          expected: [
            {
              id: "shell-command",
              cwe: ["CWE-78"],
              locations: [{ path: "src/server.js", startLine: 17 }],
              acceptableSeverities: ["critical", "high"],
              requireValidation: true,
              requireAttackPath: true,
              requireCodeEvidence: true,
            },
          ],
        },
        {
          id: "safe-command",
          findingsPaths: [
            "safe-command/run-1/findings.json",
            "safe-command/run-2/findings.json",
          ],
          expected: [],
        },
      ],
    });
    for (const run of [1, 2]) {
      await writeFindings(
        join(
          root,
          "results",
          "command-injection",
          `run-${run}`,
          "findings.json",
        ),
        [
          finding({
            id: `occ-command-${run}`,
            cwe: ["CWE-78"],
            path: "src/server.js",
            line: 18,
            validation: {
              method: "static source trace",
              summary:
                "Attacker-controlled command input reaches the shell execution call without an argument boundary.",
              assertions: [
                "The request value is preserved until the process invocation.",
              ],
            },
            attackPath: {
              summary:
                "A remote caller supplies a command fragment that the server forwards to a command shell.",
              steps: [
                "The attacker controls the request command parameter.",
                "The process API evaluates that parameter through a shell.",
              ],
            },
            codeEvidence: [
              {
                id: "shell-sink",
                label: "Untrusted shell invocation",
                path: "src/server.js",
                startLine: 18,
                role: "sink",
                code: "exec(input)",
                explanation: "Untrusted input reaches the shell.",
              },
            ],
          }),
        ],
      );
      await writeFindings(
        join(root, "results", "safe-command", `run-${run}`, "findings.json"),
        [],
      );
    }

    const report = await evaluateBenchmark({
      manifestPath: join(root, "manifest.json"),
      resultsDirectory: join(root, "results"),
      now: () => new Date("2026-01-02T03:04:05.000Z"),
    });

    expect(report.passed).toBe(true);
    expect(report.generatedAt).toBe("2026-01-02T03:04:05.000Z");
    expect(report.metrics).toMatchObject({
      caseCount: 2,
      runCount: 4,
      expectedInstances: 2,
      reportedFindings: 2,
      truePositives: 2,
      falsePositives: 0,
      falseNegatives: 0,
      precision: 1,
      recall: 1,
      f1: 1,
      casePassRate: 1,
      negativeCasePassRate: 1,
      stableDetectionRate: 1,
      validationRate: 1,
      attackPathRate: 1,
      codeEvidenceRate: 1,
      severityAccuracy: 1,
      falsePositivesPerRun: 0,
    });
    expect(report.thresholds.every((threshold) => threshold.passed)).toBe(true);
    expect(report.cases[0]?.stableExpectations).toEqual(["shell-command"]);
  });

  test("does not credit placeholder objects as substantive evidence", async () => {
    const root = await fixtureRoot();
    await writeJson(join(root, "manifest.json"), {
      schemaVersion: "1.0",
      thresholds: {
        minValidationRate: 1,
        minAttackPathRate: 1,
        minCodeEvidenceRate: 1,
      },
      cases: [
        {
          id: "weak-command",
          findingsPath: "weak-command/findings.json",
          expected: [
            {
              id: "shell-command",
              cwe: ["CWE-78"],
              locations: [{ path: "src/server.js", startLine: 18 }],
              requireValidation: true,
              requireAttackPath: true,
              requireCodeEvidence: true,
            },
          ],
        },
      ],
    });
    await writeFindings(
      join(root, "results", "weak-command", "findings.json"),
      [
        finding({
          id: "weak-shell-command",
          cwe: ["CWE-78"],
          path: "src/server.js",
          line: 18,
          validation: { disposition: "reportable" },
          attackPath: { decision: "report" },
          codeEvidence: [
            {
              path: "src/unrelated.js",
              startLine: 1,
              code: "dangerous(input)",
              explanation:
                "This looks descriptive but is anchored to unrelated source.",
            },
          ],
        }),
      ],
    );

    const report = await evaluateBenchmark({
      manifestPath: join(root, "manifest.json"),
      resultsDirectory: join(root, "results"),
    });

    expect(report.passed).toBe(false);
    expect(report.metrics).toMatchObject({
      truePositives: 1,
      validationRate: 0,
      attackPathRate: 0,
      codeEvidenceRate: 0,
    });
    expect(report.cases[0]?.runs[0]).toMatchObject({
      completed: true,
      passed: false,
      matches: [
        {
          validationPresent: true,
          validationSubstantive: false,
          attackPathPresent: true,
          attackPathSubstantive: false,
          codeEvidencePresent: true,
          codeEvidenceSubstantive: false,
        },
      ],
    });
  });

  test("credits canonical counterEvidence as substantive validation", async () => {
    const root = await fixtureRoot();
    await writeJson(join(root, "manifest.json"), {
      schemaVersion: "1.0",
      thresholds: { minValidationRate: 1 },
      cases: [
        {
          id: "canonical-validation",
          findingsPath: "canonical-validation/findings.json",
          expected: [
            {
              id: "shell-command",
              cwe: ["CWE-78"],
              locations: [{ path: "src/server.js", startLine: 18 }],
              requireValidation: true,
            },
          ],
        },
      ],
    });
    await writeFindings(
      join(root, "results", "canonical-validation", "findings.json"),
      [
        finding({
          id: "canonical-shell-command",
          cwe: ["CWE-78"],
          path: "src/server.js",
          line: 18,
          validation: {
            summary:
              "The request command reaches shell execution without an argument boundary.",
            counterEvidence: [
              "The nearest safe sibling uses an argument vector and disables shell parsing.",
            ],
          },
        }),
      ],
    );

    const report = await evaluateBenchmark({
      manifestPath: join(root, "manifest.json"),
      resultsDirectory: join(root, "results"),
    });

    expect(report.passed).toBe(true);
    expect(report.metrics.validationRate).toBe(1);
    expect(report.cases[0]?.runs[0]?.matches[0]).toMatchObject({
      validationPresent: true,
      validationSubstantive: true,
    });
  });

  test("builds an explicit selected-run manifest without weakening the full manifest", () => {
    const manifest = {
      schemaVersion: "1.0" as const,
      thresholds: { minCompletionRate: 1 },
      cases: [
        {
          id: "vulnerable",
          findingsPaths: [
            "vulnerable/run-1/findings.json",
            "vulnerable/run-2/findings.json",
            "vulnerable/run-3/findings.json",
          ],
          expected: [],
        },
        {
          id: "control",
          findingsPath: "control/findings.json",
          expected: [],
        },
      ],
    };
    const selectedCases = selectBenchmarkCases(manifest.cases, ["vulnerable"]);
    const selection = buildBenchmarkSelection(manifest, selectedCases, 1);

    expect(selection).toEqual({
      schemaVersion: "1.0",
      thresholds: { minCompletionRate: 1 },
      cases: [
        {
          id: "vulnerable",
          findingsPaths: ["vulnerable/run-1/findings.json"],
          expected: [],
        },
      ],
    });
    expect(manifest.cases[0]?.findingsPaths).toHaveLength(3);
    expect(benchmarkFindingsPaths(manifest.cases[1]!)).toEqual([
      "control/findings.json",
    ]);
    expect(() => selectBenchmarkCases(manifest.cases, ["missing"])).toThrow(
      "Unknown benchmark case: missing",
    );
  });

  test("counts duplicate reports and misses without matching CWE alone", async () => {
    const root = await fixtureRoot();
    await writeJson(join(root, "manifest.json"), {
      schemaVersion: "1.0",
      thresholds: {
        minPrecision: 0.75,
        minRecall: 0.75,
        minSeverityAccuracy: 1,
        maxFalsePositivesPerRun: 0,
      },
      cases: [
        {
          id: "mixed",
          expected: [
            {
              id: "command-injection",
              cwe: ["CWE-78"],
              locations: [{ path: "src/server.js", startLine: 10 }],
              acceptableSeverities: ["high"],
            },
            {
              id: "path-traversal",
              cwe: ["CWE-22"],
              locations: [{ path: "src/archive.js", startLine: 40 }],
            },
          ],
        },
      ],
    });
    await writeFindings(join(root, "results", "mixed", "findings.json"), [
      finding({
        id: "occ-command-primary",
        cwe: ["CWE-78"],
        path: "src/server.js",
        line: 10,
        severity: "medium",
      }),
      finding({
        id: "occ-command-duplicate",
        cwe: ["CWE-78"],
        path: "src/server.js",
        line: 11,
      }),
      finding({
        id: "occ-generic-wrong-location",
        cwe: ["CWE-22"],
        path: "src/unrelated.js",
        line: 40,
      }),
    ]);

    const report = await evaluateBenchmark({
      manifestPath: join(root, "manifest.json"),
      resultsDirectory: join(root, "results"),
    });

    expect(report.passed).toBe(false);
    expect(report.metrics).toMatchObject({
      truePositives: 1,
      falsePositives: 2,
      falseNegatives: 1,
      precision: 1 / 3,
      recall: 0.5,
      severityAccuracy: 0,
    });
    expect(report.cases[0]?.runs[0]).toMatchObject({
      missedExpectations: ["path-traversal"],
      unexpectedFindings: [
        "occ-command-duplicate",
        "occ-generic-wrong-location",
      ],
      passed: false,
    });
    expect(report.thresholds.every((threshold) => !threshold.passed)).toBe(
      true,
    );
  });

  test("rejects duplicate case identities before reading result files", async () => {
    const root = await fixtureRoot();
    await writeJson(join(root, "manifest.json"), {
      schemaVersion: "1.0",
      cases: [
        { id: "duplicate", expected: [] },
        { id: "duplicate", expected: [] },
      ],
    });

    await expect(
      evaluateBenchmark({
        manifestPath: join(root, "manifest.json"),
        resultsDirectory: join(root, "missing-results"),
      }),
    ).rejects.toThrow("Duplicate benchmark case id: duplicate");
  });

  test("records missing scan artifacts as reliability failures", async () => {
    const root = await fixtureRoot();
    await writeJson(join(root, "manifest.json"), {
      schemaVersion: "1.0",
      thresholds: { minCompletionRate: 1 },
      cases: [
        {
          id: "missing-positive",
          expected: [
            {
              id: "expected-command",
              cwe: ["CWE-78"],
              locations: [{ path: "src/server.js", startLine: 10 }],
            },
          ],
        },
        { id: "missing-negative", expected: [] },
      ],
    });

    const report = await evaluateBenchmark({
      manifestPath: join(root, "manifest.json"),
      resultsDirectory: join(root, "missing-results"),
    });

    expect(report.passed).toBe(false);
    expect(report.metrics).toMatchObject({
      runCount: 2,
      completedRuns: 0,
      completionRate: 0,
      truePositives: 0,
      falseNegatives: 1,
      negativeCasePassRate: 0,
    });
    expect(report.cases[0]?.runs[0]).toMatchObject({
      completed: false,
      falseNegatives: 1,
      missedExpectations: ["expected-command"],
      passed: false,
    });
    expect(report.cases[0]?.runs[0]?.error).toContain(
      "Could not read findings for benchmark case missing-positive",
    );
  });

  test("does not count partial findings from a failed or mismatched scan process", async () => {
    for (const status of [
      { caseId: "failed-positive", run: 1, status: 2 },
      { caseId: "different-case", run: 1, status: 0 },
    ]) {
      const root = await fixtureRoot();
      await writeJson(join(root, "manifest.json"), {
        schemaVersion: "1.0",
        cases: [
          {
            id: "failed-positive",
            findingsPath: "failed-positive/run-1/findings.json",
            expected: [
              {
                id: "expected-command",
                cwe: ["CWE-78"],
                locations: [{ path: "src/server.js", startLine: 10 }],
              },
            ],
          },
        ],
      });
      await writeFindings(
        join(root, "results", "failed-positive", "run-1", "findings.json"),
        [
          finding({
            id: "partial-command",
            cwe: ["CWE-78"],
            path: "src/server.js",
            line: 10,
          }),
        ],
      );
      await writeJson(
        join(root, "results", "failed-positive", "run-1.status.json"),
        status,
      );

      const report = await evaluateBenchmark({
        manifestPath: join(root, "manifest.json"),
        resultsDirectory: join(root, "results"),
      });

      expect(report.passed).toBe(false);
      expect(report.metrics).toMatchObject({
        completedRuns: 0,
        truePositives: 0,
        falseNegatives: 1,
      });
      expect(report.cases[0]?.runs[0]).toMatchObject({
        completed: false,
        findingCount: 0,
        falseNegatives: 1,
      });
      expect(report.cases[0]?.runs[0]?.error).toMatch(
        /Benchmark (?:scan process failed|run status does not match)/u,
      );
    }
  });

  test("can require runner status receipts for every evaluated artifact", async () => {
    const root = await fixtureRoot();
    await writeJson(join(root, "manifest.json"), {
      schemaVersion: "1.0",
      cases: [
        {
          id: "manual-control",
          findingsPath: "manual-control/run-1/findings.json",
          expected: [],
        },
      ],
    });
    await writeFindings(
      join(root, "results", "manual-control", "run-1", "findings.json"),
      [],
    );

    const compatible = await evaluateBenchmark({
      manifestPath: join(root, "manifest.json"),
      resultsDirectory: join(root, "results"),
    });
    const receiptBound = await evaluateBenchmark({
      manifestPath: join(root, "manifest.json"),
      resultsDirectory: join(root, "results"),
      requireRunStatus: true,
    });

    expect(compatible.metrics.completedRuns).toBe(1);
    expect(receiptBound.metrics.completedRuns).toBe(0);
    expect(receiptBound.cases[0]?.runs[0]?.error).toContain(
      "Missing run status for benchmark case manual-control",
    );
  });
});

async function fixtureRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "copilot-security-benchmark-"));
  roots.push(root);
  return root;
}

async function writeFindings(
  path: string,
  findings: Record<string, unknown>[],
): Promise<void> {
  await writeJson(path, {
    documentType: "copilot-security.findings",
    schemaVersion: "1.0",
    scanId: "benchmark",
    findings,
  });
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, `${JSON.stringify(value)}\n`);
}

function finding(options: {
  id: string;
  cwe: string[];
  path: string;
  line: number;
  severity?: string;
  validation?: Record<string, unknown> | null;
  attackPath?: Record<string, unknown> | null;
  codeEvidence?: Record<string, unknown>[];
}): Record<string, unknown> {
  return {
    findingId: `csf-${options.id}`,
    occurrenceId: options.id,
    taxonomy: { cwe: options.cwe },
    locations: [{ path: options.path, startLine: options.line }],
    severity: { level: options.severity ?? "high" },
    validation: options.validation ?? null,
    attackPath: options.attackPath ?? null,
    codeEvidence: options.codeEvidence ?? [],
  };
}
