import { spawnSync } from "node:child_process";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { runWorkbench } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

type Finding = Record<string, unknown> & {
  ruleId: string;
  identity: { anchor: string; instance?: string };
  summary: string;
  severity: { level: string };
  confidence: { level: string };
  locations: Array<{ path: string }>;
  codeEvidence?: Array<{
    id: string;
    label: string;
    path: string;
    startLine: number;
    code: string;
    explanation: string;
  }>;
  writeup?: unknown;
};

type FindingsDocument = {
  scanId: string;
  findings: Array<Finding | null>;
};

type CoverageSurface = Record<string, unknown> & {
  id: string;
  label: string;
  disposition: string;
  receiptRefs: unknown[];
};

type CoverageDocument = Record<string, unknown> & {
  scanId: string;
  completeness: string;
  inventoryStrategy: string;
  surfaces: CoverageSurface[] | Record<string, unknown>;
  explicitExclusions: unknown;
  deferred: unknown;
};

type ScanSummary = {
  findingCount: number;
  progress: { status: string };
  warnings: string[];
};

type SarifDocument = {
  runs: Array<{
    properties: { copilotSecurityCoverageCompleteness?: string };
    results: Array<{ properties: { severity: string } }>;
    invocations?: Array<{
      executionSuccessful: boolean;
      toolExecutionNotifications: Array<{
        level: string;
        message: { text: string };
      }>;
    }>;
  }>;
};

type ScanFixture = {
  python: string;
  repository: string;
  stateDir: string;
  scanDir: string;
  scanId: string;
  registration: Record<string, unknown>;
};

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value)}\n`);
}

async function workbench(fixture: ScanFixture, args: readonly string[]) {
  return runWorkbench(
    {
      python: fixture.python,
      pluginRoot: PLUGIN_ROOT,
      environment: {
        PATH: process.env["PATH"],
        COPILOT_SECURITY_REPOSITORY: fixture.repository,
        COPILOT_SECURITY_STATE_DIR: fixture.stateDir,
      },
    },
    args,
  );
}

async function startDraftScan(
  repositoryKind: "directory" | "clean" | "dirty" | "nested" = "directory",
): Promise<ScanFixture> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "copilot-security-scan-recovery-")),
  );
  temporaryDirectories.push(root);
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();

  const target = join(root, "repository");
  const scanDir = join(root, "scan");
  await mkdir(join(target, "src"), { recursive: true });
  await writeFile(join(target, "src", "extract.py"), "# fixture\n");
  await mkdir(scanDir, { mode: 0o700 });

  if (repositoryKind !== "directory") {
    for (const args of [
      ["init", "--quiet", target],
      ["-C", target, "add", "--", "src/extract.py"],
      [
        "-C",
        target,
        "-c",
        "user.name=Copilot Security",
        "-c",
        "user.email=copilot-security@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
      ],
    ]) {
      const result = spawnSync("git", args, { encoding: "utf8" });
      expect(result.status, result.stderr).toBe(0);
    }
    if (repositoryKind === "dirty") {
      await writeFile(join(target, "src", "extract.py"), "# changed fixture\n");
    }
    if (repositoryKind === "nested") {
      const nested = join(target, "nested");
      await mkdir(nested);
      await writeFile(join(nested, "source.py"), "# nested fixture\n");
      const initialized = spawnSync("git", ["init", "--quiet", nested], {
        encoding: "utf8",
      });
      expect(initialized.status, initialized.stderr).toBe(0);
    }
  }

  const fixture: ScanFixture = {
    python: python!,
    repository: target,
    stateDir: join(root, "state"),
    scanDir,
    scanId: "",
    registration: {},
  };
  const registration = await workbench(fixture, [
    "register-cli-scan",
    "--repository",
    target,
    "--scan-dir",
    scanDir,
    "--recipe-json",
    JSON.stringify({
      config: {},
      mode: "standard",
      repository: target,
      target: { kind: "repository", paths: [] },
    }),
  ]);
  fixture.scanId = String(registration["scanId"]);
  fixture.registration = registration;

  await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDir, {
    recursive: true,
  });
  const manifestPath = join(scanDir, "scan-manifest.json");
  const manifest = await readJson<{
    scan: {
      id: string;
      target: { kind: string };
      sealedAt?: string;
      artifacts?: unknown[];
    };
  }>(manifestPath);
  manifest.scan.id = fixture.scanId;
  manifest.scan.target.kind =
    repositoryKind === "directory"
      ? "directory_snapshot"
      : repositoryKind === "clean"
        ? "git_revision"
        : "git_worktree";
  delete manifest.scan.sealedAt;
  delete manifest.scan.artifacts;
  await writeJson(manifestPath, manifest);

  for (const name of ["findings.json", "coverage.json"] as const) {
    const path = join(scanDir, name);
    const document = await readJson<{ scanId: string }>(path);
    document.scanId = fixture.scanId;
    await writeJson(path, document);
  }
  await writeFile(join(scanDir, "report.md"), "# Draft report\n");
  return fixture;
}

async function completeScan(fixture: ScanFixture): Promise<ScanSummary> {
  const result = await workbench(fixture, [
    "complete-scan",
    "--scan-id",
    fixture.scanId,
  ]);
  return result["scan"] as unknown as ScanSummary;
}

describe("malformed scan artifact recovery", () => {
  test.each([
    ["all required drafts", []],
    ["the manifest draft", ["findings.json", "coverage.json"]],
    ["the findings draft", ["scan-manifest.json", "coverage.json"]],
    ["the coverage draft", ["scan-manifest.json", "findings.json"]],
  ] as const)(
    "reports every missing agent artifact when completion lacks %s",
    async (_description, present) => {
      const fixture = await startDraftScan();
      const requiredDrafts = [
        "scan-manifest.json",
        "findings.json",
        "coverage.json",
      ] as const;
      const missing = requiredDrafts.filter(
        (filename) => !present.some((candidate) => candidate === filename),
      );
      await Promise.all(
        missing.map((filename) => rm(join(fixture.scanDir, filename))),
      );

      await expect(completeScan(fixture)).rejects.toThrow(
        `Scan agent did not create required draft artifacts: ${missing.join(
          ", ",
        )}. Check that the scan agent can run shell commands and write to the scan directory before retrying.`,
      );
      const stored = await workbench(fixture, [
        "get-scan",
        "--scan-id",
        fixture.scanId,
      ]);
      expect(stored["scan"]).toMatchObject({
        progress: { status: "running" },
      });
    },
  );

  test("normalizes a draft manifest with noncanonical artifact metadata", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "scan-manifest.json");
    const manifest = await readJson<{
      scan: Record<string, unknown>;
    }>(path);
    manifest.scan["artifacts"] = { path: fixture.scanDir };
    manifest.scan["scope"] = {
      includePaths: ["."],
      excludePaths: [],
      repo_root: fixture.repository,
      type: "repository",
    };
    delete manifest.scan["coverageRef"];
    delete manifest.scan["findingsRef"];
    await writeJson(path, manifest);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(1);
    const recovered = await readJson<{
      scan: {
        artifacts: Array<{ path: string }>;
        coverageRef: string;
        findingsRef: string;
        sealedAt: string;
        scope: Record<string, unknown>;
      };
    }>(path);
    expect(recovered.scan.coverageRef).toBe("coverage.json");
    expect(recovered.scan.findingsRef).toBe("findings.json");
    expect(recovered.scan.sealedAt).toBeString();
    expect(recovered.scan.scope).not.toHaveProperty("repo_root");
    expect(recovered.scan.scope).not.toHaveProperty("type");
    expect(recovered.scan.artifacts).toBeArray();
    expect(recovered.scan.artifacts.map((artifact) => artifact.path)).toEqual(
      expect.arrayContaining(["coverage.json", "findings.json"]),
    );
  });

  test("drops a malformed optional threat-model summary from an unsealed draft", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "scan-manifest.json");
    const manifest = await readJson<{
      scan: Record<string, unknown>;
    }>(path);
    manifest.scan["threatModel"] = "artifacts/01_context/threat_model.md";
    await writeJson(path, manifest);

    const completed = await completeScan(fixture);
    const recovered = await readJson<{
      scan: Record<string, unknown>;
    }>(path);

    expect(completed.progress.status).toBe("complete");
    expect(completed.warnings).toContain(
      "Recovered compact Copilot draft artifacts into the canonical scan contract.",
    );
    expect(recovered.scan).not.toHaveProperty("threatModel");
  });

  test("normalizes compact Copilot draft artifacts before sealing", async () => {
    const fixture = await startDraftScan();
    await writeJson(join(fixture.scanDir, "scan-manifest.json"), {
      scanId: fixture.scanId,
      producer: { name: "copilot-security-plugin" },
      target: {
        kind: "$COPILOT_SECURITY_TARGET_KIND",
        targetId: "draft-target",
        displayName: "repository",
      },
    });
    await writeJson(join(fixture.scanDir, "findings.json"), {
      scanId: fixture.scanId,
      findings: [
        {
          id: "archive-command-injection",
          title: "Command injection reaches a shell",
          description:
            "Attacker-controlled archive metadata reaches a shell command.",
          severity: "HIGH",
          confidence: "HIGH",
          location: {
            file: "src/extract.py",
            start_line: 1,
            end_line: 1,
          },
          attack_path: {
            actor: "Remote archive supplier",
            steps: ["Controls archive metadata", "Reaches a command shell"],
            impact: ["Arbitrary command execution"],
          },
          remediation: "Use a fixed executable and argument vector.",
        },
        {
          id: "safe-argument-vector",
          title: "Argument-vector execution is not command injection",
          description:
            "The input is constrained and passed without shell interpolation.",
          severity: "LOW",
          confidence: "HIGH",
          location: {
            file: "src//extract.py",
            start_line: 1,
            end_line: 1,
          },
          validation: {
            status: "mitigated",
            counterevidence: "No shell is involved.",
          },
        },
        {
          id: "documentation-note",
          title: "Documentation note",
          description: "This is documentation rather than executable code.",
          severity: "INFORMATIONAL",
          confidence: "HIGH",
          location: {
            file: "README.md",
            start_line: 1,
            end_line: 1,
          },
          validation: { status: "informational" },
        },
      ],
    });
    await writeJson(join(fixture.scanDir, "coverage.json"), {
      generatedAt: new Date().toISOString(),
      surfaces: [
        {
          path: "src/extract.py",
          outcome: "confirmed",
          rationale: "Validated attacker-controlled shell input.",
        },
        {
          path: "README.md",
          outcome: "reviewed-no-findings",
          rationale: "Reviewed; no exploitable issues found.",
        },
        {
          path: "package.json",
          outcome: "reviewed_no_candidate",
          rationale: "Repository metadata reviewed; no candidate.",
        },
      ],
    });

    const scan = await completeScan(fixture);
    const findings = await readJson<{
      findings: Array<{
        taxonomy: { cwe: string[] };
        codeEvidence: unknown[];
        attackPath: { actor: string; steps: string[]; impact: string[] };
      }>;
    }>(join(fixture.scanDir, "findings.json"));
    const coverage = await readJson<{
      completeness: string;
      surfaces: CoverageSurface[];
    }>(join(fixture.scanDir, "coverage.json"));

    expect(scan.progress.status).toBe("complete");
    expect(scan.findingCount).toBe(1);
    expect(scan.warnings).toContain(
      "Recovered compact Copilot draft artifacts into the canonical scan contract.",
    );
    expect(findings.findings[0]?.taxonomy.cwe).toEqual(["CWE-78"]);
    expect(findings.findings[0]?.codeEvidence).toHaveLength(1);
    expect(findings.findings[0]?.attackPath).toMatchObject({
      actor: "Remote archive supplier",
      impact: ["Arbitrary command execution"],
    });
    expect(coverage.completeness).toBe("complete");
    expect(coverage.surfaces[0]).toMatchObject({
      label: "src/extract.py",
      disposition: "reported",
    });
    expect(coverage.surfaces[1]).toMatchObject({
      label: "README.md",
      disposition: "no_issue_found",
    });
    expect(coverage.surfaces[2]).toMatchObject({
      label: "package.json",
      disposition: "no_issue_found",
    });
  });

  test("accepts an empty top-level finding array as an explicit no-finding draft", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    await writeJson(path, []);

    const completed = await completeScan(fixture);
    const recovered = await readJson<FindingsDocument>(path);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(0);
    expect(completed.warnings).toContain(
      "Recovered compact Copilot draft artifacts into the canonical scan contract.",
    );
    expect(recovered.findings).toEqual([]);
  });

  test("repairs bounded unescaped quotes only in unsealed draft JSON", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const validSummary = document.findings[0]!.summary;
    const malformedSummary = validSummary.replace(
      "attacker-controlled path",
      'attacker-controlled "path"',
    );
    const malformed = JSON.stringify(document).replace(
      JSON.stringify(validSummary),
      `"${malformedSummary}"`,
    );
    expect(() => JSON.parse(malformed)).toThrow();
    await writeFile(path, malformed);

    const completed = await completeScan(fixture);
    const recovered = await readJson<FindingsDocument>(path);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(1);
    expect(completed.warnings).toContain(
      "Recovered unescaped quotation marks in unsealed findings.json.",
    );
    expect(recovered.findings[0]!.summary).toBe(malformedSummary);

    const sealedFixture = await startDraftScan();
    await workbench(sealedFixture, [
      "prepare-scan-completion",
      "--scan-id",
      sealedFixture.scanId,
    ]);
    const sealedPath = join(sealedFixture.scanDir, "findings.json");
    const sealedDocument = await readJson<FindingsDocument>(sealedPath);
    const sealedSummary = sealedDocument.findings[0]!.summary;
    await writeFile(
      sealedPath,
      JSON.stringify(sealedDocument).replace(
        JSON.stringify(sealedSummary),
        `"${sealedSummary.replace("path", '"path"')}"`,
      ),
    );

    await expect(completeScan(sealedFixture)).rejects.toThrow("invalid JSON");

    const oversizedFixture = await startDraftScan();
    const oversizedPath = join(oversizedFixture.scanDir, "findings.json");
    const oversizedDocument = await readJson<FindingsDocument>(oversizedPath);
    const oversizedSummary = oversizedDocument.findings[0]!.summary;
    await writeFile(
      oversizedPath,
      JSON.stringify(oversizedDocument).replace(
        JSON.stringify(oversizedSummary),
        `"${oversizedSummary.replace("path", '"'.repeat(65))}"`,
      ),
    );

    await expect(completeScan(oversizedFixture)).rejects.toThrow(
      "invalid JSON",
    );
  });

  test("infers known CWEs when canonical Copilot findings leave taxonomy empty", async () => {
    for (const [title, summary, taxonomy] of [
      [
        "SQL injection in user search route",
        "Attacker-controlled email input is concatenated into a SQL query.",
        { category: "sql-injection", cwe: ["CWE-89"] },
      ],
      [
        "JWT signature verification bypass in administrative export",
        "The route trusts an unverified JWT token and attacker-controlled admin claim.",
        { category: "improper-signature-verification", cwe: ["CWE-347"] },
      ],
      [
        "XML external entity expansion in invoice import",
        "The request parser permits XXE expansion of attacker-controlled entities.",
        { category: "xml-external-entity", cwe: ["CWE-611"] },
      ],
      [
        "Prototype pollution through recursive preference update",
        "Attacker-controlled __proto__ path segments mutate the shared object prototype.",
        { category: "prototype-pollution", cwe: ["CWE-1321"] },
      ],
      [
        "TLS certificate verification disabled for settlement service",
        "The HTTPS request uses verify=False while sending a service credential.",
        { category: "improper-certificate-validation", cwe: ["CWE-295"] },
      ],
    ] as const) {
      const fixture = await startDraftScan();
      const path = join(fixture.scanDir, "findings.json");
      const document = await readJson<FindingsDocument>(path);
      const finding = document.findings[0]!;
      finding["title"] = title;
      finding.summary = summary;
      finding["taxonomy"] = { category: "security-defect", cwe: [] };
      await writeJson(path, document);

      const completed = await completeScan(fixture);
      const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;

      expect(completed.progress.status).toBe("complete");
      expect(recovered["taxonomy"]).toEqual(taxonomy);
    }
  });

  test("normalizes JWT algorithm and key-type confusion taxonomy", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const finding = document.findings[0]!;
    finding["title"] =
      "JWT algorithm confusion accepts a public-key HMAC forgery";
    finding.summary =
      "The verifier accepts token-selected HS256 alongside RS256 and reuses the RSA public key as the HMAC secret, allowing a forged administrator token.";
    finding["taxonomy"] = {
      category: "weak-cryptographic-algorithm",
      cwe: ["CWE-327"],
    };
    await writeJson(path, document);

    const completed = await completeScan(fixture);
    const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;

    expect(completed.progress.status).toBe("complete");
    expect(recovered["taxonomy"]).toEqual({
      category: "jwt-algorithm-key-confusion",
      cwe: ["CWE-347"],
    });
  });

  test("normalizes OIDC ID-token client and nonce misbinding taxonomy", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const finding = document.findings[0]!;
    finding["title"] =
      "OIDC callback accepts ID tokens not bound to its client or login transaction";
    finding.summary =
      "The callback installs a local account from a correctly signed token without validating its audience, authorized party, or nonce against the target client and initiating browser transaction.";
    finding["taxonomy"] = {
      category: "OIDC ID-token client and transaction binding failure",
      cwe: ["CWE-287", "CWE-346"],
    };
    await writeJson(path, document);

    const completed = await completeScan(fixture);
    const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;

    expect(completed.progress.status).toBe("complete");
    expect(recovered["taxonomy"]).toEqual({
      category: "oidc-id-token-binding",
      cwe: ["CWE-287", "CWE-345"],
    });
  });

  test("normalizes signed webhook capture-replay taxonomy", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const finding = document.findings[0]!;
    finding["title"] =
      "Signed payment webhook replay credits the same settlement twice";
    finding.summary =
      "The webhook validates the HMAC signature but accepts an unchanged captured request repeatedly because it never bounds the signed timestamp or atomically consumes the event ID before the financial credit.";
    finding["taxonomy"] = {
      category: "improper cryptographic verification",
      cwe: ["CWE-345"],
    };
    await writeJson(path, document);

    const completed = await completeScan(fixture);
    const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;

    expect(completed.progress.status).toBe("complete");
    expect(recovered["taxonomy"]).toEqual({
      category: "signed-webhook-replay",
      cwe: ["CWE-294"],
    });
  });

  test("normalizes catastrophic regex backtracking taxonomy", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const finding = document.findings[0]!;
    finding["title"] =
      "Alias validation regex permits unauthenticated event-loop denial of service";
    finding.summary =
      "A catastrophic-backtracking regular expression evaluates an attacker-controlled near-match with exponential work until a bounded VM witness times out, blocking the shared event loop.";
    finding["taxonomy"] = {
      category: "uncontrolled-resource-consumption",
      cwe: ["CWE-400"],
    };
    await writeJson(path, document);

    const completed = await completeScan(fixture);
    const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;

    expect(completed.progress.status).toBe("complete");
    expect(recovered["taxonomy"]).toEqual({
      category: "regular-expression-denial-of-service",
      cwe: ["CWE-1333"],
    });
  });

  test("normalizes fail-open authorization taxonomy", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const finding = document.findings[0]!;
    finding["title"] =
      "Policy-service exception bypasses signing-key authorization";
    finding.summary =
      "The authorizer defaults to allow and preserves that decision when the external policy check throws unavailable, letting a low-privilege user export a private signing key.";
    finding["taxonomy"] = {
      category: "improper-error-handling",
      cwe: ["CWE-755"],
    };
    await writeJson(path, document);

    const completed = await completeScan(fixture);
    const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;

    expect(completed.progress.status).toBe("complete");
    expect(recovered["taxonomy"]).toEqual({
      category: "fail-open-authorization",
      cwe: ["CWE-636", "CWE-863"],
    });
  });

  test("normalizes DNS-rebinding SSRF taxonomy", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const finding = document.findings[0]!;
    finding["title"] =
      "DNS rebinding reaches cloud metadata after destination validation";
    finding.summary =
      "The preview route approves a public DNS answer, but the HTTP client resolves the hostname again and connects to the link-local 169.254.169.254 metadata address.";
    finding["taxonomy"] = {
      category: "time-of-check-time-of-use",
      cwe: ["CWE-367"],
    };
    await writeJson(path, document);

    const completed = await completeScan(fixture);
    const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;

    expect(completed.progress.status).toBe("complete");
    expect(recovered["taxonomy"]).toEqual({
      category: "dns-rebinding-ssrf",
      cwe: ["CWE-918"],
    });
  });

  test("corrects browser-cache taxonomy for cross-principal web cache deception", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const finding = document.findings[0]!;
    finding["title"] = "Shared edge cache discloses authenticated responses";
    finding.summary =
      "Web cache deception stores a private response under an attacker-fetchable shared cache key, then returns it to an unauthenticated request.";
    finding["taxonomy"] = {
      category: "Web cache deception",
      cwe: ["CWE-525"],
    };
    await writeJson(path, document);

    const completed = await completeScan(fixture);
    const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;

    expect(completed.progress.status).toBe("complete");
    expect(recovered["taxonomy"]).toEqual({
      category: "web-cache-deception",
      cwe: ["CWE-524", "CWE-200"],
    });
  });

  test("normalizes cross-tenant application-cache key confusion taxonomy", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const finding = document.findings[0]!;
    finding["title"] =
      "Cross-tenant application cache hit returns another tenant's invoice";
    finding.summary =
      "The application cache key omits tenant identity, so a cached object populated by one authenticated tenant is returned to another tenant without the correctly scoped repository lookup.";
    finding["taxonomy"] = {
      category: "IDOR",
      cwe: ["CWE-639"],
    };
    await writeJson(path, document);

    const completed = await completeScan(fixture);
    const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;

    expect(completed.progress.status).toBe("complete");
    expect(recovered["taxonomy"]).toEqual({
      category: "authorization-cache-key-confusion",
      cwe: ["CWE-524", "CWE-862"],
    });
  });

  test("normalizes GraphQL resolver amplification to authentication-attempt taxonomy", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const finding = document.findings[0]!;
    finding["title"] = "GraphQL aliases bypass recovery-code request quota";
    finding.summary =
      "One accepted GraphQL-style document can invoke recovery-code verification once per attacker-controlled selection while the gateway increments its client quota only once. A successful later alias returns a reset token that changes the victim password.";
    finding["taxonomy"] = {
      category: "resource-management",
      cwe: ["CWE-770"],
    };
    await writeJson(path, document);

    const completed = await completeScan(fixture);
    const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;

    expect(completed.progress.status).toBe("complete");
    expect(recovered["taxonomy"]).toEqual({
      category: "graphql-operation-amplification",
      cwe: ["CWE-307", "CWE-799"],
    });
  });

  test("canonicalizes the GraphQL category when model CWEs already match", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const finding = document.findings[0]!;
    finding["title"] =
      "Unbounded GraphQL selections bypass recovery-code throttling";
    finding.summary =
      "An attacker submits many aliased recovery-code guesses in one request, receives a reset token when one matches, and changes the target password.";
    finding["taxonomy"] = {
      category: "Improper restriction of excessive authentication attempts",
      cwe: ["CWE-307", "CWE-799"],
    };
    await writeJson(path, document);

    const completed = await completeScan(fixture);
    const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;

    expect(completed.progress.status).toBe("complete");
    expect(recovered["taxonomy"]).toEqual({
      category: "graphql-operation-amplification",
      cwe: ["CWE-307", "CWE-799"],
    });
  });

  test("keeps relative finding paths repository-relative when the finalizer cwd is nested", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const repository = resolve(process.cwd(), "..", "..");
    const relativePath =
      "benchmarks/fixtures/javascript-graphql-recovery-amplification/src/graphql.js";
    const script = join(PLUGIN_ROOT, "scripts", "finalize_scan_contract.py");
    const program = [
      "import importlib.util",
      "import os",
      `spec = importlib.util.spec_from_file_location("finalizer_under_test", ${JSON.stringify(script)})`,
      "module = importlib.util.module_from_spec(spec)",
      "spec.loader.exec_module(module)",
      `os.environ["COPILOT_SECURITY_REPOSITORY"] = ${JSON.stringify(repository)}`,
      `os.chdir(${JSON.stringify(process.cwd())})`,
      `print(module._standalone_location_path(${JSON.stringify(relativePath)}))`,
      `print(module._standalone_location_path(${JSON.stringify(join(repository, ...relativePath.split("/")))}))`,
    ].join("\n");

    const result = spawnSync(python!, ["-I", "-B", "-c", program], {
      encoding: "utf8",
      windowsHide: true,
    });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim().split(/\r?\n/u)).toEqual([
      relativePath,
      relativePath,
    ]);
  });

  test("closes reviewed documentation and metadata instead of deferring coverage", async () => {
    const fixture = await startDraftScan();
    const coveragePath = join(fixture.scanDir, "coverage.json");
    const coverage = await readJson<{
      completeness: string;
      deferred: unknown[];
      surfaces: CoverageSurface[];
    }>(coveragePath);
    coverage.completeness = "partial";
    coverage.surfaces = [
      {
        id: "source",
        label: "src/extract.py",
        disposition: "reported",
        receiptRefs: [],
      },
      {
        id: "readme",
        label: "README.md",
        disposition: "needs_follow_up",
        notes: "Used README to confirm the authentication model.",
        receiptRefs: [],
      },
      {
        id: "package",
        label: "package.json",
        disposition: "needs_follow_up",
        notes: "Repository metadata.",
        receiptRefs: [],
      },
    ];
    coverage.deferred = [
      {
        id: "readme",
        reason: "Used README to confirm the authentication model.",
        surfaceIds: ["readme"],
      },
      {
        id: "package",
        reason: "Repository metadata.",
        surfaceIds: ["package"],
      },
    ];
    await writeJson(coveragePath, coverage);

    const scan = await completeScan(fixture);
    const recovered = await readJson<{
      completeness: string;
      deferred: unknown[];
      surfaces: CoverageSurface[];
    }>(coveragePath);

    expect(scan.progress.status).toBe("complete");
    expect(recovered.completeness).toBe("complete");
    expect(recovered.deferred).toEqual([]);
    expect(recovered.surfaces.slice(1)).toEqual([
      expect.objectContaining({
        label: "README.md",
        disposition: "no_issue_found",
      }),
      expect.objectContaining({
        label: "package.json",
        disposition: "no_issue_found",
      }),
    ]);
  });

  test("downgrades a complete claim when immutable inventory paths lack closure", async () => {
    const fixture = await startDraftScan();
    await writeFile(
      join(fixture.repository, "src", "silent.py"),
      "# no lexical risk signal\n",
    );
    const discoveryDirectory = join(
      fixture.scanDir,
      "artifacts",
      "02_discovery",
    );
    await mkdir(discoveryDirectory, { recursive: true });
    await writeFile(
      join(discoveryDirectory, "in_scope_files.txt"),
      "src/extract.py\nsrc/silent.py\n",
    );
    const coveragePath = join(fixture.scanDir, "coverage.json");
    const coverage = await readJson<CoverageDocument>(coveragePath);
    coverage.completeness = "complete";
    coverage.surfaces = [
      {
        id: "src-extract",
        label: "src/extract.py",
        disposition: "reported",
        receiptRefs: [],
      },
    ];
    coverage.deferred = [];
    await writeJson(coveragePath, coverage);

    const scan = await completeScan(fixture);
    const recovered = await readJson<{
      completeness: string;
      deferred: Array<{
        paths: string[];
        surfaceIds: string[];
      }>;
      surfaces: CoverageSurface[];
    }>(coveragePath);

    expect(scan.warnings).toContain(
      "Downgraded coverage to partial because 1 in-scope inventory path lacks a file-review closure.",
    );
    expect(recovered.completeness).toBe("partial");
    expect(recovered.surfaces).toContainEqual(
      expect.objectContaining({
        label: "src/silent.py",
        disposition: "needs_follow_up",
      }),
    );
    expect(recovered.deferred).toContainEqual(
      expect.objectContaining({
        paths: ["src/silent.py"],
      }),
    );
  });

  test("returns the authoritative directory snapshot contract at registration", async () => {
    const fixture = await startDraftScan();
    const registration = fixture.registration;
    const contract = registration["contract"] as {
      target: {
        allowedKinds: string[];
        displayName: string;
        targetId: string;
        requiredSnapshotDigest?: string;
      };
    };

    expect(registration["targetRevision"]).toBe("unversioned");
    expect(contract.target).toMatchObject({
      allowedKinds: ["directory_snapshot"],
      displayName: "repository",
      targetId: registration["targetId"],
      requiredSnapshotDigest: expect.stringMatching(
        /^copilot-security-snapshot\/v1:sha256:[a-f0-9]{64}$/,
      ),
    });
  });

  test("returns authoritative clean, dirty, and nested Git target contracts", async () => {
    for (const kind of ["clean", "dirty", "nested"] as const) {
      const fixture = await startDraftScan(kind);
      const registration = fixture.registration;
      const contract = registration["contract"] as {
        target: {
          allowedKinds: string[];
          targetId: string;
          requiredSnapshotDigest?: string;
        };
      };
      const revision = spawnSync(
        "git",
        ["-C", fixture.repository, "rev-parse", "HEAD"],
        { encoding: "utf8" },
      );

      expect(revision.status, revision.stderr).toBe(0);
      expect(registration["targetRevision"]).toBe(revision.stdout.trim());
      expect(registration["targetId"]).toBe(contract.target.targetId);
      expect(contract.target.allowedKinds).toEqual([
        kind === "clean" ? "git_revision" : "git_worktree",
      ]);
      if (kind === "clean") {
        expect(contract.target).not.toHaveProperty("requiredSnapshotDigest");
      } else {
        expect(contract.target.requiredSnapshotDigest).toMatch(
          /^copilot-security-snapshot\/v1:sha256:[a-f0-9]{64}$/,
        );
      }
      if (kind === "nested") {
        const copied = spawnSync(
          fixture.python,
          [
            "-I",
            "-B",
            "-c",
            [
              "import sys",
              "from pathlib import Path",
              "sys.path.insert(0, sys.argv[1])",
              "import workbench_target as target",
              "source = Path(sys.argv[2])",
              "checkout = target.copy_git_worktree_files(source, Path(sys.argv[3]), ())",
              "git_dir = Path(target.git_output(source, 'rev-parse', '--absolute-git-dir'))",
              "assert target.worktree_content_digest_for_context(checkout, '.', git_dir=git_dir, work_tree=checkout) == target.worktree_content_digest(source)",
            ].join("\n"),
            join(PLUGIN_ROOT, "scripts"),
            fixture.repository,
            join(fixture.stateDir, "checkout"),
          ],
          { encoding: "utf8" },
        );
        expect(copied.status, copied.stderr).toBe(0);
      }
    }
  });

  test("seals a prepared scan without publishing it before acceptance", async () => {
    const fixture = await startDraftScan();

    const prepared = await workbench(fixture, [
      "prepare-scan-completion",
      "--scan-id",
      fixture.scanId,
    ]);

    expect((prepared["scan"] as ScanSummary).progress.status).toBe("running");
    const manifest = await readJson<{
      scan: { sealedAt: string; completedAt: string };
    }>(join(fixture.scanDir, "scan-manifest.json"));
    expect(manifest.scan.sealedAt).toBe(manifest.scan.completedAt);
    const running = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((running["scan"] as ScanSummary).progress.status).toBe("running");
    expect((await completeScan(fixture)).progress.status).toBe("complete");
  });

  test("marks rejected prepared scans as failed without publishing completion", async () => {
    const fixture = await startDraftScan();
    await workbench(fixture, [
      "prepare-scan-completion",
      "--scan-id",
      fixture.scanId,
    ]);
    await writeFile(join(fixture.scanDir, "findings.json"), "corrupted\n");

    const failed = await workbench(fixture, [
      "fail-scan",
      "--scan-id",
      fixture.scanId,
      "--message",
      "Sealed scan could not be accepted.",
    ]);

    expect((failed["scan"] as ScanSummary).progress.status).toBe("failed");
    const stored = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((stored["scan"] as ScanSummary).progress.status).toBe("failed");
  });

  test("normalizes finding identities and persists recovery warnings", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const finding = document.findings[0]!;
    finding.ruleId = "Path Traversal: Archive Extraction";
    finding.identity.anchor = "Archive Entry Write Without Containment";
    finding.identity.instance = "User Input #1";
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(1);
    expect(completed.warnings).toEqual([
      "Recovered finding 1: normalized rule identifier, semantic anchor, instance.",
    ]);
    const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;
    expect(recovered.ruleId).toBe("path-traversal-archive-extraction");
    expect(recovered.identity).toEqual({
      anchor: "archive-entry-write-without-containment",
      instance: "user-input-1",
    });
    const saved = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((saved["scan"] as unknown as ScanSummary).warnings).toEqual(
      completed.warnings,
    );
  });

  test("preserves recovery warnings across prepared scan completion", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    document.findings[0]!.identity.anchor = "Archive Entry Without Containment";
    await writeJson(path, document);

    const prepared = await workbench(fixture, [
      "prepare-scan-completion",
      "--scan-id",
      fixture.scanId,
    ]);
    const warning = "Recovered finding 1: normalized semantic anchor.";

    expect((prepared["scan"] as ScanSummary).progress.status).toBe("running");
    expect((prepared["scan"] as ScanSummary).warnings).toEqual([warning]);
    const completed = await completeScan(fixture);
    expect(completed.progress.status).toBe("complete");
    expect(completed.warnings).toEqual([warning]);
    const saved = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((saved["scan"] as ScanSummary).warnings).toEqual([warning]);
  });

  test("keeps a finding while pruning dangling attack-path evidence references", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const finding = document.findings[0]!;
    finding.codeEvidence = [
      {
        id: "cors-policy",
        label: "Credentialed CORS policy",
        path: "src/extract.py",
        startLine: 1,
        code: "# fixture",
        explanation: "The declared code evidence remains available.",
      },
    ];
    finding["attackPath"] = {
      summary: "Attacker JavaScript reads a credentialed response.",
      evidenceRefs: [
        "cors-policy",
        "artifacts/02_discovery/validation_artifacts/cors/result.txt",
      ],
    };
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(1);
    expect(completed.warnings).toEqual([
      "Recovered finding 1: removed 1 unknown attack-path code-evidence reference.",
    ]);
    const recovered = await readJson<FindingsDocument>(path);
    expect(recovered.findings[0]?.["attackPath"]).toEqual({
      summary: "Attacker JavaScript reads a credentialed response.",
      evidenceRefs: ["cors-policy"],
    });
    const coverage = await readJson<CoverageDocument>(
      join(fixture.scanDir, "coverage.json"),
    );
    expect(coverage.completeness).toBe("complete");
    expect(coverage.deferred).toEqual([]);
  });

  test("keeps valid findings and skips malformed or duplicate findings", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const valid = document.findings[0]!;
    const missingSummary = structuredClone(valid);
    missingSummary.identity.anchor = "missing-summary";
    missingSummary.summary = "";
    const unsafeLocation = structuredClone(valid);
    unsafeLocation.identity.anchor = "unsafe-location";
    unsafeLocation.locations[0]!.path = "../outside.py";
    const missingIdentity = structuredClone(valid);
    delete (missingIdentity as Partial<Finding>).identity;
    document.findings.push(
      missingSummary,
      unsafeLocation,
      missingIdentity,
      structuredClone(valid),
      null,
    );
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(1);
    expect(completed.warnings).toHaveLength(5);
    expect(
      completed.warnings.every((warning) =>
        warning.startsWith("Skipped malformed finding"),
      ),
    ).toBe(true);
    for (const reason of [
      "summary",
      "safe repository-relative",
      "identity",
      "duplicate logical finding",
      "expected an object",
    ]) {
      expect(
        completed.warnings.some((warning) => warning.includes(reason)),
      ).toBe(true);
    }
    expect((await readJson<FindingsDocument>(path)).findings).toHaveLength(1);
    const coverage = await readJson<CoverageDocument>(
      join(fixture.scanDir, "coverage.json"),
    );
    expect(coverage.completeness).toBe("partial");
    expect((coverage.surfaces as CoverageSurface[])[0]?.disposition).toBe(
      "needs_follow_up",
    );
    expect(coverage.deferred).toHaveLength(4);
  });

  test("retains the strongest duplicate finding regardless of input order", async () => {
    const cases = [
      {
        name: "severity ascending",
        candidates: [
          ["informational", "high", 1],
          ["critical", "high", 1],
        ],
        expected: ["critical", "high", 1],
      },
      {
        name: "severity descending",
        candidates: [
          ["critical", "high", 1],
          ["informational", "high", 1],
        ],
        expected: ["critical", "high", 1],
      },
      {
        name: "confidence ascending",
        candidates: [
          ["critical", "low", 1],
          ["critical", "high", 1],
        ],
        expected: ["critical", "high", 1],
      },
      {
        name: "confidence descending",
        candidates: [
          ["critical", "high", 1],
          ["critical", "low", 1],
        ],
        expected: ["critical", "high", 1],
      },
      {
        name: "evidence ascending",
        candidates: [
          ["critical", "high", 1],
          ["critical", "high", 2],
        ],
        expected: ["critical", "high", 2],
      },
      {
        name: "evidence descending",
        candidates: [
          ["critical", "high", 2],
          ["critical", "high", 1],
        ],
        expected: ["critical", "high", 2],
      },
    ] as const;

    for (const { name, candidates, expected } of cases) {
      const fixture = await startDraftScan();
      const path = join(fixture.scanDir, "findings.json");
      const document = await readJson<FindingsDocument>(path);
      const baseline = document.findings[0]!;
      document.findings = candidates.map(([severity, confidence, count]) => {
        const finding = structuredClone(baseline);
        finding.severity.level = severity;
        finding.confidence.level = confidence;
        finding.codeEvidence = Array.from({ length: count }, (_, index) => ({
          id: `evidence-${index + 1}`,
          label: "Archive extraction",
          path: "src/extract.py",
          startLine: 1,
          code: "# fixture",
          explanation: "The archive entry reaches a filesystem write.",
        }));
        return finding;
      });
      await writeJson(path, document);

      const completed = await completeScan(fixture);

      expect(completed.progress.status, name).toBe("complete");
      expect(completed.findingCount, name).toBe(1);
      expect(completed.warnings, name).toHaveLength(1);
      expect(completed.warnings[0], name).toContain(
        "duplicate logical finding",
      );
      const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;
      expect(
        [
          recovered.severity.level,
          recovered.confidence.level,
          recovered.codeEvidence?.length,
        ],
        name,
      ).toEqual([...expected]);
      const coverage = await readJson<CoverageDocument>(
        join(fixture.scanDir, "coverage.json"),
      );
      expect(coverage.completeness, name).toBe("complete");
      expect(
        await readFile(join(fixture.scanDir, "report.md"), "utf8"),
        name,
      ).not.toContain("### No findings");
      const sarif = await readJson<SarifDocument>(
        join(fixture.scanDir, "exports", "results.sarif"),
      );
      expect(sarif.runs[0]?.results[0]?.properties.severity, name).toBe(
        "critical",
      );
    }
  });

  test("completes scans when every draft finding is malformed", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    document.findings[0]!.summary = "";
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(0);
    expect(completed.warnings).toHaveLength(1);
    expect(completed.warnings[0]).toContain("summary");
    expect((await readJson<FindingsDocument>(path)).findings).toEqual([]);
    const coverage = await readJson<CoverageDocument>(
      join(fixture.scanDir, "coverage.json"),
    );
    expect(coverage.completeness).toBe("partial");
    expect((coverage.surfaces as CoverageSurface[])[0]?.disposition).toBe(
      "needs_follow_up",
    );
    expect(coverage.deferred).toEqual([
      { id: "discarded-finding-1", reason: completed.warnings[0] },
    ]);
    const report = await readFile(join(fixture.scanDir, "report.md"), "utf8");
    expect(report).toContain("| Coverage | partial |");
    expect(report).toContain("Skipped malformed finding 1");
    const sarif = await readJson<SarifDocument>(
      join(fixture.scanDir, "exports", "results.sarif"),
    );
    expect(sarif.runs[0]?.properties.copilotSecurityCoverageCompleteness).toBe(
      "partial",
    );
    expect(sarif.runs[0]?.invocations).toEqual([
      {
        executionSuccessful: true,
        toolExecutionNotifications: [
          { level: "warning", message: { text: completed.warnings[0]! } },
        ],
      },
    ]);
  });

  test("keeps findings while removing invalid or duplicate writeups", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const valid = document.findings[0]!;
    const reportPath = "findings/linked-writeup/linked-writeup.md";
    await mkdir(join(fixture.scanDir, "findings", "linked-writeup"), {
      recursive: true,
    });
    await writeFile(join(fixture.scanDir, reportPath), "# Verified finding\n");

    for (const [anchor, writeup] of [
      ["linked-writeup", { reportPath }],
      ["duplicate-writeup", { reportPath }],
      ["missing-writeup", { reportPath: "findings/missing/missing.md" }],
      ["unsafe-writeup", { reportPath: "../outside.md" }],
      ["invalid-writeup", "not an object"],
    ] as const) {
      const finding = structuredClone(valid);
      finding.identity.anchor = anchor;
      finding.writeup = writeup;
      document.findings.push(finding);
    }
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(6);
    expect(completed.warnings).toHaveLength(4);
    expect(
      completed.warnings.every((warning) =>
        warning.startsWith("Skipped malformed writeup for finding"),
      ),
    ).toBe(true);
    expect(completed.warnings.join("\n")).not.toContain("../outside.md");
    const recovered = (await readJson<FindingsDocument>(path)).findings;
    expect(
      recovered.find((finding) => finding?.identity.anchor === "linked-writeup")
        ?.writeup,
    ).toEqual({ reportPath });
    for (const anchor of [
      "duplicate-writeup",
      "missing-writeup",
      "unsafe-writeup",
      "invalid-writeup",
    ]) {
      expect(
        recovered.find((finding) => finding?.identity.anchor === anchor),
      ).not.toHaveProperty("writeup");
    }
  });

  test("keeps verified coverage receipts and downgrades invalid coverage", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "coverage.json");
    const document = await readJson<CoverageDocument>(path);
    const receipt = "artifacts/02_discovery/work_ledger.jsonl";
    await mkdir(join(fixture.scanDir, "artifacts", "02_discovery"), {
      recursive: true,
    });
    await writeFile(join(fixture.scanDir, receipt), '{"status":"reviewed"}\n');
    const surface = (document.surfaces as CoverageSurface[])[0]!;
    surface.receiptRefs = [
      receipt,
      "report.md",
      "../outside.json",
      "artifacts/02_discovery/missing.jsonl",
      null,
    ];
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.warnings).toHaveLength(4);
    expect(
      completed.warnings.every((warning) =>
        warning.startsWith("Skipped malformed coverage receipt"),
      ),
    ).toBe(true);
    expect(completed.warnings.join("\n")).not.toContain("../outside.json");
    const recovered = await readJson<CoverageDocument>(path);
    expect(recovered.completeness).toBe("partial");
    expect((recovered.surfaces as CoverageSurface[])[0]).toMatchObject({
      disposition: "needs_follow_up",
      receiptRefs: [receipt],
    });
    const manifest = await readJson<{
      scan: { artifacts: Array<{ path: string }> };
    }>(join(fixture.scanDir, "scan-manifest.json"));
    expect(manifest.scan.artifacts.map((artifact) => artifact.path)).toContain(
      receipt,
    );
  });

  test("downgrades malformed coverage collections without claiming completeness", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "coverage.json");
    const document = await readJson<CoverageDocument>(path);
    document.completeness = "finished";
    document.surfaces = { id: "not-an-array" };
    document.explicitExclusions = null;
    document.deferred = "later";
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.warnings).toHaveLength(4);
    const recovered = await readJson<CoverageDocument>(path);
    expect(recovered).toMatchObject({
      completeness: "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    });
  });

  test("discards unsafe hardening portfolios without discarding findings", async () => {
    for (const hardening of [
      "not an object",
      { portfolioPath: "../outside.md" },
      { portfolioPath: "hardening/hardening.md" },
    ]) {
      const fixture = await startDraftScan();
      const path = join(fixture.scanDir, "scan-manifest.json");
      const manifest = await readJson<{
        scan: { hardening?: unknown };
      }>(path);
      manifest.scan.hardening = hardening;
      await writeJson(path, manifest);

      const completed = await completeScan(fixture);

      expect(completed.progress.status).toBe("complete");
      expect(completed.findingCount).toBe(1);
      expect(completed.warnings).toHaveLength(1);
      expect(completed.warnings[0]).toContain(
        "Skipped malformed hardening portfolio:",
      );
      expect(completed.warnings[0]).not.toContain("../outside.md");
      expect(
        (await readJson<{ scan: { hardening?: unknown } }>(path)).scan,
      ).not.toHaveProperty("hardening");
    }
  });

  test("keeps direct finalization strict unless recovery is explicitly enabled", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    document.findings[0]!.identity.anchor = "Invalid Anchor";
    await writeJson(path, document);

    const strict = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        join(PLUGIN_ROOT, "scripts", "finalize_scan_contract.py"),
        "--scan-dir",
        fixture.scanDir,
      ],
      { encoding: "utf8" },
    );

    expect(strict.status).not.toBe(0);
    expect(strict.stderr).toContain("stable lowercase semantic slug");
    expect((await completeScan(fixture)).findingCount).toBe(1);
  });

  test("refuses to repair scan-wide coverage contract violations", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "coverage.json");
    const document = await readJson<CoverageDocument>(path);
    document.inventoryStrategy = "";
    await writeJson(path, document);
    const original = await readFile(path, "utf8");

    await expect(completeScan(fixture)).rejects.toThrow("inventoryStrategy");
    expect(await readFile(path, "utf8")).toBe(original);
  });
});
