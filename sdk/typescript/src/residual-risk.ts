import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { extname, isAbsolute, join, relative, resolve } from "node:path";
import {
  isSubstantiveAttackPath,
  isSubstantiveCodeEvidence,
  isSubstantiveValidation,
  type EvidenceLocation,
} from "./evidence-quality.js";

const MAX_FILES = 2_000;
const MAX_FILE_BYTES = 256 * 1024;
const MAX_TOTAL_BYTES = 8 * 1024 * 1024;
const MAX_CANDIDATES = 4_096;
const MAX_SIGNALS = 96;
const MAX_SIGNALS_PER_FILE = MAX_SIGNALS;
const MAX_COVERAGE_GAPS = 256;
const MAX_FINDING_QUALITY_GAPS = 256;
const MAX_INVENTORY_BYTES = 8 * 1024 * 1024;
const MAX_COVERAGE_BYTES = 32 * 1024 * 1024;
const MAX_FINDINGS_BYTES = 128 * 1024 * 1024;
const CONTEXT_LINES_BEFORE = 3;
const CONTEXT_LINES_AFTER = 5;
const MAX_EXCERPT_LINES = 16;
const SOFT_SIGNALS_PER_FILE = 4;
const CLOSED_COVERAGE_DISPOSITIONS = new Set([
  "reported",
  "no_issue_found",
  "rejected",
  "not_applicable",
]);

const SOURCE_EXTENSIONS = new Set([
  ".c",
  ".cc",
  ".clj",
  ".cljs",
  ".cjs",
  ".coffee",
  ".cpp",
  ".cs",
  ".dart",
  ".ex",
  ".exs",
  ".erl",
  ".fs",
  ".fsx",
  ".go",
  ".groovy",
  ".gvy",
  ".h",
  ".hpp",
  ".hrl",
  ".java",
  ".js",
  ".jsx",
  ".kt",
  ".kts",
  ".lua",
  ".m",
  ".mjs",
  ".mm",
  ".php",
  ".pl",
  ".pm",
  ".ps1",
  ".py",
  ".rb",
  ".rego",
  ".rs",
  ".scala",
  ".sh",
  ".sol",
  ".sql",
  ".svelte",
  ".swift",
  ".tf",
  ".ts",
  ".tsx",
  ".vb",
  ".vue",
  ".xml",
  ".yaml",
  ".yml",
]);

const RISK_SIGNALS: ReadonlyArray<
  readonly [category: string, priority: number, expression: RegExp]
> = [
  [
    "archive-or-attacker-path",
    90,
    /\b(?:arcname|entry|filename|member|tarinfo|zipentry)\b|\.(?:filename|getName|name)\b/iu,
  ],
  [
    "untrusted-input",
    92,
    /\b(?:req|request)\.(?:body|cookies|data|files|form|headers|json|params|query|values)\b|\b(?:req|request)\.get_json\s*\(|\b(?:process|sys)\.argv\b|\b(?:environ|getenv|stdin)\b|\bgetParameter\s*\(/iu,
  ],
  [
    "authentication-or-session",
    94,
    /\b(?:authorization|bearer|cookie|jwt|login|oauth|oidc|session|token)\b|\b(?:authenticate|decode|verify)\s*\(/iu,
  ],
  [
    "browser-ambient-credential-or-csrf",
    96,
    /\b(?:anti[_-]?forgery|antiforgery|csrf|xsrf)\b|\b(?:SameSite|Sec-Fetch-Site)\b|\bsame_?site\s*[:=]\s*["']?none\b|\bValidateAntiForgeryToken\b/iu,
  ],
  [
    "oauth-authorization-code-transaction-binding",
    100,
    /\b(?:authorizationUrl|authorizeUrl|codeChallenge|codeChallengeMethod|codeVerifier|exchangeCode|pkce|redirectUri|responseType)\b|\b(?:oauth|oidc)[\w./-]*(?:callback|link|redirect)\b/iu,
  ],
  [
    "oauth-account-linking-identity-binding",
    99,
    /\b(?:beginExternalIdentityLink|completeExternalIdentityLink|externalLinks|linkExternalIdentity|loginExternal)\b/iu,
  ],
  [
    "login-session-fixation-and-rotation",
    101,
    /\b(?:changeSessionId|destroySession|invalidateSession|promoteAuthenticatedSession|regenerateSession|renewSession|rotateAuthenticatedSession|startAnonymousSession)\b|\b(?:sessionId|sessionID)\b/iu,
  ],
  [
    "security-sensitive-randomness",
    97,
    /\b(?:Math\.random|crypto\.randomBytes|randomBytes|randomUUID|SecureRandom|secrets\.(?:choice|randbelow|token_bytes|token_hex|token_urlsafe)|crypto\.getRandomValues|random\.(?:random|randint|randrange)|mt_rand|srand|uuid1)\s*\(/iu,
  ],
  [
    "filesystem-write",
    80,
    /\b(?:copyfile|createWriteStream|extract|extractall|makedirs|mkdir|move|open|rename|sendFile|write_bytes|write_text|writeFile|writeFileSync)\b/iu,
  ],
  [
    "untrusted-file-upload-or-content-placement",
    99,
    /\b(?:formidable|IFormFile|move_uploaded_file|MultipartFile|multipart|multer|originalname|uploadedFile|uploadPlugin)\b|\b(?:req|request)\.file\b/iu,
  ],
  [
    "process-or-shell",
    100,
    /\b(?:child_process|execFile|execSync|popen|ProcessBuilder|Runtime\.getRuntime|spawn|spawnSync|subprocess)\b|\b(?:exec|system)\s*\(|\bshell\s*[:=]\s*true\b/iu,
  ],
  [
    "dynamic-code-or-template",
    95,
    /\b(?:compile|eval|execScript|Function|render|renderString|template)\s*\(/iu,
  ],
  [
    "dynamic-module-or-plugin-load",
    97,
    /\b(?:activatePlugins|extensionDirectory|loadPlugins|pluginDirectory)\b|\bimport\s*\(\s*(?!["'`])/iu,
  ],
  [
    "template-source-evaluation",
    98,
    /\b(?:from_string|parseExpression|compileExpression|render_template_string)\s*\(|\bnew\s+(?:Function|Template)\s*\(|\bTemplate\s*\(/iu,
  ],
  [
    "dynamic-property-or-prototype",
    96,
    /\b(?:__proto__|Object\.assign|Object\.setPrototypeOf|prototype)\b|\[[A-Za-z_$][\w$]*\]\s*(?:=|\?\?=|\|\|=)/iu,
  ],
  [
    "bulk-object-write-or-mass-assignment",
    98,
    /\bObject\.assign\s*\([^,\r\n]+,\s*(?:req|request)\.(?:body|data|form|json|values)\b|\{\s*\.\.\.\s*(?:req|request)\.(?:body|data|form|json|values)\b|\.(?:merge|update)\s*\(\s*(?:req|request)\.(?:body|data|form|json|values)\b|\b(?:findByIdAndUpdate|findOneAndUpdate|updateMany|updateOne)\s*\([^,\r\n]+,\s*(?:req|request)\.(?:body|data|form|json|values)\b|\b(?:assign_attributes|update_attributes)\s*\(\s*(?:params\b|(?:req|request)\.)|\b(?:BeanUtils|PropertyUtils)\.copyProperties\s*\(\s*(?:req|request)\b|\b(?:fill|forceFill)\s*\(\s*(?:req|request)\b/iu,
  ],
  [
    "query-or-object-lookup",
    85,
    /\b(?:execute|findById|findOne|getById|query|raw|select|where)\s*\(/iu,
  ],
  [
    "document-query-or-nosql-operator",
    96,
    /\b(?:aggregate|findOne|findOneAndDelete|findOneAndReplace|findOneAndUpdate|mongo|mongoose)\s*\(|["'`]?\$(?:all|and|elemMatch|eq|expr|gt|gte|in|lt|lte|ne|nin|nor|not|or|regex|size|where)\b/iu,
  ],
  [
    "ldap-filter-construction-or-directory-query",
    99,
    /\b(?:directorySubject|distinguishedName|escapeLdapFilterAssertion|ldapFilter|principalDn|searchOne)\b|\b(?:LDAP|LdapConnection|SearchRequest|DirectorySearcher)\b/iu,
  ],
  [
    "ldap-authorization-membership-binding",
    98,
    /\b(?:administrators|memberOf|principalDnForUser|requireDirectoryAdministrator)\b/iu,
  ],
  [
    "xpath-or-xquery-construction",
    99,
    /\b(?:XPath|XQuery|evaluateXPath|selectNodes?|selectSingleNode)\b|\b(?:document|xpath)\.evaluate\s*\(|\/[A-Za-z_][\w.-]*(?:\/[A-Za-z_][\w.-]*)*\s*\[/iu,
  ],
  [
    "xml-query-authentication-binding",
    98,
    /\b(?:authenticateDirectoryUser|passwordVerifier|ACCOUNT_EXPRESSION)\b|\b(?:role|session|username)\s*[:.=]/iu,
  ],
  [
    "authorization-boundary",
    85,
    /\b(?:account_?id|customer_?id|object_?id|owner_?id|req\.params|request\.params|tenant_?id|user_?id)\b/iu,
  ],
  [
    "state-or-check-use-boundary",
    91,
    /\b(?:compare_and_set|compareAndSet|for_update|get_[a-z][a-z0-9_]*|lstat|mark_[a-z][a-z0-9_]*|optimistic_lock|read_[a-z][a-z0-9_]*|row_version|transaction|update_[a-z][a-z0-9_]*)\s*\(|\b(?:access|exists|rename|replace|stat)\s*\(/iu,
  ],
  [
    "network-request",
    80,
    /\b(?:axios|fetch|http\.get|http\.request|requests\.(?:get|post|put|delete)|urlopen)\s*\(/iu,
  ],
  [
    "parser-or-deserializer",
    90,
    /\b(?:deserialize|load|loads|ObjectInputStream|parse|pickle|readObject|unmarshal|urlencoded|yaml\.load)\s*\(/iu,
  ],
  [
    "http-message-framing-or-request-smuggling",
    99,
    /\b(?:content-length|transfer-encoding|chunked|rawHeaders|rawRequest|rawRequests|consumeChunkedBody|messageEnd)\b/iu,
  ],
  [
    "proxy-gateway-or-multi-hop-request-boundary",
    96,
    /\b(?:authorizeAndForward|forwardedHeaders|processBackendPipeline|proxy_pass|reverseProxy|trustedProxy|upstreamRequest)\b/iu,
  ],
  [
    "xml-or-entity-parser",
    93,
    /\b(?:DocumentBuilderFactory|fromstring|lxml|SAXParserFactory|XMLParser)\b|\b(?:disallow-doctype-decl|external-general-entities|load_dtd|no_network|resolve_entities)\b/iu,
  ],
  [
    "cryptographic-verification",
    75,
    /\b(?:crypto|decrypt|encrypt|hash|hmac|jwt|signature|verify)\b/iu,
  ],
  [
    "jwt-oidc-remote-key-origin",
    100,
    /\b(?:createRemoteJWKSet|fetchJwks|jwksUri|jku|x5u)\b|\b(?:header|protectedHeader)\s*(?:\.|\[\s*["'])\s*(?:jku|kid|x5u)\b/iu,
  ],
  [
    "jwt-oidc-claim-binding",
    98,
    /\b(?:expectedAudience|expectedIssuer|maxTokenAgeSeconds|pendingNonces)\b|\bclaims\s*\.\s*(?:aud|exp|iat|iss|nonce|sub)\b/iu,
  ],
  [
    "saml-federation-or-assertion-boundary",
    98,
    /\b(?:acsUrl|assertion|assertions|audience|identityProvider|recipient|SAML|SubjectConfirmation)\b/iu,
  ],
  [
    "signed-versus-consumed-object-binding",
    100,
    /\b(?:foundValid|referenceId|signatureValue|signedAssertion|validatedAssertion)\b|\bassertions\s*\[\s*(?:0|assertionIndex)\s*\]/iu,
  ],
  [
    "unsafe-memory-operation",
    98,
    /\b(?:copy_from_user|gets|memcpy|memmove|readv|recv|recvfrom|scanf|snprintf|sprintf|strcat|strcpy|strncat|strncpy|vsnprintf|vsprintf)\s*\(/iu,
  ],
  [
    "browser-or-response-injection",
    85,
    /\b(?:dangerouslySetInnerHTML|document\.write|innerHTML|mark_safe|redirect|Response\.Write)\b|\.(?:send|write)\s*\(/iu,
  ],
  [
    "disabled-security-control",
    95,
    /\b(?:check_hostname|rejectUnauthorized|verify|verify_mode)\s*[:=]\s*(?:false|0|none|ssl\.CERT_NONE)\b|\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0\b/iu,
  ],
];

const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  ".venv",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "target",
  "vendor",
]);

interface ResidualRiskRecord {
  path: string;
  line: number;
  categories: string[];
  priority: number;
  startLine: number;
  endLine: number;
  excerpt: string;
}

interface CoverageSurfaceDraft {
  label?: unknown;
  disposition?: unknown;
}

interface CoverageGapRecord {
  path: string;
  reason:
    | "missing_coverage_surface"
    | "needs_follow_up"
    | "invalid_coverage_disposition"
    | "conflicting_coverage_surfaces";
  dispositions?: string[];
}

type FindingQualityGapReason =
  | "missing_explicit_cwe"
  | "missing_or_unanchored_code_evidence"
  | "missing_or_weak_validation"
  | "missing_validation_method"
  | "missing_exploit_witness"
  | "missing_negative_control"
  | "missing_validation_evidence"
  | "missing_counterevidence"
  | "missing_remaining_uncertainty"
  | "missing_or_weak_attack_path"
  | "incomplete_attack_path_dataflow"
  | "incomplete_attack_path_reachability"
  | "missing_broken_controls"
  | "missing_attack_path_evidence_refs"
  | "non_reportable_validation_disposition"
  | "non_reportable_attack_path_decision";

interface FindingQualityGapRecord {
  findingIndex: number;
  findingId: string;
  reasons: FindingQualityGapReason[];
}

export async function buildResidualRiskInventory(
  repository: string,
  scanDirectory?: string,
): Promise<string> {
  const canonicalRepository = await realpath(repository);
  const inventoryPaths =
    scanDirectory === undefined
      ? []
      : await readModelInventoryPaths(scanDirectory, canonicalRepository);
  const paths =
    inventoryPaths.length > 0
      ? inventoryPaths
      : await discoverSourcePaths(canonicalRepository);
  const records: ResidualRiskRecord[] = [];
  let totalBytes = 0;

  for (const candidatePath of paths.slice(0, MAX_FILES)) {
    const source = await readBoundedRepositoryFile(
      canonicalRepository,
      candidatePath,
    );
    if (source === null) continue;
    totalBytes += source.byteLength;
    if (totalBytes > MAX_TOTAL_BYTES) break;
    const text = source.toString("utf8");
    if (text.includes("\0")) continue;
    const lines = text.split(/\r?\n/u);
    let fileRecords: ResidualRiskRecord[] = [];
    const retainedFileRecords: ResidualRiskRecord[] = [];
    for (let index = 0; index < lines.length; index += 1) {
      const matchingSignals = RISK_SIGNALS.filter(([, , expression]) =>
        expression.test(lines[index] ?? ""),
      );
      const categories = matchingSignals.map(([category]) => category);
      if (categories.length === 0) continue;
      const startLine = Math.max(1, index + 1 - CONTEXT_LINES_BEFORE);
      const endLine = Math.min(lines.length, index + 1 + CONTEXT_LINES_AFTER);
      mergeResidualRiskRecord(fileRecords, lines, {
        path: candidatePath.replaceAll("\\", "/"),
        line: index + 1,
        categories,
        priority: Math.max(...matchingSignals.map(([, priority]) => priority)),
        startLine,
        endLine,
        excerpt: "",
      });
      if (fileRecords.length >= MAX_CANDIDATES) {
        retainedFileRecords.push(
          ...selectResidualRiskRecords(fileRecords, MAX_SIGNALS_PER_FILE),
        );
        fileRecords = [];
      }
    }
    records.push(
      ...selectResidualRiskRecords(
        [...retainedFileRecords, ...fileRecords],
        MAX_SIGNALS_PER_FILE,
      ),
    );
  }

  return selectResidualRiskRecords(records, MAX_SIGNALS)
    .map(({ priority: _priority, excerpt, ...record }) =>
      JSON.stringify({
        ...record,
        excerptEncoding: "base64",
        excerptBase64: Buffer.from(excerpt, "utf8").toString("base64"),
      }),
    )
    .join("\n");
}

export async function buildCoverageGapInventory(
  scanDirectory: string | undefined,
): Promise<string> {
  if (scanDirectory === undefined) return "";
  const canonicalScanDirectory = await realpath(scanDirectory).catch(
    () => null,
  );
  if (canonicalScanDirectory === null) return "";
  const inventory = await readBoundedScanFile(
    canonicalScanDirectory,
    join("artifacts", "02_discovery", "in_scope_files.txt"),
    MAX_INVENTORY_BYTES,
  );
  if (inventory === null) return "";
  const inventoryPaths = parseInventoryPaths(inventory.toString("utf8"));
  if (inventoryPaths.length === 0) return "";

  const coverageBytes = await readBoundedScanFile(
    canonicalScanDirectory,
    "coverage.json",
    MAX_COVERAGE_BYTES,
  );
  const coverage = parseCoverageSurfaces(coverageBytes);
  const surfacesByPath = new Map<string, CoverageSurfaceDraft[]>();
  for (const surface of coverage.surfaces) {
    if (
      typeof surface.label !== "string" ||
      !isSafeInventoryPath(surface.label)
    ) {
      continue;
    }
    const surfaces = surfacesByPath.get(surface.label) ?? [];
    surfaces.push(surface);
    surfacesByPath.set(surface.label, surfaces);
  }

  let coveredPathCount = 0;
  const gaps: CoverageGapRecord[] = [];
  for (const path of inventoryPaths) {
    const surfaces = surfacesByPath.get(path) ?? [];
    const dispositions = [
      ...new Set(
        surfaces
          .map((surface) => surface.disposition)
          .filter(
            (disposition): disposition is string =>
              typeof disposition === "string",
          ),
      ),
    ].sort((left, right) => left.localeCompare(right));
    const closed = surfaces.filter(
      (surface) =>
        typeof surface.disposition === "string" &&
        CLOSED_COVERAGE_DISPOSITIONS.has(surface.disposition),
    );
    if (surfaces.length === 0) {
      gaps.push({ path, reason: "missing_coverage_surface" });
    } else if (closed.length === 0) {
      gaps.push({
        path,
        reason:
          dispositions.length > 0 &&
          dispositions.every((disposition) => disposition === "needs_follow_up")
            ? "needs_follow_up"
            : "invalid_coverage_disposition",
        dispositions,
      });
    } else if (surfaces.length > 1) {
      gaps.push({
        path,
        reason: "conflicting_coverage_surfaces",
        dispositions,
      });
    } else {
      coveredPathCount += 1;
    }
  }

  const selected = gaps.sort(compareCoverageGaps).slice(0, MAX_COVERAGE_GAPS);
  return [
    JSON.stringify({
      type: "coverage-gap-summary",
      inventoryPathCount: inventoryPaths.length,
      coveredPathCount,
      gapCount: gaps.length,
      emittedGapCount: selected.length,
      omittedGapCount: gaps.length - selected.length,
      coverageReadable: coverage.readable,
    }),
    ...selected.map((gap) => JSON.stringify(gap)),
  ].join("\n");
}

export async function buildFindingQualityGapInventory(
  scanDirectory: string | undefined,
): Promise<string> {
  if (scanDirectory === undefined) return "";
  const canonicalScanDirectory = await realpath(scanDirectory).catch(
    () => null,
  );
  if (canonicalScanDirectory === null) return "";
  const findingsBytes = await readBoundedScanFile(
    canonicalScanDirectory,
    "findings.json",
    MAX_FINDINGS_BYTES,
  );
  if (findingsBytes === null) {
    return findingQualityInventoryFailure("missing_findings_document");
  }

  let document: unknown;
  try {
    document = JSON.parse(findingsBytes.toString("utf8")) as unknown;
  } catch {
    return findingQualityInventoryFailure("invalid_findings_json");
  }
  if (!isRecord(document) || !Array.isArray(document["findings"])) {
    return findingQualityInventoryFailure("invalid_findings_document");
  }

  const findings = document["findings"];
  const gaps: FindingQualityGapRecord[] = [];
  for (let index = 0; index < findings.length; index += 1) {
    const finding = findings[index];
    const reasons: FindingQualityGapReason[] = [];
    if (!isRecord(finding)) {
      gaps.push({
        findingIndex: index,
        findingId: `finding-${index + 1}`,
        reasons: [
          "missing_explicit_cwe",
          "missing_or_unanchored_code_evidence",
          "missing_or_weak_validation",
          "missing_or_weak_attack_path",
        ],
      });
      continue;
    }

    const taxonomy = finding["taxonomy"];
    if (
      !isRecord(taxonomy) ||
      !Array.isArray(taxonomy["cwe"]) ||
      !taxonomy["cwe"].some(
        (cwe) => typeof cwe === "string" && /^CWE-[1-9]\d*$/iu.test(cwe),
      )
    ) {
      reasons.push("missing_explicit_cwe");
    }
    const locations = parseFindingLocations(finding["locations"]);
    if (!isSubstantiveCodeEvidence(finding["codeEvidence"], locations)) {
      reasons.push("missing_or_unanchored_code_evidence");
    }
    if (!isSubstantiveValidation(finding["validation"])) {
      reasons.push("missing_or_weak_validation");
    }
    reasons.push(...validationClosureGaps(finding["validation"]));
    if (!isSubstantiveAttackPath(finding["attackPath"])) {
      reasons.push("missing_or_weak_attack_path");
    }
    reasons.push(...attackPathClosureGaps(finding["attackPath"]));
    if (hasNonreportableValidationDisposition(finding["validation"])) {
      reasons.push("non_reportable_validation_disposition");
    }
    if (hasNonreportableAttackPathDecision(finding["attackPath"])) {
      reasons.push("non_reportable_attack_path_decision");
    }
    if (reasons.length > 0) {
      gaps.push({
        findingIndex: index,
        findingId: findingIdentifier(finding, index),
        reasons,
      });
    }
  }
  if (gaps.length === 0) return "";

  const selected = gaps.slice(0, MAX_FINDING_QUALITY_GAPS);
  return [
    JSON.stringify({
      type: "finding-quality-gap-summary",
      findingsReadable: true,
      findingCount: findings.length,
      gapCount: gaps.length,
      emittedGapCount: selected.length,
      omittedGapCount: gaps.length - selected.length,
    }),
    ...selected.map((gap) => JSON.stringify(gap)),
  ].join("\n");
}

function validationClosureGaps(value: unknown): FindingQualityGapReason[] {
  if (!isRecord(value)) {
    return [
      "missing_validation_method",
      "missing_exploit_witness",
      "missing_negative_control",
      "missing_validation_evidence",
      "missing_counterevidence",
      "missing_remaining_uncertainty",
    ];
  }
  const gaps: FindingQualityGapReason[] = [];
  if (!hasNamedSubstantiveValue(value, ["method"], 3)) {
    gaps.push("missing_validation_method");
  }
  if (!hasNamedSubstantiveValue(value, ["exploitWitness", "exploit_witness"])) {
    gaps.push("missing_exploit_witness");
  }
  if (
    !hasNamedSubstantiveValue(value, ["negativeControl", "negative_control"])
  ) {
    gaps.push("missing_negative_control");
  }
  if (!hasNamedSubstantiveValue(value, ["evidence"])) {
    gaps.push("missing_validation_evidence");
  }
  if (
    !hasNamedSubstantiveValue(value, [
      "counterEvidence",
      "counterevidence",
      "counter_evidence",
    ])
  ) {
    gaps.push("missing_counterevidence");
  }
  if (
    !hasNamedSubstantiveValue(value, [
      "remainingUncertainty",
      "remaining_uncertainty",
    ])
  ) {
    gaps.push("missing_remaining_uncertainty");
  }
  return gaps;
}

function attackPathClosureGaps(value: unknown): FindingQualityGapReason[] {
  if (!isRecord(value)) {
    return [
      "incomplete_attack_path_dataflow",
      "incomplete_attack_path_reachability",
      "missing_broken_controls",
      "missing_attack_path_evidence_refs",
    ];
  }
  const gaps: FindingQualityGapReason[] = [];
  const dataflow = value["dataflow"];
  if (
    !isRecord(dataflow) ||
    !["source", "sink", "outcome"].every((field) =>
      hasNamedSubstantiveValue(dataflow, [field], 3),
    )
  ) {
    gaps.push("incomplete_attack_path_dataflow");
  }
  const reachability = value["reachability"];
  if (
    !isRecord(reachability) ||
    !["attacker", "entrypoint", "outcome"].every((field) =>
      hasNamedSubstantiveValue(reachability, [field], 3),
    )
  ) {
    gaps.push("incomplete_attack_path_reachability");
  }
  if (!hasNamedSubstantiveValue(value, ["controlsBroken", "controls_broken"])) {
    gaps.push("missing_broken_controls");
  }
  if (!hasNamedSubstantiveValue(value, ["evidenceRefs", "evidence_refs"], 3)) {
    gaps.push("missing_attack_path_evidence_refs");
  }
  return gaps;
}

function hasNamedSubstantiveValue(
  value: Record<string, unknown>,
  names: readonly string[],
  minimumLength = 20,
): boolean {
  return names.some((name) => hasSubstantiveValue(value[name], minimumLength));
}

function hasSubstantiveValue(value: unknown, minimumLength: number): boolean {
  if (typeof value === "string") {
    const text = value.trim();
    return (
      text.length >= minimumLength &&
      !/^(?:n\/?a|none|not tested|placeholder|tbd|todo|unknown)$/iu.test(text)
    );
  }
  if (Array.isArray(value)) {
    return value.some((entry) => hasSubstantiveValue(entry, minimumLength));
  }
  if (isRecord(value)) {
    return Object.values(value).some((entry) =>
      hasSubstantiveValue(entry, minimumLength),
    );
  }
  return false;
}

function findingQualityInventoryFailure(reason: string): string {
  return [
    JSON.stringify({
      type: "finding-quality-gap-summary",
      findingsReadable: false,
      findingCount: 0,
      gapCount: 1,
      emittedGapCount: 1,
      omittedGapCount: 0,
    }),
    JSON.stringify({
      findingIndex: 0,
      findingId: "findings-document",
      reasons: [reason],
    }),
  ].join("\n");
}

function parseFindingLocations(value: unknown): EvidenceLocation[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((location) => {
    if (!isRecord(location)) return [];
    const path = location["path"];
    const startLine = location["startLine"];
    const endLine = location["endLine"];
    if (
      typeof path !== "string" ||
      path.trim() === "" ||
      !Number.isSafeInteger(startLine) ||
      Number(startLine) < 1 ||
      (endLine !== undefined &&
        (!Number.isSafeInteger(endLine) || Number(endLine) < Number(startLine)))
    ) {
      return [];
    }
    return [
      {
        path,
        startLine: Number(startLine),
        ...(endLine === undefined ? {} : { endLine: Number(endLine) }),
      },
    ];
  });
}

function findingIdentifier(
  finding: Record<string, unknown>,
  index: number,
): string {
  for (const key of ["occurrenceId", "findingId", "ruleId"]) {
    const value = finding[key];
    if (typeof value === "string" && value.trim() !== "") {
      return value.slice(0, 256);
    }
  }
  return `finding-${index + 1}`;
}

function hasNonreportableValidationDisposition(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (value["exploitable"] === false || value["vulnerable"] === false) {
    return true;
  }
  const nonreportable = new Set([
    "false positive",
    "mitigated",
    "no issue",
    "no issue found",
    "not applicable",
    "rejected",
    "safe",
    "suppressed",
  ]);
  return ["status", "verdict", "disposition", "result"].some((field) => {
    const candidate = value[field];
    return (
      typeof candidate === "string" &&
      nonreportable.has(candidate.trim().toLowerCase().replaceAll("_", " "))
    );
  });
}

function hasNonreportableAttackPathDecision(value: unknown): boolean {
  if (!isRecord(value)) return false;
  const decision = value["decision"];
  return (
    typeof decision === "string" &&
    ["deferred", "ignore", "not reportable", "suppressed"].includes(
      decision.trim().toLowerCase().replaceAll("_", " "),
    )
  );
}

function mergeResidualRiskRecord(
  records: ResidualRiskRecord[],
  lines: readonly string[],
  next: ResidualRiskRecord,
): void {
  const previous = records.at(-1);
  if (
    previous !== undefined &&
    next.startLine <= previous.endLine + 1 &&
    Math.max(previous.endLine, next.endLine) -
      Math.min(previous.startLine, next.startLine) +
      1 <=
      MAX_EXCERPT_LINES
  ) {
    previous.categories = [
      ...new Set([...previous.categories, ...next.categories]),
    ];
    if (next.priority > previous.priority) {
      previous.line = next.line;
    }
    previous.priority = Math.max(previous.priority, next.priority);
    previous.startLine = Math.min(previous.startLine, next.startLine);
    previous.endLine = Math.max(previous.endLine, next.endLine);
    previous.excerpt = sourceExcerpt(
      lines,
      previous.startLine,
      previous.endLine,
    );
    return;
  }
  next.excerpt = sourceExcerpt(lines, next.startLine, next.endLine);
  records.push(next);
}

function sourceExcerpt(
  lines: readonly string[],
  startLine: number,
  endLine: number,
): string {
  return lines
    .slice(startLine - 1, endLine)
    .map((line, offset) => `${startLine + offset}: ${line}`)
    .join("\n");
}

function selectResidualRiskRecords(
  records: readonly ResidualRiskRecord[],
  limit: number,
): ResidualRiskRecord[] {
  const ranked = [...records].sort(compareResidualRiskRecords);
  const selected: ResidualRiskRecord[] = [];
  const selectedRecords = new Set<ResidualRiskRecord>();
  const add = (record: ResidualRiskRecord): void => {
    if (selected.length >= limit || selectedRecords.has(record)) {
      return;
    }
    selected.push(record);
    selectedRecords.add(record);
  };

  const representedCategories = new Set<string>();
  for (const record of ranked) {
    if (
      record.categories.some((category) => !representedCategories.has(category))
    ) {
      add(record);
      record.categories.forEach((category) =>
        representedCategories.add(category),
      );
    }
  }

  const representedPaths = new Set(selected.map((record) => record.path));
  const pathSeedLimit = Math.floor(limit / 2);
  for (const record of ranked) {
    if (selected.length >= pathSeedLimit || representedPaths.has(record.path)) {
      continue;
    }
    add(record);
    representedPaths.add(record.path);
  }

  const selectedPerPath = new Map<string, number>();
  for (const record of selected) {
    selectedPerPath.set(
      record.path,
      (selectedPerPath.get(record.path) ?? 0) + 1,
    );
  }
  for (const record of ranked) {
    if ((selectedPerPath.get(record.path) ?? 0) >= SOFT_SIGNALS_PER_FILE) {
      continue;
    }
    const before = selected.length;
    add(record);
    if (selected.length > before) {
      selectedPerPath.set(
        record.path,
        (selectedPerPath.get(record.path) ?? 0) + 1,
      );
    }
  }

  for (const record of ranked) add(record);
  return selected.sort(compareResidualRiskRecords);
}

function compareResidualRiskRecords(
  left: ResidualRiskRecord,
  right: ResidualRiskRecord,
): number {
  return (
    right.priority - left.priority ||
    left.path.localeCompare(right.path) ||
    left.line - right.line
  );
}

async function readModelInventoryPaths(
  scanDirectory: string,
  repository: string,
): Promise<string[]> {
  const canonicalScanDirectory = await realpath(scanDirectory).catch(
    () => null,
  );
  if (canonicalScanDirectory === null) return [];
  const inventoryBytes = await readBoundedScanFile(
    canonicalScanDirectory,
    join("artifacts", "02_discovery", "in_scope_files.txt"),
    MAX_INVENTORY_BYTES,
  );
  const inventory = inventoryBytes?.toString("utf8") ?? "";
  const seen = new Set<string>();
  for (const candidate of parseInventoryPaths(inventory)) {
    if (!isSourcePath(candidate)) {
      continue;
    }
    const relativePath = relative(repository, resolve(repository, candidate));
    if (!isContainedRelativePath(relativePath)) continue;
    seen.add(relativePath);
  }
  return [...seen].sort((left, right) => left.localeCompare(right));
}

function parseInventoryPaths(inventory: string): string[] {
  const seen = new Set<string>();
  for (const line of inventory.split(/\r?\n/u)) {
    const candidate = line.trim();
    if (!isSafeInventoryPath(candidate)) continue;
    seen.add(candidate);
  }
  return [...seen].sort((left, right) => left.localeCompare(right));
}

function isSafeInventoryPath(path: string): boolean {
  if (
    path === "" ||
    path.includes("\\") ||
    path.includes("\0") ||
    isAbsolute(path)
  ) {
    return false;
  }
  const parts = path.split("/");
  return parts.every((part) => part !== "" && part !== "." && part !== "..");
}

function parseCoverageSurfaces(coverageBytes: Buffer | null): {
  readable: boolean;
  surfaces: CoverageSurfaceDraft[];
} {
  if (coverageBytes === null) return { readable: false, surfaces: [] };
  try {
    const coverage = JSON.parse(coverageBytes.toString("utf8")) as unknown;
    if (
      typeof coverage !== "object" ||
      coverage === null ||
      !Array.isArray((coverage as { surfaces?: unknown }).surfaces)
    ) {
      return { readable: false, surfaces: [] };
    }
    return {
      readable: true,
      surfaces: (coverage as { surfaces: unknown[] }).surfaces.filter(
        (surface): surface is CoverageSurfaceDraft =>
          typeof surface === "object" && surface !== null,
      ),
    };
  } catch {
    return { readable: false, surfaces: [] };
  }
}

function compareCoverageGaps(
  left: CoverageGapRecord,
  right: CoverageGapRecord,
): number {
  const priority = {
    missing_coverage_surface: 0,
    needs_follow_up: 1,
    invalid_coverage_disposition: 2,
    conflicting_coverage_surfaces: 3,
  } as const;
  return (
    priority[left.reason] - priority[right.reason] ||
    left.path.localeCompare(right.path)
  );
}

async function discoverSourcePaths(repository: string): Promise<string[]> {
  const paths: string[] = [];
  const pending = [repository];
  while (pending.length > 0 && paths.length < MAX_FILES) {
    const directory = pending.pop();
    if (directory === undefined) break;
    const entries = await readdir(directory, { withFileTypes: true }).catch(
      () => [],
    );
    entries.sort((left, right) => right.name.localeCompare(left.name));
    for (const entry of entries) {
      if (paths.length >= MAX_FILES) break;
      const absolutePath = join(directory, entry.name);
      if (
        entry.isDirectory() &&
        !entry.isSymbolicLink() &&
        !IGNORED_DIRECTORIES.has(entry.name)
      ) {
        pending.push(absolutePath);
      } else if (
        entry.isFile() &&
        !entry.isSymbolicLink() &&
        isSourcePath(entry.name)
      ) {
        paths.push(relative(repository, absolutePath));
      }
    }
  }
  return paths.sort((left, right) => left.localeCompare(right));
}

function isSourcePath(path: string): boolean {
  const baseName = path.replaceAll("\\", "/").split("/").at(-1) ?? "";
  return (
    SOURCE_EXTENSIONS.has(extname(baseName).toLowerCase()) ||
    /^(?:Dockerfile|Gemfile|Jenkinsfile|Makefile|Rakefile)$/u.test(baseName)
  );
}

async function readBoundedRepositoryFile(
  repository: string,
  relativePath: string,
): Promise<Buffer | null> {
  const candidate = resolve(repository, relativePath);
  if (!isContainedRelativePath(relative(repository, candidate))) return null;
  const metadata = await lstat(candidate).catch(() => null);
  if (
    metadata === null ||
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size > MAX_FILE_BYTES
  ) {
    return null;
  }
  const canonicalCandidate = await realpath(candidate).catch(() => null);
  if (
    canonicalCandidate === null ||
    !isContainedRelativePath(relative(repository, canonicalCandidate))
  ) {
    return null;
  }
  return await readFile(canonicalCandidate);
}

async function readBoundedScanFile(
  scanDirectory: string,
  relativePath: string,
  maximumBytes: number,
): Promise<Buffer | null> {
  const candidate = resolve(scanDirectory, relativePath);
  if (!isContainedRelativePath(relative(scanDirectory, candidate))) return null;
  const metadata = await lstat(candidate).catch(() => null);
  if (
    metadata === null ||
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size > maximumBytes
  ) {
    return null;
  }
  const canonicalCandidate = await realpath(candidate).catch(() => null);
  if (
    canonicalCandidate === null ||
    !isContainedRelativePath(relative(scanDirectory, canonicalCandidate))
  ) {
    return null;
  }
  return await readFile(canonicalCandidate);
}

function isContainedRelativePath(path: string): boolean {
  return (
    path !== "" &&
    path !== ".." &&
    !path.startsWith("..\\") &&
    !path.startsWith("../") &&
    !isAbsolute(path)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
