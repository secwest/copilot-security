import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { extname, isAbsolute, join, posix, relative, resolve } from "node:path";
import {
  isSubstantiveAttackPath,
  isSubstantiveCodeEvidence,
  isSubstantiveValidation,
  type EvidenceLocation,
} from "./evidence-quality.js";
import {
  githubActionsArtifactPoisoningRecords,
  githubActionsCompositeActionInjectionRecords,
  githubActionsPrivilegeRecords,
  githubActionsReusableWorkflowInjectionRecords,
  githubActionsSelfHostedPrRecords,
  githubActionsWorkflowInjectionRecords,
} from "./github-actions-risk.js";
import { goExecInjectionRecords } from "./go-exec-risk.js";
import { goHttpSsrfRecords } from "./go-http-risk.js";
import { goObjectAuthorizationRecords } from "./go-object-authorization-risk.js";
import { goPathTraversalRecords } from "./go-path-risk.js";
import { goTemplateInjectionRecords } from "./go-template-risk.js";
import { goGormSqlInjectionRecords } from "./go-gorm-risk.js";
import { goPgconnSqlInjectionRecords } from "./go-pgconn-risk.js";
import { goPgxSqlInjectionRecords } from "./go-pgx-risk.js";
import { goSqlInjectionRecords } from "./go-sql-risk.js";
import { goSqlxSqlInjectionRecords } from "./go-sqlx-risk.js";
import { goSquirrelSqlInjectionRecords } from "./go-squirrel-risk.js";

const MAX_FILES = 2_000;
const MAX_FILE_BYTES = 256 * 1024;
const MAX_TOTAL_BYTES = 8 * 1024 * 1024;
const MAX_CANDIDATES = 4_096;
const MAX_SIGNALS = 96;
const MAX_SIGNALS_PER_FILE = MAX_SIGNALS;
const MAX_FRAMEWORK_CROSS_FILE_RECORDS = 64;
const MAX_FRAMEWORK_MULTI_HOP_RECORDS = 64;
const MAX_RELATIVE_IMPORT_RELAY_LAYERS = 2;
const MAX_TYPED_SERVICE_RELAY_LAYERS = 2;
const MAX_WRAPPER_FUNCTION_LINES = 160;
const MAX_WRAPPER_CALL_DISTANCE = 12;
const MAX_COVERAGE_GAPS = 256;
const MAX_FINDING_QUALITY_GAPS = 256;
const MAX_INVENTORY_BYTES = 8 * 1024 * 1024;
const MAX_COVERAGE_BYTES = 32 * 1024 * 1024;
const MAX_FINDINGS_BYTES = 128 * 1024 * 1024;
const MAX_JAVA_MAVEN_MODEL_DEPTH = 128;
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
  ".csproj",
  ".dart",
  ".ex",
  ".exs",
  ".erl",
  ".fs",
  ".fsx",
  ".go",
  ".gradle",
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
  ".props",
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
const JAVA_PROJECT_BOUNDARY_FILES = new Set([
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "settings.gradle",
  "settings.gradle.kts",
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
    "archive-link-target-or-no-follow-boundary",
    106,
    /\b(?:hardlink|issym|islnk|linkName|linkname|readlink|symlink|S_IFLNK)\b|\b(?:mkdir|open|writeFile)(?:NoFollow)\b/iu,
  ],
  [
    "decompression-output-or-expansion-budget",
    107,
    /\b(?:brotliDecompress|decompress|gunzip|inflate|uncompress)(?:Raw)?(?:Sync)?\s*\(|\b(?:compressedSize|expandedSize|expansionRatio|maxOutputLength|uncompressedSize|MAX_(?:BUNDLE_ENTRIES|COMPRESSED(?:_[A-Z0-9]+)*|ENTRIES|ENTRY_COUNT|EXPANDED(?:_[A-Z0-9]+)*|UNCOMPRESSED(?:_[A-Z0-9]+)*))\b/iu,
  ],
  [
    "aead-key-nonce-or-authentication-binding",
    108,
    /\b(?:AESGCM|ChaCha20Poly1305|createCipheriv|createDecipheriv|hkdfSync|HKDF|EVP_(?:Decrypt|Encrypt)Init(?:_ex)?)\b|\b(?:AEAD|GCM|POLY1305)[_-]?(?:IV|NONCE)\b|\b(?:getAuthTag|setAAD|setAuthTag)\s*\(/iu,
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
    "privileged-role-or-operation",
    93,
    /\b(?:admin|administrator|privileged|role)\b|\b(?:exportAudit|exportSigningAudit|exportSigningKeys|requireAdministrator)\b/iu,
  ],
  [
    "external-authorization-policy-decision",
    102,
    /\b(?:authorizer|authorizationClient|policyClient|policyEngine)\b|\b(?:authorize|checkAccess|isAllowed)\s*\(|\bauthorization_unavailable\b|\b(?:allowed|authorized|decision)\s*!==\s*true\b/iu,
  ],
  [
    "fail-open-security-decision",
    103,
    /\b(?:allowed|authorized|permitted|decision)\s*=\s*true\b|\b(?:defaultAllow|failOpen|permitOnError)\b/iu,
  ],
  [
    "browser-ambient-credential-or-csrf",
    96,
    /\b(?:anti[_-]?forgery|antiforgery|csrf|xsrf)\b|\b(?:SameSite|Sec-Fetch-Site)\b|\bsame_?site\s*[:=]\s*["']?none\b|\bValidateAntiForgeryToken\b/iu,
  ],
  [
    "credentialed-cors-response-exposure",
    102,
    /\bAccess-Control-Allow-(?:Credentials|Origin)\b|\b(?:allowCredentials|credentialedCors|TRUSTED_ORIGINS)\b|\bcredentials\s*[:=]\s*(?:["']include["']|true)\b|\bcors\s*\(/iu,
  ],
  [
    "cookie-authenticated-websocket-origin",
    103,
    /\b(?:WebSocket|WebSocketServer|Sec-WebSocket-(?:Protocol|Key|Version)|handleUpgrade|upgradeToWebSocket|socket\.io|SockJS|graphql-ws|subscriptions-transport-ws)\b|\b(?:ws|socket)\.on\s*\(\s*["'](?:connection|message|upgrade)["']|\b(?:ws|wss):\/\//iu,
  ],
  [
    "shared-cache-sensitive-response-or-route-disagreement",
    104,
    /\b(?:Cache-Control|Surrogate-Control|s-maxage|X-Cache|CDN-Cache-Control|cacheableExtensions?|sharedCache|publicCache|edgeCache|cacheKey)\b|\b(?:private|no-store|public)\s*,?\s*(?:max-age|s-maxage)\b/iu,
  ],
  [
    "principal-or-tenant-scoped-application-cache",
    104,
    /\b(?:applicationCache|authorizationCache|invoiceCache|permissionCache|responseCache|tenantCache)\b|\b(?:cacheKey|cache_key)\b|\b(?:cache|cached)\.(?:get|set)\s*\(/iu,
  ],
  [
    "http-response-header-value-boundary",
    105,
    /\b(?:Content-Disposition|Location|Set-Cookie|X-Accel-Redirect|X-Sendfile)\b|\b(?:appendHeader|setHeader|writeHead|rawResponse|serializeResponse)\b|\.join\s*\(\s*["']\\r\\n["']\s*\)/iu,
  ],
  [
    "graphql-operation-amplification-or-resolver-budget",
    105,
    /\b(?:GraphQL|gql|document\.selections|selectionSet|resolverCost|chargedCost|verifyRecoveryCode|recoveryOperations|failedAttempts|MAX_(?:FAILED_ATTEMPTS|SELECTIONS))\b/iu,
  ],
  [
    "forwarded-client-identity-or-proxy-trust-budget",
    106,
    /\b(?:Forwarded|X-Forwarded-For|X-Real-IP|CF-Connecting-IP|True-Client-IP)\b|\b(?:clientAddress|clientIp|peerAddress|remoteAddress|trustedProx(?:y|ies)|trust proxy|forwardedHops|attemptsByClient|attemptsByAccount|maxAttemptsPerClient|maxAttemptsPerAccount)\b|\.split\s*\(\s*["'],["']\s*\)\s*\[\s*0\s*\]/iu,
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
    "account-recovery-link-origin-binding",
    102,
    /\b(?:Forwarded|Host|X-Forwarded-Host|X-Forwarded-Proto)\b|\b(?:magicLink|passwordReset|public[_-]?origin|resetUrl|sendPasswordReset|verificationLink)\b|\b(?:req|request)\.(?:get\s*\(\s*["']host["']|headers\s*(?:\.|\[\s*["'])(?:forwarded|host|x-forwarded-host|x-forwarded-proto))\b/iu,
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
    "filesystem-path-construction-or-access",
    94,
    /\bPath\.(?:Combine|GetFullPath|GetRelativePath|IsPathRooted|Join|TryJoin)\s*\(|\bFile\.(?:AppendAllLines|AppendAllText|AppendAllTextAsync|Copy|Create|CreateText|Delete|Move|Open|OpenHandle|OpenRead|OpenText|OpenWrite|ReadAllBytes|ReadAllBytesAsync|ReadAllLines|ReadAllLinesAsync|ReadAllText|ReadAllTextAsync|ReadLines|WriteAllBytes|WriteAllBytesAsync|WriteAllLines|WriteAllLinesAsync|WriteAllText|WriteAllTextAsync)\s*\(|\bFiles\.(?:copy|delete|deleteIfExists|lines|move|newBufferedReader|newBufferedWriter|newByteChannel|newInputStream|newOutputStream|readAllBytes|readAllLines|readString|write|writeString)\s*\(|\bnew\s+(?:(?:System\.IO\.)?FileStream|(?:java\.io\.)?(?:FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile))\s*\(/iu,
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
    "llm-trusted-prompt-or-tool-description",
    105,
    /\b(?:customAgents|systemMessage|systemPrompt)\b|\brole\s*:\s*["']system["']|\b(?:commands|tools)\s*:\s*\[/iu,
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
    "regular-expression-complexity",
    101,
    /\b(?:RegExp|Regex|Pattern\.compile|re\.compile|regexp\.Compile)\s*\(|\b[A-Z][A-Z0-9_]*(?:PATTERN|REGEX)[A-Z0-9_]*\b|\b(?:pattern|regex|regexp)\s*\.(?:match|matches|replace|search|split|test)\s*\(/iu,
  ],
  [
    "input-size-or-complexity-bound",
    97,
    /\bMAX_[A-Z0-9_]*(?:BYTES|DEPTH|LENGTH|SIZE)\b|\b[\w$.]+\.(?:byteLength|length)\s*(?:[<>]=?)|\bcharCodeAt\s*\(/u,
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
    "dns-resolution-or-rebinding-boundary",
    101,
    /\b(?:dns\.(?:lookup|resolve|resolve4|resolve6)|getaddrinfo|resolveAll)\s*\(|\bresolver\.resolveAll\b/iu,
  ],
  [
    "network-destination-pinning",
    102,
    /\b(?:connectAddress|getPinned|hostHeader|tlsServerName)\b|\bredirect\s*:\s*["']error["']/iu,
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
    "duplicate-parameter-parser-or-authorization-boundary",
    106,
    /\b(?:URLSearchParams|Object\.(?:freeze|fromEntries)|parseQuery|parse_qs|querystring\.parse)\b|\b(?:duplicate|repeated)\s+(?:decoded\s+)?(?:parameter|query)\b|\b(?:authorizedAction|executedAction|parseCanonicalQuery)\b|\b(?:req|request)\.query\b/iu,
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
    "jwt-jws-algorithm-key-confusion",
    101,
    /\b(?:HS256|RS256|ES256|EdDSA|EXPECTED_ALGORITHM|allowedAlgorithms|asymmetricKeyType|createHmac)\b|\b(?:header|protectedHeader)\s*(?:\.|\[\s*["'])\s*alg\b|\b(?:publicKey|verificationKey|keyMaterial)\b/iu,
  ],
  [
    "jwt-oidc-remote-key-origin",
    100,
    /\b(?:createRemoteJWKSet|fetchJwks|jwksUri|jku|x5u)\b|\b(?:header|protectedHeader)\s*(?:\.|\[\s*["'])\s*(?:jku|kid|x5u)\b/iu,
  ],
  [
    "oidc-id-token-client-transaction-binding",
    102,
    /\b(?:beginLogin|finishLogin|verifySignedIdToken|pendingOidc|OIDC_CLIENT_ID|intendedForClient|idToken)\b|\bclaims\s*\.\s*(?:aud|azp|nonce)\b/iu,
  ],
  [
    "webauthn-credential-account-binding-boundary",
    107,
    /\b(?:navigator\.credentials|PublicKeyCredential|verifyAuthenticationResponse|beginLogin|finishLogin|allowedCredentialIds|credentialId|ownerId|rpId|relyingPartyId|userHandle|signCount|authenticatorData|clientDataJSON)\b/iu,
  ],
  [
    "signed-webhook-freshness-and-idempotency",
    103,
    /\b(?:handlePaymentWebhook|signatureHeader|webhookSecret|applyCreditOnce|processedEventIds|processedEvents)\b|\b(?:event|webhook)\s*(?:\.|\[\s*["'])\s*(?:id|timestamp)\b|\bcreateHmac\s*\(/iu,
  ],
  [
    "signature-representation-and-replay-identity",
    104,
    /\b(?:ECDSA|ES256|P256_ORDER|prime256v1|secp256r1|malleat(?:e|ed|ion)|applySignatureOnce|applyEventOnce|consumedSignatureDigests|consumedEventIds|signatureBase64)\b|\bcreateHash\s*\([^)]*\)\s*\.\s*update\s*\(\s*signature\b/iu,
  ],
  [
    "jwt-oidc-claim-binding",
    98,
    /\b(?:expectedAudience|expectedIssuer|maxTokenAgeSeconds|pendingNonces|pendingOidc|OIDC_CLIENT_ID)\b|\bclaims\s*\.\s*(?:aud|azp|exp|iat|iss|nonce|sub)\b/iu,
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
    "format-string-or-variadic-argument-binding",
    106,
    /\b(?:dprintf|fprintf|printf|snprintf|sprintf|syslog|vfprintf|vprintf|vsnprintf|vsprintf)\s*\(|\b(?:format|format_string|fmt)\b/iu,
  ],
  [
    "native-object-lifetime-or-deferred-pointer",
    107,
    /\b(?:free|g_free|kfree|HeapFree|LocalFree|CoTaskMemFree|arena_free|pool_free|pool_release|release_session|slab_free)\s*\(|\bdelete\s*(?:\[\s*\])?\s+[A-Za-z_$]|\b(?:pending|deferred)[A-Za-z0-9_]*(?:callback|completion|operation|pointer|session|task|work)?\b|\b(?:callback|completion|timer|work)_?(?:context|data|owner|pointer|session|state)\b/iu,
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

interface FrameworkModelPattern {
  kind: string;
  expression: RegExp;
}

interface FrameworkDataflowModel {
  id: string;
  language: string;
  extensions: ReadonlySet<string>;
  activation: readonly RegExp[];
  sources: readonly FrameworkModelPattern[];
  sinks: readonly (FrameworkModelPattern & { cweIds: readonly string[] })[];
  controls: readonly FrameworkModelPattern[];
}

const JAVASCRIPT_EXTENSIONS = new Set([
  ".cjs",
  ".js",
  ".jsx",
  ".mjs",
  ".ts",
  ".tsx",
]);
const PYTHON_EXTENSIONS = new Set([".py"]);
const JAVA_EXTENSIONS = new Set([".java", ".kt", ".kts"]);
const DOTNET_EXTENSIONS = new Set([".cs", ".fs", ".vb"]);

const FRAMEWORK_DATAFLOW_MODELS: readonly FrameworkDataflowModel[] = [
  {
    id: "node-http-command",
    language: "javascript-typescript",
    extensions: JAVASCRIPT_EXTENSIONS,
    activation: [
      /\b(?:node:)?child_process\b|\brequire\s*\(\s*["'](?:node:)?child_process["']/iu,
    ],
    sources: [
      {
        kind: "http-request-field",
        expression:
          /\b(?:req|request)\.(?:body|cookies|files|headers|params|query)\b|\bctx\.(?:headers|params|query|request\.body)\b/iu,
      },
      {
        kind: "next-url-search-parameter",
        expression:
          /\b(?:searchParams|nextUrl\.searchParams)\.(?:get|getAll)\s*\(/iu,
      },
    ],
    sinks: [
      {
        kind: "child-process-shell",
        expression: /\b(?:exec|execSync)\s*\(/iu,
        cweIds: ["CWE-78"],
      },
      {
        kind: "child-process-explicit-shell",
        expression: /\b(?:spawn|spawnSync)\s*\([^\r\n]*\bshell\s*:\s*true\b/iu,
        cweIds: ["CWE-78"],
      },
    ],
    controls: [
      {
        kind: "fixed-executable-argument-vector",
        expression: /\b(?:execFile|execFileSync)\s*\(|\bshell\s*:\s*false\b/iu,
      },
      {
        kind: "bounded-allowlist-or-validation",
        expression:
          /\b(?:allowlist|allowedCommands?|isValid|safeCommands?|validate)\b|\.test\s*\(/iu,
      },
    ],
  },
  {
    id: "node-http-sql",
    language: "javascript-typescript",
    extensions: JAVASCRIPT_EXTENSIONS,
    activation: [
      /\b(?:knex|mysql2?|pg|postgres|prisma|sequelize|typeorm)\b/iu,
      /\b(?:createConnection|createPool|DataSource|PrismaClient|Sequelize)\b/iu,
      /\bdatabase\.(?:execute|query)\s*\(/iu,
    ],
    sources: [
      {
        kind: "http-request-field",
        expression:
          /\b(?:req|request)\.(?:body|cookies|headers|params|query)\b|\bctx\.(?:headers|params|query|request\.body)\b/iu,
      },
      {
        kind: "next-url-search-parameter",
        expression:
          /\b(?:searchParams|nextUrl\.searchParams)\.(?:get|getAll)\s*\(/iu,
      },
    ],
    sinks: [
      {
        kind: "raw-sql-query",
        expression:
          /\b(?:client|connection|database|db|knex|pool|sequelize)\.(?:execute|query|raw)\s*\(|\.\$(?:executeRawUnsafe|queryRawUnsafe)\s*\(/iu,
        cweIds: ["CWE-89"],
      },
    ],
    controls: [
      {
        kind: "bound-query-parameters",
        expression:
          /\b(?:bind|bindValue|parameterized|parameters|prepared|replacements)\b|\$\{?\d+\}?/iu,
      },
      {
        kind: "typed-query-builder",
        expression:
          /\b(?:where|whereIn)\s*\(|\.\$(?:executeRaw|queryRaw)\s*`/iu,
      },
      {
        kind: "bounded-allowlist-or-validation",
        expression: /\b(?:allowlist|isValid|validate)\b|\.test\s*\(/iu,
      },
    ],
  },
  {
    id: "node-http-mongoose-nosql",
    language: "javascript-typescript",
    extensions: JAVASCRIPT_EXTENSIONS,
    activation: [/['"]mongoose['"]/u],
    sources: [
      {
        kind: "http-request-field",
        expression:
          /\b(?:req|request)\.(?:body|cookies|headers|params|query)\b|\bctx\.(?:headers|params|query|request\.body)\b/iu,
      },
      {
        kind: "next-url-search-parameter",
        expression:
          /\b(?:searchParams|nextUrl\.searchParams)\.(?:get|getAll)\s*\(/iu,
      },
    ],
    sinks: [
      {
        kind: "mongoose-query-filter",
        expression:
          /\.\s*(?:countDocuments|deleteMany|deleteOne|exists|find|findOne|findOneAndDelete|findOneAndReplace|findOneAndUpdate|replaceOne|updateMany|updateOne)\s*\(/u,
        cweIds: ["CWE-943"],
      },
    ],
    controls: [
      {
        kind: "literal-query-value-equality",
        expression: /\$eq\s*:/u,
      },
      {
        kind: "mongoose-filter-sanitization",
        expression: /\.\s*sanitizeFilter\s*\(/u,
      },
    ],
  },
  {
    id: "node-http-mongoose-update",
    language: "javascript-typescript",
    extensions: JAVASCRIPT_EXTENSIONS,
    activation: [/["']mongoose["']/u],
    sources: [
      {
        kind: "http-request-field",
        expression:
          /\b(?:req|request)\.(?:body|cookies|headers|params|query)\b|\bctx\.(?:headers|params|query|request\.body)\b/iu,
      },
      {
        kind: "next-url-search-parameter",
        expression:
          /\b(?:searchParams|nextUrl\.searchParams)\.(?:get|getAll)\s*\(/iu,
      },
    ],
    sinks: [
      {
        kind: "mongoose-update-document",
        expression:
          /\.\s*(?:findByIdAndUpdate|findOneAndUpdate|updateMany|updateOne)\s*\(/u,
        cweIds: ["CWE-943", "CWE-915"],
      },
    ],
    controls: [
      {
        kind: "fixed-update-field-value-boundary",
        expression: /\$set\s*:\s*\{/u,
      },
    ],
  },
  {
    id: "node-http-mongoose-bulk-write",
    language: "javascript-typescript",
    extensions: JAVASCRIPT_EXTENSIONS,
    activation: [/["']mongoose["']/u],
    sources: [
      {
        kind: "http-request-field",
        expression:
          /\b(?:req|request)\.(?:body|cookies|headers|params|query)\b|\bctx\.(?:headers|params|query|request\.body)\b/iu,
      },
      {
        kind: "next-url-search-parameter",
        expression:
          /\b(?:searchParams|nextUrl\.searchParams)\.(?:get|getAll)\s*\(/iu,
      },
    ],
    sinks: [
      {
        kind: "mongoose-bulk-write-operation-array",
        expression: /\.\s*bulkWrite\s*\(/u,
        cweIds: ["CWE-943", "CWE-915"],
      },
    ],
    controls: [
      {
        kind: "literal-query-value-equality",
        expression: /\$eq\s*:/u,
      },
      {
        kind: "mongoose-filter-sanitization",
        expression: /\.\s*sanitizeFilter\s*\(/u,
      },
      {
        kind: "fixed-update-field-value-boundary",
        expression: /\$set\s*:\s*\{/u,
      },
      {
        kind: "fixed-document-field-projection",
        expression: /\{[\s\S]*:[\s\S]*\}/u,
      },
    ],
  },
  {
    id: "node-http-object-authorization",
    language: "javascript-typescript",
    extensions: JAVASCRIPT_EXTENSIONS,
    activation: [
      /\b(?:findById|findByPk|findFirst|findOne|findUnique|getById|loadById|selectById)\s*\(/iu,
      /\b(?:database|db|prisma|repository|store)\b/iu,
    ],
    sources: [
      {
        kind: "http-object-reference",
        expression:
          /\b(?:req|request)\.(?:body|cookies|headers|params|query)\b|\bctx\.(?:headers|params|query|request\.body)\b/iu,
      },
      {
        kind: "next-url-object-reference",
        expression:
          /\b(?:searchParams|nextUrl\.searchParams)\.(?:get|getAll)\s*\(/iu,
      },
    ],
    sinks: [
      {
        kind: "object-record-lookup",
        expression:
          /\.\s*(?:findById|findByPk|findFirst|findOne|findUnique|getById|loadById|selectById)\s*(?:<[^;(){}]+>)?\s*\(/iu,
        cweIds: ["CWE-639", "CWE-862"],
      },
    ],
    controls: [
      {
        kind: "principal-bound-object-filter",
        expression:
          /\b(?:account|customer|organization|owner|principal|tenant|user|workspace)Id\b/iu,
      },
      {
        kind: "post-lookup-object-authorization",
        expression:
          /\b(?:assertCanAccess|authorize|authorizeObject|canAccess|canRead|canWrite|checkAccess|enforceOwnership|owns)\s*\(/iu,
      },
    ],
  },
  {
    id: "node-http-ssrf",
    language: "javascript-typescript",
    extensions: JAVASCRIPT_EXTENSIONS,
    activation: [
      /\b(?:axios|fetch|got|undici)\b/iu,
      /\b(?:node:)?https?\b|\brequire\s*\(\s*["'](?:node:)?https?["']/iu,
    ],
    sources: [
      {
        kind: "http-request-field",
        expression:
          /\b(?:req|request)\.(?:body|cookies|headers|params|query)\b|\bctx\.(?:headers|params|query|request\.body)\b/iu,
      },
      {
        kind: "next-url-search-parameter",
        expression:
          /\b(?:searchParams|nextUrl\.searchParams)\.(?:get|getAll)\s*\(/iu,
      },
    ],
    sinks: [
      {
        kind: "outbound-http-url",
        expression:
          /\b(?:axios|fetch|got)\s*\(|\b[A-Za-z_$][\w$]*\s*\.\s*(?:delete|get|head|options|patch|post|put|request)\s*(?:<[^;(){}]+>)?\s*\(|\b(?:https?|undici)\.(?:get|request)\s*\(/iu,
        cweIds: ["CWE-918"],
      },
    ],
    controls: [
      {
        kind: "fixed-destination-allowlist",
        expression:
          /\b(?:allowedUrls?|assetUrls?|trustedUrls?)\b|\bObject\.hasOwn\s*\(/iu,
      },
      {
        kind: "parsed-host-exact-allowlist",
        expression:
          /\b(?:allowedHosts?|trustedHosts?)\.(?:has|includes)\s*\([^)]*\.(?:host|hostname)\b|\.(?:host|hostname)\b\s*(?:===|==)/iu,
      },
      {
        kind: "fixed-origin-url-construction",
        expression: /\bnew\s+URL\s*\(/iu,
      },
      {
        kind: "redirects-disabled",
        expression: /\bmaxRedirects\s*:\s*0\b|\bredirect\s*:\s*["']error["']/iu,
      },
      {
        kind: "axios-absolute-url-override-disabled",
        expression: /\ballowAbsoluteUrls\s*:\s*false\b/iu,
      },
      {
        kind: "relative-url-path-validation",
        expression:
          /\b(?:allowedPaths?|isSafeRelativePath|safeRelativePaths?|validateRelativePath)\b/iu,
      },
      {
        kind: "network-address-validation-or-pinning",
        expression:
          /\b(?:dns\.(?:lookup|resolve|resolve4|resolve6)|isPrivateAddress|isPublicAddress|lookupAndPin|pinnedAddress|connectAddress)\b/iu,
      },
    ],
  },
  {
    id: "node-copilot-system-prompt-injection",
    language: "javascript-typescript",
    extensions: JAVASCRIPT_EXTENSIONS,
    activation: [/["']@github\/copilot-sdk["']/u],
    sources: [
      {
        kind: "http-request-field",
        expression:
          /\b(?:req|request)\.(?:body|cookies|files|headers|params|query)\b|\bctx\.(?:headers|params|query|request\.body)\b/iu,
      },
      {
        kind: "next-url-search-parameter",
        expression:
          /\b(?:searchParams|nextUrl\.searchParams)\.(?:get|getAll)\s*\(/iu,
      },
    ],
    sinks: [
      {
        kind: "copilot-sdk-trusted-instruction",
        expression: /\.\s*(?:createSession|resumeSession)\s*\(/u,
        cweIds: ["CWE-1427"],
      },
    ],
    controls: [
      {
        kind: "fixed-trusted-prompt-allowlist",
        expression:
          /\b(?:allowedAgents?|allowedPersonas?|allowedPrompts?|trustedAgents?|trustedPrompts?)\b|\bObject\.hasOwn\s*\(/iu,
      },
    ],
  },
  {
    id: "node-http-template-injection",
    language: "javascript-typescript",
    extensions: JAVASCRIPT_EXTENSIONS,
    activation: [
      /\b(?:ejs|handlebars|nunjucks|pug)\b/iu,
      /\b(?:doT\.template|lodash\.template|mustache\.render)\b/iu,
    ],
    sources: [
      {
        kind: "http-request-field",
        expression:
          /\b(?:req|request)\.(?:body|cookies|headers|params|query)\b|\bctx\.(?:headers|params|query|request\.body)\b/iu,
      },
      {
        kind: "next-url-search-parameter",
        expression:
          /\b(?:searchParams|nextUrl\.searchParams)\.(?:get|getAll)\s*\(/iu,
      },
    ],
    sinks: [
      {
        kind: "dynamic-template-source",
        expression:
          /\b(?:ejs\.render|Handlebars\.compile|nunjucks\.renderString|pug\.compile|doT\.template|mustache\.render|_\.template)\s*\(/iu,
        cweIds: ["CWE-1336"],
      },
    ],
    controls: [
      {
        kind: "fixed-template-with-data-context",
        expression: /\b(?:compile|render|renderString|template)\s*\(\s*["']/iu,
      },
      {
        kind: "sandboxed-template-environment",
        expression:
          /\b(?:sandbox|SandboxedEnvironment|allowedGlobals?|safeRuntime)\b/iu,
      },
      {
        kind: "bounded-template-identifier-map",
        expression:
          /\b(?:allowedTemplates?|templateMap|templateNames?|trustedTemplates?)\b|\bObject\.hasOwn\s*\(/iu,
      },
    ],
  },
  {
    id: "node-http-path",
    language: "javascript-typescript",
    extensions: JAVASCRIPT_EXTENSIONS,
    activation: [/['"](?:node:)?fs(?:\/promises)?['"]/u],
    sources: [
      {
        kind: "http-request-field",
        expression:
          /\b(?:req|request)\.(?:body|cookies|files|headers|params|query)\b|\bctx\.(?:headers|params|query|request\.body)\b/iu,
      },
      {
        kind: "next-url-search-parameter",
        expression:
          /\b(?:searchParams|nextUrl\.searchParams)\.(?:get|getAll)\s*\(/iu,
      },
    ],
    sinks: [
      {
        kind: "filesystem-path",
        expression:
          /\b(?:access|appendFile|appendFileSync|chmod|chmodSync|chown|chownSync|copyFile|copyFileSync|cp|cpSync|createReadStream|createWriteStream|link|linkSync|lstat|lstatSync|mkdir|mkdirSync|mkdtemp|mkdtempSync|open|openSync|opendir|opendirSync|readFile|readFileSync|readdir|readdirSync|readlink|readlinkSync|realpath|realpathSync|rename|renameSync|rm|rmSync|rmdir|rmdirSync|stat|statSync|symlink|symlinkSync|truncate|truncateSync|unlink|unlinkSync|utimes|utimesSync|watch|writeFile|writeFileSync)\s*\(/u,
        cweIds: ["CWE-22"],
      },
    ],
    controls: [
      {
        kind: "fixed-path-allowlist",
        expression:
          /\b(?:ALLOWED|DOCUMENTS|KNOWN|TRUSTED)_(?:FILES?|PATHS?)\b|\b(?:allowed|document|known|trusted)(?:Files?|Paths?)\b|\bDOCUMENTS\b|\bObject\.(?:hasOwn|freeze)\s*\(/iu,
      },
      {
        kind: "absolute-path-rejection",
        expression: /\b(?:isAbsolute|isSafeRelativePath)\s*\(/iu,
      },
      {
        kind: "canonical-or-normalized-path",
        expression: /\b(?:realpath|realpathSync|resolve)\s*\(/iu,
      },
      {
        kind: "component-aware-root-containment",
        expression:
          /\brelative\s*\(|\b(?:candidate|relative)\.(?:startsWith|includes)\s*\(/iu,
      },
      {
        kind: "link-or-race-resistant-filesystem-access",
        expression: /\b(?:O_NOFOLLOW|opendir|openat|realpath|realpathSync)\b/iu,
      },
    ],
  },
  {
    id: "python-web-command",
    language: "python",
    extensions: PYTHON_EXTENSIONS,
    activation: [
      /\b(?:from\s+subprocess\s+import|import\s+(?:os|subprocess))\b/iu,
    ],
    sources: [
      {
        kind: "framework-request-field",
        expression:
          /\brequest\.(?:args|cookies|files|form|headers|json|values)\b|\brequest\.get_json\s*\(/iu,
      },
      {
        kind: "fastapi-bound-parameter",
        expression: /\b(?:Body|Cookie|Form|Header|Path|Query)\s*\(/u,
      },
    ],
    sinks: [
      {
        kind: "os-shell-command",
        expression: /\bos\.(?:popen|system)\s*\(/iu,
        cweIds: ["CWE-78"],
      },
      {
        kind: "subprocess-explicit-shell",
        expression:
          /\bsubprocess\.(?:call|check_call|check_output|Popen|run)\s*\([^\r\n]*\bshell\s*=\s*True\b/iu,
        cweIds: ["CWE-78"],
      },
    ],
    controls: [
      {
        kind: "argument-vector-without-shell",
        expression:
          /\bsubprocess\.(?:call|check_call|check_output|Popen|run)\s*\(\s*[\[(]|\bshell\s*=\s*False\b/iu,
      },
      {
        kind: "shell-context-quoting",
        expression: /\bshlex\.quote\s*\(/iu,
      },
      {
        kind: "bounded-allowlist-or-validation",
        expression: /\b(?:allowlist|is_valid|validate)\b|\.fullmatch\s*\(/iu,
      },
    ],
  },
  {
    id: "python-web-sql",
    language: "python",
    extensions: PYTHON_EXTENSIONS,
    activation: [/\b(?:django\.db|psycopg|sqlalchemy|sqlite3)\b/iu],
    sources: [
      {
        kind: "framework-request-field",
        expression:
          /\brequest\.(?:args|cookies|form|GET|json|POST|values)\b|\brequest\.get_json\s*\(/iu,
      },
      {
        kind: "fastapi-bound-parameter",
        expression: /\b(?:Body|Cookie|Form|Header|Path|Query)\s*\(/u,
      },
    ],
    sinks: [
      {
        kind: "raw-sql-execution",
        expression:
          /\b(?:connection|cursor|session)\.(?:execute|executemany|executescript)\s*\(|\.raw\s*\(/iu,
        cweIds: ["CWE-89"],
      },
    ],
    controls: [
      {
        kind: "bound-query-parameters",
        expression:
          /\b(?:bindparam|parameters|params)\b|\.(?:execute|executemany)\s*\([^,\r\n]+,/iu,
      },
      {
        kind: "orm-expression-builder",
        expression: /\b(?:filter|filter_by|where)\s*\(/iu,
      },
      {
        kind: "bounded-allowlist-or-validation",
        expression: /\b(?:allowlist|is_valid|validate)\b|\.fullmatch\s*\(/iu,
      },
    ],
  },
  {
    id: "python-web-ssrf",
    language: "python",
    extensions: PYTHON_EXTENSIONS,
    activation: [
      /\b(?:aiohttp|httpx|requests|urllib3?)\b/iu,
      /\bfrom\s+urllib\.request\s+import\s+urlopen\b/iu,
    ],
    sources: [
      {
        kind: "framework-request-field",
        expression:
          /\brequest\.(?:args|cookies|form|GET|headers|json|POST|values)\b|\brequest\.get_json\s*\(/iu,
      },
      {
        kind: "fastapi-bound-parameter",
        expression: /\b(?:Body|Cookie|Form|Header|Path|Query)\s*\(/u,
      },
    ],
    sinks: [
      {
        kind: "outbound-http-url",
        expression:
          /\b(?:aiohttp|httpx|requests|urllib3)\.(?:delete|get|head|options|patch|post|put|request)\s*\(|\b(?:urllib\.request\.)?urlopen\s*\(/iu,
        cweIds: ["CWE-918"],
      },
    ],
    controls: [
      {
        kind: "fixed-destination-allowlist",
        expression: /\b(?:allowed_urls?|asset_urls?|trusted_urls?)\b/iu,
      },
      {
        kind: "parsed-host-exact-allowlist",
        expression:
          /\.hostname\b\s*(?:==|\b(?:not\s+)?in\b)[^\r\n]*\b(?:allowed_hosts?|trusted_hosts?)\b|\.hostname\b\s*==/iu,
      },
      {
        kind: "fixed-origin-url-construction",
        expression: /\b(?:urljoin|urlunsplit)\s*\(/iu,
      },
      {
        kind: "redirects-disabled",
        expression: /\b(?:allow_redirects|follow_redirects)\s*=\s*False\b/u,
      },
      {
        kind: "network-address-validation-or-pinning",
        expression:
          /\b(?:getaddrinfo|ip_address|is_global|is_private|pinned_address|connect_address)\b/iu,
      },
    ],
  },
  {
    id: "python-web-template-injection",
    language: "python",
    extensions: PYTHON_EXTENSIONS,
    activation: [
      /\b(?:django\.template|flask|jinja2|mako)\b/iu,
      /\b(?:Environment|render_template_string|Template)\b/iu,
    ],
    sources: [
      {
        kind: "framework-request-field",
        expression:
          /\brequest\.(?:args|cookies|form|GET|headers|json|POST|values)\b|\brequest\.get_json\s*\(/iu,
      },
      {
        kind: "fastapi-bound-parameter",
        expression: /\b(?:Body|Cookie|Form|Header|Path|Query)\s*\(/u,
      },
    ],
    sinks: [
      {
        kind: "dynamic-template-source",
        expression:
          /\b(?:render_template_string|Template)\s*\(|\.from_string\s*\(/iu,
        cweIds: ["CWE-1336"],
      },
    ],
    controls: [
      {
        kind: "fixed-template-with-data-context",
        expression:
          /\b(?:render_template_string|Template)\s*\(\s*[rub]*(?:["']|["']{3})/iu,
      },
      {
        kind: "sandboxed-template-environment",
        expression:
          /\b(?:ImmutableSandboxedEnvironment|SandboxedEnvironment)\b/iu,
      },
      {
        kind: "bounded-template-identifier-map",
        expression:
          /\b(?:allowed_templates?|template_map|template_names?|trusted_templates?)\b/iu,
      },
    ],
  },
  {
    id: "python-web-path",
    language: "python",
    extensions: PYTHON_EXTENSIONS,
    activation: [/\bopen\s*\(/u, /\b(?:builtins|os|shutil)\b/iu],
    sources: [
      {
        kind: "framework-request-field",
        expression:
          /\brequest\.(?:args|cookies|files|form|GET|headers|json|POST|values)\b|\brequest\.get_json\s*\(/iu,
      },
      {
        kind: "fastapi-bound-parameter",
        expression: /\b(?:Body|Cookie|Form|Header|Path|Query)\s*\(/u,
      },
    ],
    sinks: [
      {
        kind: "filesystem-path",
        expression:
          /\b(?:chmod|chown|copy|copy2|copyfile|copytree|lchmod|lchown|listdir|lstat|makedirs|mkdir|move|open|readlink|remove|removedirs|rename|renames|replace|rmdir|rmtree|scandir|stat|truncate|unlink|utime|walk)\s*\(/u,
        cweIds: ["CWE-22"],
      },
    ],
    controls: [
      {
        kind: "fixed-path-allowlist",
        expression:
          /\b(?:ALLOWED|DOCUMENTS|KNOWN|TRUSTED)_(?:FILES?|PATHS?)\b|\b(?:allowed|document|known|trusted)_(?:files?|paths?)\b|\bDOCUMENTS\b/iu,
      },
      {
        kind: "absolute-path-rejection",
        expression: /\b(?:isabs|is_absolute|is_safe_relative_path)\s*\(/iu,
      },
      {
        kind: "canonical-or-normalized-path",
        expression: /\b(?:abspath|normpath|realpath|resolve)\s*\(/iu,
      },
      {
        kind: "component-aware-root-containment",
        expression: /\b(?:commonpath|is_relative_to|relative_to)\s*\(/iu,
      },
      {
        kind: "link-or-race-resistant-filesystem-access",
        expression: /\b(?:dir_fd|O_NOFOLLOW|follow_symlinks\s*=\s*False)\b/u,
      },
    ],
  },
  {
    id: "spring-http-command",
    language: "java-kotlin",
    extensions: JAVA_EXTENSIONS,
    activation: [/\b(?:ProcessBuilder|Runtime\.getRuntime\s*\(\))\b/iu],
    sources: [
      {
        kind: "spring-bound-parameter",
        expression:
          /@(?:CookieValue|PathVariable|RequestBody|RequestHeader|RequestParam)\b/iu,
      },
      {
        kind: "servlet-request-parameter",
        expression: /\b(?:getHeader|getParameter|getParameterValues)\s*\(/iu,
      },
    ],
    sinks: [
      {
        kind: "runtime-command-execution",
        expression: /\bRuntime\.getRuntime\s*\(\)\.exec\s*\(/iu,
        cweIds: ["CWE-78"],
      },
      {
        kind: "process-builder-execution",
        expression: /\bnew\s+ProcessBuilder\s*\(/iu,
        cweIds: ["CWE-78"],
      },
    ],
    controls: [
      {
        kind: "fixed-executable-argument-list",
        expression: /\bProcessBuilder\s*\(\s*(?:List\.of|new\s+String\s*\[)/iu,
      },
      {
        kind: "bounded-allowlist-or-validation",
        expression:
          /\b(?:allowedCommands?|isValid|validate)\b|\.matches\s*\(/iu,
      },
    ],
  },
  {
    id: "spring-http-sql",
    language: "java-kotlin",
    extensions: JAVA_EXTENSIONS,
    activation: [
      /\b(?:EntityManager|JdbcTemplate|NamedParameterJdbcTemplate|Statement)\b/iu,
    ],
    sources: [
      {
        kind: "spring-bound-parameter",
        expression:
          /@(?:CookieValue|PathVariable|RequestBody|RequestHeader|RequestParam)\b/iu,
      },
      {
        kind: "servlet-request-parameter",
        expression: /\b(?:getHeader|getParameter|getParameterValues)\s*\(/iu,
      },
    ],
    sinks: [
      {
        kind: "raw-sql-execution",
        expression:
          /\b(?:createNativeQuery|executeQuery|executeUpdate)\s*\(|\b(?:jdbcTemplate|statement)\.(?:execute|query|queryForObject|update)\s*\(/iu,
        cweIds: ["CWE-89"],
      },
    ],
    controls: [
      {
        kind: "bound-query-parameters",
        expression:
          /\b(?:NamedParameterJdbcTemplate|PreparedStatement|setParameter|setString)\b/iu,
      },
      {
        kind: "bounded-allowlist-or-validation",
        expression: /\b(?:allowedColumns?|isValid|validate)\b|\.matches\s*\(/iu,
      },
    ],
  },
  {
    id: "spring-http-template-injection",
    language: "java-kotlin",
    extensions: JAVA_EXTENSIONS,
    activation: [/\b(?:Handlebars|Jinjava|PebbleEngine|Velocity)\b/iu],
    sources: [
      {
        kind: "spring-bound-parameter",
        expression:
          /@(?:CookieValue|PathVariable|RequestBody|RequestHeader|RequestParam)\b/iu,
      },
      {
        kind: "servlet-request-parameter",
        expression: /\b(?:getHeader|getParameter|getParameterValues)\s*\(/iu,
      },
    ],
    sinks: [
      {
        kind: "dynamic-template-source",
        expression:
          /\bVelocity\.evaluate\s*\(|\bJinjava\.render\s*\(|\bHandlebars\.compile\s*\(|\.getLiteralTemplate\s*\(/iu,
        cweIds: ["CWE-1336"],
      },
    ],
    controls: [
      {
        kind: "fixed-template-with-data-context",
        expression:
          /\bVelocity\.evaluate\s*\([^,]+,[^,]+,[^,]+,\s*"|\b(?:Jinjava\.render|Handlebars\.compile)\s*\(\s*"|\.getLiteralTemplate\s*\(\s*"/iu,
      },
      {
        kind: "sandboxed-template-environment",
        expression:
          /\b(?:SecureUberspector|Sandbox|Sandboxed|ClassFilter|MemberAccessPolicy)\b/iu,
      },
      {
        kind: "bounded-template-identifier-map",
        expression:
          /\b(?:ALLOWED_TEMPLATES|allowedTemplates|templateMap|trustedTemplates)\b/iu,
      },
    ],
  },
  {
    id: "spring-http-object-authorization",
    language: "java-kotlin",
    extensions: JAVA_EXTENSIONS,
    activation: [
      /\b(?:CrudRepository|JpaRepository|PagingAndSortingRepository)\b|\bfindById/iu,
      /\borg\.springframework\.data\.(?:jpa\.)?repository\b/iu,
    ],
    sources: [
      {
        kind: "spring-object-reference",
        expression:
          /@(?:CookieValue|PathVariable|RequestBody|RequestHeader|RequestParam)\b/iu,
      },
      {
        kind: "servlet-object-reference",
        expression: /\b(?:getHeader|getParameter|getParameterValues)\s*\(/iu,
      },
    ],
    sinks: [
      {
        kind: "spring-data-object-record-lookup",
        expression:
          /\.\s*findById(?:And(?:Account|Customer|Organization|Owner|Principal|Tenant|User|Workspace)Id)?\s*\(/iu,
        cweIds: ["CWE-639", "CWE-862"],
      },
    ],
    controls: [
      {
        kind: "principal-bound-object-query",
        expression:
          /\bfindByIdAnd(?:Account|Customer|Organization|Owner|Principal|Tenant|User|Workspace)Id\s*\(/iu,
      },
      {
        kind: "enabled-return-object-authorization",
        expression: /@PostAuthorize\s*\(/iu,
      },
    ],
  },
  {
    id: "spring-mvc-jpa-mass-assignment",
    language: "java-kotlin",
    extensions: JAVA_EXTENSIONS,
    activation: [
      /\bModelAttribute\b|\bWebDataBinder\b/iu,
      /\bJpaRepository\b|\bCrudRepository\b|\.\s*save\s*\(/iu,
    ],
    sources: [
      {
        kind: "spring-bound-domain-object",
        expression: /\bModelAttribute\b/iu,
      },
    ],
    sinks: [
      {
        kind: "jpa-bound-entity-save",
        expression: /\.\s*save\s*\(/iu,
        cweIds: ["CWE-915"],
      },
    ],
    controls: [
      {
        kind: "explicit-binding-allowlist",
        expression: /\.\s*setAllowedFields\s*\(/iu,
      },
      {
        kind: "constructor-only-binding",
        expression: /\.\s*setDeclarativeBinding\s*\(\s*true\s*\)/iu,
      },
    ],
  },
  {
    id: "spring-http-ssrf",
    language: "java-kotlin",
    extensions: JAVA_EXTENSIONS,
    activation: [
      /\b(?:java\.net\.http|okhttp3|HttpClient|HttpRequest|OkHttpClient|Request\.Builder|RestTemplate|WebClient)\b/iu,
    ],
    sources: [
      {
        kind: "spring-bound-parameter",
        expression:
          /@(?:CookieValue|PathVariable|RequestBody|RequestHeader|RequestParam)\b/iu,
      },
      {
        kind: "servlet-request-parameter",
        expression: /\b(?:getHeader|getParameter|getParameterValues)\s*\(/iu,
      },
    ],
    sinks: [
      {
        kind: "outbound-http-url",
        expression:
          /\b[A-Za-z_$][\w$]*\s*\.\s*(?:send|sendAsync|uri|url)\s*\(|\.\s*(?:uri|url)\s*\(|\b(?:java\.net\.http\.)?HttpClient\s*\.\s*(?:newHttpClient|newBuilder)\s*\(\)[^;\r\n]*?\.\s*(?:send|sendAsync)\s*\(|\b[A-Za-z_$][\w$]*\s*\.\s*(?:delete|exchange|execute|getForEntity|getForObject|headForHeaders|optionsForAllow|patchForObject|postForEntity|postForLocation|postForObject|put)\s*\(|\bnew\s+(?:org\.springframework\.web\.client\.)?RestTemplate\s*\([^)]*\)\s*\.\s*(?:delete|exchange|execute|getForEntity|getForObject|headForHeaders|optionsForAllow|patchForObject|postForEntity|postForLocation|postForObject|put)\s*\(/iu,
        cweIds: ["CWE-918"],
      },
    ],
    controls: [
      {
        kind: "fixed-destination-allowlist",
        expression:
          /\b(?:ALLOWED|KNOWN|TRUSTED|VALID)_(?:DESTINATIONS?|ENDPOINTS?|URIS?|URLS?)\b|\b(?:allowed|known|trusted|valid)(?:Destinations?|Endpoints?|Uris?|Urls?)\b|\.containsKey\s*\(/iu,
      },
      {
        kind: "parsed-host-exact-allowlist",
        expression:
          /\.getHost\s*\(\)\s*\.equals\s*\(|\b(?:allowed|trusted)Hosts?\.contains\s*\(/iu,
      },
      {
        kind: "allowed-uri-scheme",
        expression:
          /\.getScheme\s*\(\)\s*\.equals\s*\(|\b(?:allowed|trusted)Schemes?\.contains\s*\(/iu,
      },
      {
        kind: "fixed-origin-url-construction",
        expression:
          /\b(?:URI\.create|new\s+URI)\s*\(\s*"|\bHttpRequest\.newBuilder\s*\(\s*URI\.create\s*\(\s*"/iu,
      },
      {
        kind: "redirects-disabled",
        expression:
          /\b(?:HttpClient\.)?Redirect\.NEVER\b|\.followRedirects?\s*\(\s*false\s*\)|\.followSslRedirects\s*\(\s*false\s*\)/iu,
      },
      {
        kind: "network-address-validation-or-pinning",
        expression:
          /\b(?:InetAddress\.getAllByName|Dns\.SYSTEM|isLoopbackAddress|isSiteLocalAddress|isLinkLocalAddress|isPublicAddress|lookupAndPin|pinnedAddress|connectAddress)\b|\.dns\s*\(/iu,
      },
    ],
  },
  {
    id: "spring-http-path",
    language: "java-kotlin",
    extensions: JAVA_EXTENSIONS,
    activation: [
      /\b(?:java\.io|java\.nio\.file|FileInputStream|FileOutputStream|FileReader|FileWriter|Files\.|Path\.|Paths\.)\b/iu,
    ],
    sources: [
      {
        kind: "spring-bound-parameter",
        expression:
          /@(?:CookieValue|PathVariable|RequestBody|RequestHeader|RequestParam)\b/iu,
      },
      {
        kind: "servlet-request-parameter",
        expression: /\b(?:getHeader|getParameter|getParameterValues)\s*\(/iu,
      },
    ],
    sinks: [
      {
        kind: "filesystem-path",
        expression:
          /\b(?:java\.nio\.file\.)?Files\.(?:copy|delete|deleteIfExists|lines|move|newBufferedReader|newBufferedWriter|newByteChannel|newInputStream|newOutputStream|readAllBytes|readAllLines|readString|write|writeString)\s*\(|\bnew\s+(?:java\.io\.)?(?:FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)\s*\(/iu,
        cweIds: ["CWE-22"],
      },
    ],
    controls: [
      {
        kind: "fixed-path-allowlist",
        expression:
          /\b(?:ALLOWED|KNOWN|TRUSTED)_(?:FILES?|PATHS?)\b|\b(?:allowed|known|trusted)(?:Files?|Paths?)\b|\.containsKey\s*\(/iu,
      },
      {
        kind: "absolute-path-rejection",
        expression: /\.isAbsolute\s*\(\)/iu,
      },
      {
        kind: "normalized-path",
        expression: /\.normalize\s*\(\)/iu,
      },
      {
        kind: "filesystem-canonical-path",
        expression: /\.toRealPath\s*\(/iu,
      },
      {
        kind: "component-aware-root-containment",
        expression: /\.startsWith\s*\(/iu,
      },
      {
        kind: "link-or-race-resistant-filesystem-access",
        expression:
          /\b(?:LinkOption\.NOFOLLOW_LINKS|SecureDirectoryStream|NOFOLLOW_LINKS)\b/iu,
      },
    ],
  },
  {
    id: "aspnet-http-command",
    language: "dotnet",
    extensions: DOTNET_EXTENSIONS,
    activation: [
      /\b(?:Process\.Start|ProcessStartInfo|System\.Diagnostics)\b/iu,
    ],
    sources: [
      {
        kind: "aspnet-bound-parameter",
        expression:
          /\[(?:FromBody|FromForm|FromHeader|FromQuery|FromRoute)\b/iu,
      },
      {
        kind: "aspnet-request-field",
        expression:
          /\bRequest\.(?:Body|Form|Headers|Query|RouteValues)\b|\bHttpRequest\b/iu,
      },
    ],
    sinks: [
      {
        kind: "process-start",
        expression: /\b(?:Process\.Start|new\s+ProcessStartInfo)\s*\(/iu,
        cweIds: ["CWE-78"],
      },
    ],
    controls: [
      {
        kind: "fixed-executable-argument-list",
        expression:
          /\bArgumentList\.Add\s*\(|\bUseShellExecute\s*=\s*false\b/iu,
      },
      {
        kind: "bounded-allowlist-or-validation",
        expression:
          /\b(?:AllowedCommands?|IsValid|Validate)\b|Regex\.IsMatch\s*\(/iu,
      },
    ],
  },
  {
    id: "aspnet-http-sql",
    language: "dotnet",
    extensions: DOTNET_EXTENSIONS,
    activation: [/\b(?:DbContext|FromSqlRaw|SqlCommand|ExecuteSqlRaw)\b/iu],
    sources: [
      {
        kind: "aspnet-bound-parameter",
        expression:
          /\[(?:FromBody|FromForm|FromHeader|FromQuery|FromRoute)\b/iu,
      },
      {
        kind: "aspnet-request-field",
        expression:
          /\bRequest\.(?:Body|Form|Headers|Query|RouteValues)\b|\bHttpRequest\b/iu,
      },
    ],
    sinks: [
      {
        kind: "raw-sql-execution",
        expression:
          /\b(?:ExecuteSqlRaw|FromSqlRaw)\s*\(|\bnew\s+SqlCommand\s*\(/iu,
        cweIds: ["CWE-89"],
      },
    ],
    controls: [
      {
        kind: "bound-query-parameters",
        expression:
          /\b(?:DbParameter|FromSqlInterpolated|SqlParameter)\b|\.Parameters\.Add(?:WithValue)?\s*\(/iu,
      },
      {
        kind: "bounded-allowlist-or-validation",
        expression:
          /\b(?:AllowedColumns?|IsValid|Validate)\b|Regex\.IsMatch\s*\(/iu,
      },
    ],
  },
  {
    id: "aspnet-http-object-authorization",
    language: "dotnet",
    extensions: DOTNET_EXTENSIONS,
    activation: [
      /^\s*(?:global\s+)?using\s+Microsoft\.EntityFrameworkCore\s*;/mu,
      /\b(?:DbContext|DbSet\s*<[^;{}]+>|FindAsync|SingleOrDefaultAsync)\b/iu,
    ],
    sources: [
      {
        kind: "aspnet-object-reference",
        expression:
          /\[(?:FromBody|FromForm|FromHeader|FromQuery|FromRoute)\b/iu,
      },
      {
        kind: "aspnet-request-object-reference",
        expression:
          /\bRequest\.(?:Body|Form|Headers|Query|RouteValues)\b|\bHttpRequest\b/iu,
      },
    ],
    sinks: [
      {
        kind: "ef-core-object-record-lookup",
        expression:
          /\.\s*(?:Find|FindAsync|First|FirstAsync|FirstOrDefault|FirstOrDefaultAsync|Single|SingleAsync|SingleOrDefault|SingleOrDefaultAsync)\s*(?:<[^;(){}]+>)?\s*\(/iu,
        cweIds: ["CWE-639", "CWE-862"],
      },
    ],
    controls: [
      {
        kind: "principal-bound-object-filter",
        expression:
          /\b(?:account|customer|organization|owner|principal|tenant|user|workspace)Id\b/iu,
      },
      {
        kind: "resource-based-object-authorization",
        expression: /\bAuthorizeAsync\s*\(/iu,
      },
    ],
  },
  {
    id: "aspnet-http-template-injection",
    language: "dotnet",
    extensions: DOTNET_EXTENSIONS,
    activation: [
      /^\s*(?:global\s+)?using\s+Scriban\s*;/mu,
      /\b(?:global\s*::\s*)?Scriban\s*\.\s*Template\s*\.\s*Parse\s*\(/iu,
      /^\s*(?:global\s+)?using\s+RazorLight\s*;/mu,
      /\bCompileRenderStringAsync(?:\s*<[^;(){}]+>)?\s*\(/iu,
    ],
    sources: [
      {
        kind: "aspnet-bound-parameter",
        expression:
          /\[(?:FromBody|FromForm|FromHeader|FromQuery|FromRoute)\b/iu,
      },
      {
        kind: "aspnet-request-field",
        expression:
          /\bRequest\.(?:Body|Form|Headers|Query|RouteValues)\b|\bHttpRequest\b/iu,
      },
    ],
    sinks: [
      {
        kind: "dynamic-template-source",
        expression:
          /\b(?:(?:global\s*::\s*)?Scriban\s*\.\s*)?Template\s*\.\s*Parse\s*\(/iu,
        cweIds: ["CWE-1336"],
      },
      {
        kind: "dynamic-razor-template-source",
        expression: /\bCompileRenderStringAsync(?:\s*<[^;(){}]+>)?\s*\(/iu,
        cweIds: ["CWE-1336"],
      },
    ],
    controls: [
      {
        kind: "bounded-template-source-map",
        expression:
          /\b(?:Allowed|Known|Trusted)(?:Templates?|TemplateSources?)\b|\.TryGetValue\s*\(/iu,
      },
      {
        kind: "restricted-template-context",
        expression:
          /\b(?:MemberFilter|MemberRenamer|TemplateContext|ScriptObject)\b/iu,
      },
    ],
  },
  {
    id: "aspnet-http-ssrf",
    language: "dotnet",
    extensions: DOTNET_EXTENSIONS,
    activation: [
      /\b(?:HttpClient|HttpClientHandler|IHttpClientFactory|SocketsHttpHandler)\b/iu,
    ],
    sources: [
      {
        kind: "aspnet-bound-parameter",
        expression:
          /\[(?:FromBody|FromForm|FromHeader|FromQuery|FromRoute)\b/iu,
      },
      {
        kind: "aspnet-request-field",
        expression:
          /\bRequest\.(?:Body|Form|Headers|Query|RouteValues)\b|\bHttpRequest\b/iu,
      },
    ],
    sinks: [
      {
        kind: "outbound-http-url",
        expression:
          /\.(?:DeleteAsync|GetAsync|GetByteArrayAsync|GetStreamAsync|GetStringAsync|PatchAsync|PostAsync|PutAsync)\s*\(/iu,
        cweIds: ["CWE-918"],
      },
    ],
    controls: [
      {
        kind: "fixed-destination-allowlist",
        expression:
          /\b(?:Allowed|Asset|Trusted)(?:Hosts?|Uris?|Urls?)\b|\.TryGetValue\s*\(/iu,
      },
      {
        kind: "parsed-host-exact-allowlist",
        expression:
          /\.(?:DnsSafeHost|Host|IdnHost)\b\s*(?:==|!=)|\b(?:Allowed|Trusted)Hosts?\.(?:Contains|TryGetValue)\s*\(/iu,
      },
      {
        kind: "fixed-origin-url-construction",
        expression:
          /\b(?:new\s+Uri|Uri\.TryCreate)\s*\(\s*"|\bBaseAddress\s*=\s*new\s+Uri\s*\(\s*"/iu,
      },
      {
        kind: "redirects-disabled",
        expression: /\bAllowAutoRedirect\s*=\s*false\b/iu,
      },
      {
        kind: "network-address-validation-or-pinning",
        expression:
          /\b(?:ConnectCallback|Dns\.GetHostAddressesAsync?|IPAddress\.IsLoopback|IsPrivateAddress|IsPublicAddress|PinnedAddress|SocketsHttpHandler)\b/iu,
      },
    ],
  },
  {
    id: "aspnet-http-path",
    language: "dotnet",
    extensions: DOTNET_EXTENSIONS,
    activation: [
      /\b(?:System\.IO|FileStream|Path\.(?:Combine|Join|GetFullPath|GetRelativePath)|File\.(?:Append\w*|Copy|Create\w*|Delete|Move|Open\w*|Read\w*|Write\w*)\s*\()/iu,
    ],
    sources: [
      {
        kind: "aspnet-bound-parameter",
        expression:
          /\[(?:FromBody|FromForm|FromHeader|FromQuery|FromRoute)\b/iu,
      },
      {
        kind: "aspnet-request-field",
        expression:
          /\bRequest\.(?:Body|Form|Headers|Query|RouteValues)\b|\bHttpRequest\b/iu,
      },
    ],
    sinks: [
      {
        kind: "filesystem-path",
        expression:
          /\b(?:System\.IO\.)?File\.(?:AppendAllLines|AppendAllText|AppendAllTextAsync|Copy|Create|CreateText|Delete|Move|Open|OpenHandle|OpenRead|OpenText|OpenWrite|ReadAllBytes|ReadAllBytesAsync|ReadAllLines|ReadAllLinesAsync|ReadAllText|ReadAllTextAsync|ReadLines|WriteAllBytes|WriteAllBytesAsync|WriteAllLines|WriteAllLinesAsync|WriteAllText|WriteAllTextAsync)\s*\(|\bnew\s+(?:System\.IO\.)?FileStream\s*\(/iu,
        cweIds: ["CWE-22"],
      },
    ],
    controls: [
      {
        kind: "fixed-path-allowlist",
        expression:
          /\b(?:Allowed|Known|Trusted)(?:Files?|Paths?)\b|\.TryGetValue\s*\(/iu,
      },
      {
        kind: "rooted-path-rejection",
        expression: /\bPath\.IsPathRooted\s*\(/iu,
      },
      {
        kind: "canonical-full-path",
        expression: /\bPath\.GetFullPath\s*\(/iu,
      },
      {
        kind: "canonical-relative-containment",
        expression: /\bPath\.GetRelativePath\s*\(/iu,
      },
      {
        kind: "relative-parent-boundary-rejection",
        expression: /\b(?:relative|candidate)\w*\.StartsWith\s*\(/iu,
      },
      {
        kind: "single-path-component-validation",
        expression:
          /\bPath\.GetFileName\s*\(|\b(?:DirectorySeparatorChar|AltDirectorySeparatorChar)\b/iu,
      },
      {
        kind: "link-or-reparse-point-defense",
        expression:
          /\b(?:FileAttributes\.ReparsePoint|FileOptions\.OpenReparsePoint|LinkTarget|ResolveLinkTarget)\b/iu,
      },
    ],
  },
];

const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  ".venv",
  "bin",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "obj",
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
  sourceExcerpt?: string;
  frameworkModel?: {
    schemaVersion: "1.2";
    id: string;
    language: string;
    scope:
      | "same-file"
      | "cross-file"
      | "cross-file-wrapper"
      | "cross-file-multi-hop-wrapper";
    source: { kind: string; path: string; line: number };
    sink: {
      kind: string;
      path: string;
      line: number;
      cweIds: readonly string[];
    };
    propagators: Array<{
      kind: string;
      path: string;
      line: number;
      symbol?: string;
    }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

interface SourceFileSnapshot {
  path: string;
  extension: string;
  lines: readonly string[];
  text: string;
}

interface ExportedJavascriptFunction {
  symbol: string;
  parameters: string[];
  startLine: number;
  endLine: number;
}

interface ExportedPythonFunction {
  symbol: string;
  parameters: string[];
  startLine: number;
  endLine: number;
}

interface ExportedJavaMethod {
  ownerType: string;
  symbol: string;
  parameters: Array<{ name: string; declaration: string }>;
  startLine: number;
  endLine: number;
}

interface JavaMethodDeclaration extends ExportedJavaMethod {
  access: "package" | "private" | "protected" | "public";
  isStatic: boolean;
  returnType: string;
}

interface JavaBasenameHelperSummary {
  ownerType: string;
  access: JavaMethodDeclaration["access"];
  isStatic: boolean;
  symbol: string;
  parameterIndex: number;
  parameterCount: number;
  inputKind: "file" | "path" | "string";
  reductionLine: number;
  sourcePath: string;
  packageName?: string;
  projectRoot: string;
}

interface JavaBasenameProjectGraph {
  directDependencies: ReadonlyMap<string, ReadonlySet<string>>;
}

interface JavaMavenXmlElement {
  name: string;
  children: JavaMavenXmlElement[];
  text: string;
}

interface JavaMavenParent {
  groupId: string;
  artifactId: string;
  version: string;
  relativePath?: string;
  localResolutionDisabled: boolean;
}

interface JavaMavenDependency {
  groupId: string;
  artifactId: string;
  version: string;
  scope?: string;
  type?: string;
  classifier?: string;
}

interface JavaMavenPom {
  root: string;
  groupId?: string;
  artifactId: string;
  version?: string;
  packaging?: string;
  parent?: JavaMavenParent;
  modules: readonly string[];
  dependencies: readonly JavaMavenDependency[];
}

interface JavaMavenCoordinates {
  groupId: string;
  artifactId: string;
  version: string;
}

interface JavaBasenameOrigin {
  evidenceLine: number;
  evidencePath: string;
  guardStartLine: number;
}

interface JavaBasenameBoundary {
  reductionLine: number;
  reductionPath: string;
  parentRejectionLine?: number;
}

interface ExportedDotnetMethod {
  ownerType: string;
  symbol: string;
  access: "public" | "protected" | "internal";
  isStatic: boolean;
  parameters: Array<{ name: string; declaration: string }>;
  startLine: number;
  endLine: number;
}

interface FrameworkWrapperSummary {
  model: FrameworkDataflowModel;
  file: SourceFileSnapshot;
  ownerType?: string;
  symbol: string;
  parameter: string;
  parameterIndex: number;
  parameterCount?: number;
  valueType?: string;
  declarationLine: number;
  sink: { kind: string; line: number; cweIds: readonly string[] };
  controls: Array<{ kind: string; line: number }>;
}

interface FrameworkRelaySummary {
  model: FrameworkDataflowModel;
  file: SourceFileSnapshot;
  symbol: string;
  parameter: string;
  parameterIndex: number;
  declarationLine: number;
  downstreamImport: ImportedJavascriptSymbol | ImportedPythonSymbol;
  downstreamCallLine: number;
  downstream: FrameworkWrapperSummary | FrameworkRelaySummary;
  controls: Array<{ kind: string; line: number }>;
}

interface ImportedFrameworkRelayChain {
  relays: readonly FrameworkRelaySummary[];
  sink: FrameworkWrapperSummary;
}

interface DotnetFrameworkRelaySummary {
  model: FrameworkDataflowModel;
  file: SourceFileSnapshot;
  ownerType: string;
  symbol: string;
  parameter: string;
  parameterIndex: number;
  parameterCount: number;
  declarationLine: number;
  downstreamBinding: JavaReceiverBinding;
  downstreamCallLine: number;
  downstream: FrameworkWrapperSummary | DotnetFrameworkRelaySummary;
  controls: Array<{ kind: string; line: number }>;
}

type JavaFrameworkRelaySummary = DotnetFrameworkRelaySummary;

interface TypedFrameworkRelayChain {
  relays: readonly DotnetFrameworkRelaySummary[];
  sink: FrameworkWrapperSummary;
}

interface ImportedJavascriptSymbol {
  imported: string;
  local: string;
  moduleSpecifier: string;
  line: number;
}

interface ImportedPythonSymbol {
  imported: string;
  local: string;
  moduleSpecifier: string;
  line: number;
}

interface FrameworkFilesystemPathSink {
  expressions: readonly string[];
  operation: string;
}

const NODE_FILESYSTEM_PATH_ARGUMENTS: ReadonlyMap<string, readonly number[]> =
  new Map<string, readonly number[]>([
    ...[
      "access",
      "appendFile",
      "appendFileSync",
      "chmod",
      "chmodSync",
      "chown",
      "chownSync",
      "createReadStream",
      "createWriteStream",
      "lstat",
      "lstatSync",
      "mkdir",
      "mkdirSync",
      "mkdtemp",
      "mkdtempSync",
      "open",
      "openSync",
      "opendir",
      "opendirSync",
      "readFile",
      "readFileSync",
      "readdir",
      "readdirSync",
      "readlink",
      "readlinkSync",
      "realpath",
      "realpathSync",
      "rm",
      "rmSync",
      "rmdir",
      "rmdirSync",
      "stat",
      "statSync",
      "truncate",
      "truncateSync",
      "unlink",
      "unlinkSync",
      "utimes",
      "utimesSync",
      "watch",
      "writeFile",
      "writeFileSync",
    ].map((operation) => [operation, [0] as const] as const),
    ...[
      "copyFile",
      "copyFileSync",
      "cp",
      "cpSync",
      "link",
      "linkSync",
      "rename",
      "renameSync",
      "symlink",
      "symlinkSync",
    ].map((operation) => [operation, [0, 1] as const] as const),
  ]);

const PYTHON_FILESYSTEM_PATH_ARGUMENTS: ReadonlyMap<string, readonly number[]> =
  new Map<string, readonly number[]>([
    ["builtins.open", [0]],
    ...[
      "chmod",
      "chown",
      "lchmod",
      "lchown",
      "listdir",
      "lstat",
      "makedirs",
      "mkdir",
      "readlink",
      "remove",
      "removedirs",
      "rmdir",
      "scandir",
      "stat",
      "truncate",
      "unlink",
      "utime",
      "walk",
    ].map((operation) => [`os.${operation}`, [0] as const] as const),
    ...["rename", "renames", "replace"].map(
      (operation) => [`os.${operation}`, [0, 1] as const] as const,
    ),
    ["shutil.rmtree", [0]],
    ...["copy", "copy2", "copyfile", "copytree", "move"].map(
      (operation) => [`shutil.${operation}`, [0, 1] as const] as const,
    ),
  ]);

interface NodeCopilotTrustedInput {
  expression: string;
  kind:
    | "copilot-system-message-content"
    | "copilot-system-message-section-content"
    | "copilot-system-message-section-transform"
    | "copilot-custom-agent-prompt"
    | "copilot-custom-agent-description"
    | "copilot-tool-description";
  line: number;
}

interface NodeCopilotPromptSink {
  callEndLine: number;
  callLine: number;
  inputs: NodeCopilotTrustedInput[];
}

interface NodeCopilotSourceResolution {
  input: NodeCopilotTrustedInput;
  source: { kind: string; line: number };
}

interface JavaReceiverBinding {
  receiver: string;
  ownerType: string;
  line: number;
}

interface CoverageSurfaceDraft {
  label?: unknown;
  disposition?: unknown;
}

interface CoverageGapRecord {
  path: string;
  reason:
    | "missing_coverage_surface"
    | "missing_direct_file_review"
    | "invalid_coverage_mode"
    | "needs_follow_up"
    | "deferred_coverage_item"
    | "invalid_coverage_disposition"
    | "conflicting_coverage_surfaces";
  dispositions?: string[];
  directFileReviewObserved?: boolean;
  expectedMode?: string;
  actualMode?: unknown;
}

type FindingQualityGapReason =
  | "missing_explicit_cwe"
  | "missing_or_unanchored_code_evidence"
  | "invalid_or_ungrounded_code_evidence"
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
  | "unknown_code_evidence_refs"
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
  const sourceFiles: SourceFileSnapshot[] = [];
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
    const normalizedPath = candidatePath.replaceAll("\\", "/");
    sourceFiles.push({
      path: normalizedPath,
      extension: extname(normalizedPath).toLowerCase(),
      lines,
      text,
    });
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

  for (const file of sourceFiles) {
    records.push(
      ...frameworkDataflowRecords(file.path, file.lines, sourceFiles),
      ...githubActionsPrivilegeRecords(file.path, file.lines, file.text),
      ...githubActionsSelfHostedPrRecords(file.path, file.lines, file.text),
      ...githubActionsWorkflowInjectionRecords(
        file.path,
        file.lines,
        file.text,
      ),
    );
  }
  records.push(...githubActionsArtifactPoisoningRecords(sourceFiles));
  records.push(...githubActionsReusableWorkflowInjectionRecords(sourceFiles));
  records.push(...githubActionsCompositeActionInjectionRecords(sourceFiles));
  records.push(...goExecInjectionRecords(sourceFiles));
  records.push(...goHttpSsrfRecords(sourceFiles));
  records.push(...goPathTraversalRecords(sourceFiles));
  records.push(...goTemplateInjectionRecords(sourceFiles));
  records.push(...goObjectAuthorizationRecords(sourceFiles));
  records.push(...goGormSqlInjectionRecords(sourceFiles));
  records.push(...goSqlInjectionRecords(sourceFiles));
  records.push(...goSqlxSqlInjectionRecords(sourceFiles));
  records.push(...goSquirrelSqlInjectionRecords(sourceFiles));
  records.push(...goPgxSqlInjectionRecords(sourceFiles));
  records.push(...goPgconnSqlInjectionRecords(sourceFiles));
  records.push(...frameworkCrossFileDataflowRecords(sourceFiles));
  records.push(
    ...nodeIpv6TransitionIncompleteGuardRecords(sourceFiles, records),
  );
  records.push(...javaFileGetNamePathBoundaryRecords(sourceFiles, records));
  records.push(...javaPathGetFileNamePathBoundaryRecords(sourceFiles, records));

  return selectResidualRiskRecords(records, MAX_SIGNALS)
    .map(({ priority: _priority, excerpt, sourceExcerpt, ...record }) =>
      JSON.stringify({
        ...record,
        excerptEncoding: "base64",
        excerptBase64: Buffer.from(excerpt, "utf8").toString("base64"),
        ...(sourceExcerpt === undefined
          ? {}
          : {
              sourceExcerptEncoding: "base64",
              sourceExcerptBase64: Buffer.from(sourceExcerpt, "utf8").toString(
                "base64",
              ),
            }),
      }),
    )
    .join("\n");
}

function frameworkDataflowRecords(
  path: string,
  lines: readonly string[],
  files: readonly SourceFileSnapshot[] = [],
): ResidualRiskRecord[] {
  const extension = extname(path).toLowerCase();
  const text = lines.join("\n");
  const activationText = PYTHON_EXTENSIONS.has(extension)
    ? pythonStructuralLines(lines).join("\n")
    : extension === ".java" || extension === ".cs"
      ? cFamilyStructuralLines(lines).join("\n")
      : text;
  const records: ResidualRiskRecord[] = [];
  for (const model of FRAMEWORK_DATAFLOW_MODELS) {
    if (
      !model.extensions.has(extension) ||
      !model.activation.some((expression) => expression.test(activationText))
    ) {
      continue;
    }
    if (
      (model.id === "node-http-mongoose-nosql" ||
        model.id === "node-http-mongoose-update" ||
        model.id === "node-http-mongoose-bulk-write") &&
      !nodeMongooseHasOfficialFactoryBinding(lines)
    ) {
      continue;
    }
    const rawMatchedSources = JAVASCRIPT_EXTENSIONS.has(extension)
      ? matchingJavascriptModelLines(lines, model.sources, 16)
      : PYTHON_EXTENSIONS.has(extension)
        ? matchingPythonModelLines(lines, model.sources, 16)
        : extension === ".java" || extension === ".cs"
          ? matchingJavaModelLines(lines, model.sources, 16)
          : matchingModelLines(lines, model.sources, 16);
    const matchedSources = PYTHON_EXTENSIONS.has(extension)
      ? rawMatchedSources.filter(
          (source) =>
            source.kind !== "fastapi-bound-parameter" ||
            pythonFastApiParameterSourceHasOfficialBinding(lines),
        )
      : rawMatchedSources;
    const sources =
      extension === ".cs" && model.id.startsWith("aspnet-http-")
        ? [...matchedSources, ...dotnetRazorPageSources(files, path, lines)]
            .filter(
              (source, index, all) =>
                all.findIndex(
                  (candidate) =>
                    candidate.kind === source.kind &&
                    candidate.line === source.line,
                ) === index,
            )
            .slice(0, 16)
        : matchedSources;
    const sinks =
      model.id === "node-http-path" || model.id === "python-web-path"
        ? exactFilesystemPathSinkLines(lines, model.id, 32)
        : JAVASCRIPT_EXTENSIONS.has(extension)
          ? matchingJavascriptModelLines(
              lines,
              model.sinks,
              model.id === "node-http-ssrf" ||
                model.id === "node-http-object-authorization" ||
                model.id === "node-copilot-system-prompt-injection"
                ? 64
                : 8,
            )
          : PYTHON_EXTENSIONS.has(extension)
            ? matchingPythonModelLines(lines, model.sinks, 8)
            : extension === ".java" || extension === ".cs"
              ? matchingJavaModelLines(lines, model.sinks, 8)
              : matchingModelLines(lines, model.sinks, 8);
    if (sources.length === 0 || sinks.length === 0) continue;
    const controls = JAVASCRIPT_EXTENSIONS.has(extension)
      ? model.id === "node-http-object-authorization" ||
        model.id === "node-http-mongoose-nosql" ||
        model.id === "node-http-mongoose-update" ||
        model.id === "node-http-mongoose-bulk-write"
        ? []
        : model.id === "node-http-ssrf" || model.id === "node-http-path"
          ? matchingJavascriptControlLines(lines, model.controls, 24)
          : matchingModelLines(lines, model.controls, 24)
      : PYTHON_EXTENSIONS.has(extension)
        ? matchingPythonModelLines(lines, model.controls, 24)
        : extension === ".java" || extension === ".cs"
          ? model.id === "aspnet-http-object-authorization" ||
            model.id === "spring-http-object-authorization" ||
            model.id === "spring-mvc-jpa-mass-assignment"
            ? []
            : matchingJavaModelLines(lines, model.controls, 24)
          : matchingModelLines(lines, model.controls, 24);
    for (const sink of sinks) {
      const nodeHttpSink =
        model.id === "node-http-ssrf"
          ? nodeHttpUrlSink(lines, sink.line)
          : undefined;
      const nodeObjectSink =
        model.id === "node-http-object-authorization"
          ? nodeObjectAuthorizationSink(lines, sink.line)
          : undefined;
      const nodeCopilotSink =
        model.id === "node-copilot-system-prompt-injection"
          ? nodeCopilotPromptSink(lines, sink.line)
          : undefined;
      const nodePathSink =
        model.id === "node-http-path"
          ? nodeFilesystemPathSink(lines, sink.line)
          : undefined;
      const nodeMongooseSink =
        model.id === "node-http-mongoose-nosql"
          ? nodeMongooseNoSqlSink(lines, sink.line)
          : undefined;
      const nodeMongooseUpdate =
        model.id === "node-http-mongoose-update"
          ? nodeMongooseUpdateSink(lines, sink.line)
          : undefined;
      const nodeMongooseBulkWrite =
        model.id === "node-http-mongoose-bulk-write"
          ? nodeMongooseBulkWriteSink(lines, sink.line)
          : undefined;
      const pythonPathSink =
        model.id === "python-web-path"
          ? pythonFilesystemPathSink(lines, sink.line)
          : undefined;
      const dotnetObjectSink =
        model.id === "aspnet-http-object-authorization"
          ? dotnetObjectAuthorizationSink(lines, sink.line)
          : undefined;
      const javaObjectSink =
        model.id === "spring-http-object-authorization"
          ? javaObjectAuthorizationSink(lines, sink.line)
          : undefined;
      const javaJpaSink =
        model.id === "spring-mvc-jpa-mass-assignment"
          ? javaJpaPersistenceSink(lines, sink.line)
          : undefined;
      const javaJpaDomainType =
        javaJpaSink === undefined
          ? undefined
          : javaSpringDataRepositoryDomainType(
              files,
              path,
              lines,
              javaJpaSink.receiver,
            );
      if (model.id === "node-http-ssrf" && nodeHttpSink === undefined) {
        continue;
      }
      if (
        model.id === "node-http-object-authorization" &&
        nodeObjectSink === undefined
      ) {
        continue;
      }
      if (
        model.id === "node-copilot-system-prompt-injection" &&
        nodeCopilotSink === undefined
      ) {
        continue;
      }
      if (model.id === "node-http-path" && nodePathSink === undefined) {
        continue;
      }
      if (
        model.id === "node-http-mongoose-nosql" &&
        nodeMongooseSink === undefined
      ) {
        continue;
      }
      if (
        model.id === "node-http-mongoose-update" &&
        nodeMongooseUpdate === undefined
      ) {
        continue;
      }
      if (
        model.id === "node-http-mongoose-bulk-write" &&
        nodeMongooseBulkWrite === undefined
      ) {
        continue;
      }
      if (model.id === "python-web-path" && pythonPathSink === undefined) {
        continue;
      }
      if (
        model.id === "aspnet-http-object-authorization" &&
        (dotnetObjectSink === undefined ||
          !dotnetEfObjectLookupHasTypedReceiver(lines, dotnetObjectSink))
      ) {
        continue;
      }
      if (
        model.id === "spring-http-object-authorization" &&
        (javaObjectSink === undefined ||
          !javaSpringDataLookupHasTypedReceiver(
            files,
            path,
            lines,
            javaObjectSink,
          ))
      ) {
        continue;
      }
      if (
        model.id === "spring-mvc-jpa-mass-assignment" &&
        (javaJpaSink === undefined ||
          javaJpaDomainType === undefined ||
          !javaJpaEntityTypeExists(files, path, javaJpaDomainType))
      ) {
        continue;
      }
      if (
        nodeHttpSink?.axiosReceiver !== undefined &&
        javascriptAxiosReceiverShadowedInExport(
          lines,
          sink.line,
          nodeHttpSink.axiosReceiver,
        )
      ) {
        continue;
      }
      if (
        model.id === "aspnet-http-ssrf" &&
        !dotnetHttpClientSinkHasTypedReceiver(lines, sink.line)
      ) {
        continue;
      }
      if (
        model.id === "aspnet-http-path" &&
        !dotnetFilesystemSinkHasTypedReceiver(
          lines,
          sink.line,
          dotnetProjectProvidesSystemIo(files, path),
        )
      ) {
        continue;
      }
      if (
        model.id === "aspnet-http-template-injection" &&
        dotnetTemplateSourceArgument(lines, sink.line) === undefined
      ) {
        continue;
      }
      if (
        model.id === "spring-http-ssrf" &&
        !javaOutboundHttpSinkHasTypedReceiver(lines, sink.line)
      ) {
        continue;
      }
      if (
        model.id === "spring-http-path" &&
        !javaFilesystemSinkHasTypedReceiver(lines, sink.line)
      ) {
        continue;
      }
      const nodeCopilotResolution =
        model.id === "node-copilot-system-prompt-injection" &&
        nodeCopilotSink !== undefined
          ? nodeCopilotPromptSource(lines, nodeCopilotSink, model.sources)
          : undefined;
      const source =
        model.id === "node-http-mongoose-bulk-write" &&
        nodeMongooseBulkWrite !== undefined
          ? nodeMongooseBulkWrite.positions
              .map(({ expression }) =>
                modeledObjectLookupSource(
                  lines,
                  sources,
                  sink.line,
                  expression,
                  model.sources,
                ),
              )
              .find((candidate) => candidate !== undefined)
          : model.id === "node-http-mongoose-update" &&
              nodeMongooseUpdate !== undefined
            ? modeledObjectLookupSource(
                lines,
                sources,
                sink.line,
                nodeMongooseUpdate.updateExpression,
                model.sources,
              )
            : model.id === "node-http-mongoose-nosql" &&
                nodeMongooseSink !== undefined
              ? modeledObjectLookupSource(
                  lines,
                  sources,
                  sink.line,
                  nodeMongooseSink.filterExpression,
                  model.sources,
                )
              : model.id === "node-http-path" && nodePathSink !== undefined
                ? nodePathSink.expressions
                    .map((expression) =>
                      modeledObjectLookupSource(
                        lines,
                        sources,
                        sink.line,
                        expression,
                        model.sources,
                      ),
                    )
                    .find((candidate) => candidate !== undefined)
                : model.id === "python-web-path" && pythonPathSink !== undefined
                  ? pythonPathSink.expressions
                      .map((expression) =>
                        modeledPythonObjectSource(
                          lines,
                          sources,
                          sink.line,
                          expression,
                          model.sources,
                        ),
                      )
                      .find((candidate) => candidate !== undefined)
                  : model.id === "node-http-object-authorization" &&
                      nodeObjectSink !== undefined
                    ? modeledObjectLookupSource(
                        lines,
                        sources,
                        sink.line,
                        nodeObjectSink.argument,
                        model.sources,
                      )
                    : model.id === "node-http-ssrf" &&
                        nodeHttpSink?.urlExpression !== undefined
                      ? modeledCallSource(
                          lines,
                          sources,
                          sink.line,
                          nodeHttpSink.urlExpression,
                          model.sources,
                        )
                      : model.id === "node-copilot-system-prompt-injection"
                        ? nodeCopilotResolution?.source
                        : extension === ".java" &&
                            model.id === "spring-http-object-authorization" &&
                            javaObjectSink !== undefined
                          ? modeledSameFileJavaObjectSource(
                              lines,
                              sink.line,
                              javaObjectSink.argument,
                              model.sources,
                            )
                          : extension === ".java" &&
                              model.id === "spring-mvc-jpa-mass-assignment" &&
                              javaJpaSink !== undefined &&
                              javaJpaDomainType !== undefined
                            ? (() => {
                                const method = exportedJavaMethods(lines).find(
                                  (candidate) =>
                                    sink.line >= candidate.startLine &&
                                    sink.line <= candidate.endLine,
                                );
                                return method === undefined
                                  ? undefined
                                  : modeledJavaMassAssignmentSource(
                                      lines,
                                      method,
                                      sink.line,
                                      javaJpaSink.argument,
                                      javaJpaDomainType,
                                    );
                              })()
                            : extension === ".java" &&
                                (model.id === "spring-http-ssrf" ||
                                  model.id === "spring-http-path")
                              ? modeledSameFileJavaSource(
                                  lines,
                                  sink.line,
                                  model.id,
                                  model.sources,
                                )
                              : extension === ".cs" &&
                                  model.id === "aspnet-http-template-injection"
                                ? modeledSameFileDotnetTemplateSource(
                                    lines,
                                    sink.line,
                                    model.sources,
                                    files,
                                    path,
                                  )
                                : extension === ".cs" &&
                                    model.id ===
                                      "aspnet-http-object-authorization" &&
                                    dotnetObjectSink !== undefined
                                  ? modeledSameFileDotnetObjectSource(
                                      lines,
                                      sink.line,
                                      dotnetObjectSink.argument,
                                      model.sources,
                                      files,
                                      path,
                                    )
                                  : extension === ".cs" &&
                                      model.id.startsWith("aspnet-http-")
                                    ? modeledSameFileDotnetSource(
                                        lines,
                                        sink.line,
                                        model.sources,
                                        files,
                                        path,
                                      ) ??
                                      nearestModeledSource(
                                        matchedSources,
                                        sink.line,
                                      )
                                    : nearestModeledSource(sources, sink.line);
      if (source === undefined) continue;
      const sinkExpressionControls = PYTHON_EXTENSIONS.has(extension)
        ? model.controls
            .filter((control) =>
              control.expression.test(
                pythonCallExpression(lines, sink.line, lines.length),
              ),
            )
            .map((control) => ({ kind: control.kind, line: sink.line }))
        : [];
      const nearbyControls = [
        ...sinkExpressionControls,
        ...(model.id === "node-http-ssrf" && nodeHttpSink !== undefined
          ? nodeAxiosConfigurationControls(lines, nodeHttpSink, model.controls)
          : []),
        ...(model.id === "node-http-object-authorization" &&
        nodeObjectSink !== undefined
          ? nodeObjectAuthorizationControls(lines, nodeObjectSink, lines.length)
          : []),
        ...(model.id === "node-http-mongoose-nosql" &&
        nodeMongooseSink !== undefined
          ? nodeMongooseNoSqlControls(lines, nodeMongooseSink, sink.line)
          : []),
        ...(model.id === "node-http-mongoose-update" &&
        nodeMongooseUpdate !== undefined
          ? nodeMongooseUpdateControls(lines, nodeMongooseUpdate, sink.line)
          : []),
        ...(model.id === "node-http-mongoose-bulk-write" &&
        nodeMongooseBulkWrite !== undefined
          ? nodeMongooseBulkWriteControls(
              lines,
              nodeMongooseBulkWrite,
              sink.line,
            )
          : []),
        ...(model.id === "aspnet-http-object-authorization" &&
        dotnetObjectSink !== undefined
          ? dotnetObjectAuthorizationControls(
              lines,
              dotnetObjectSink,
              lines.length,
            )
          : []),
        ...(model.id === "spring-http-object-authorization" &&
        javaObjectSink !== undefined
          ? javaObjectAuthorizationControls(files, path, lines, javaObjectSink)
          : []),
        ...(model.id === "spring-mvc-jpa-mass-assignment" &&
        javaJpaSink !== undefined &&
        javaJpaDomainType !== undefined
          ? (() => {
              const method = exportedJavaMethods(lines).find(
                (candidate) =>
                  sink.line >= candidate.startLine &&
                  sink.line <= candidate.endLine,
              );
              const parameter = method?.parameters.find(
                (candidate) =>
                  candidate.name === javaJpaSink.argument.trim() &&
                  javaParameterSimpleType(candidate) === javaJpaDomainType,
              );
              return parameter === undefined
                ? []
                : javaSpringBindingControls(lines, parameter);
            })()
          : []),
        ...controls.filter(
          (control) =>
            control.line >= Math.min(source.line, sink.line) - 8 &&
            control.line <= Math.max(source.line, sink.line) + 8 &&
            nodeHttpGeneralControlApplies(nodeHttpSink, control.kind) &&
            filesystemPathControlApplies(model.id, control.kind, controls),
        ),
      ]
        .filter(
          (control, index, all) =>
            all.findIndex(
              (candidate) =>
                candidate.kind === control.kind &&
                candidate.line === control.line,
            ) === index,
        )
        .slice(0, 8);
      const sinkPattern = model.sinks.find(
        (pattern) => pattern.kind === sink.kind,
      );
      if (sinkPattern === undefined) continue;
      const effectiveSinkLine = nodeCopilotResolution?.input.line ?? sink.line;
      const effectiveSinkKind = nodeCopilotResolution?.input.kind ?? sink.kind;
      const startLine = Math.max(1, effectiveSinkLine - CONTEXT_LINES_BEFORE);
      const endLine = Math.min(
        lines.length,
        effectiveSinkLine + CONTEXT_LINES_AFTER,
      );
      const sourceStart = Math.max(1, source.line - 2);
      const sourceEnd = Math.min(lines.length, source.line + 2);
      records.push({
        path,
        line: effectiveSinkLine,
        categories: [
          `framework-dataflow:${model.id}`,
          `modeled-source:${source.kind}`,
          `modeled-sink:${effectiveSinkKind}`,
          ...nearbyControls.map(
            (control) => `candidate-control:${control.kind}`,
          ),
        ],
        priority: 116,
        startLine,
        endLine,
        excerpt: sourceExcerpt(lines, startLine, endLine),
        sourceExcerpt: sourceExcerpt(lines, sourceStart, sourceEnd),
        frameworkModel: {
          schemaVersion: "1.2",
          id: model.id,
          language: model.language,
          scope: "same-file",
          source: { kind: source.kind, path, line: source.line },
          sink: {
            kind: effectiveSinkKind,
            path,
            line: effectiveSinkLine,
            cweIds: sinkPattern.cweIds,
          },
          propagators: [],
          candidateControls: nearbyControls.map((control) => ({
            ...control,
            path,
          })),
        },
      });
    }
  }
  return records;
}

function nodeIpv6TransitionIncompleteGuardRecords(
  files: readonly SourceFileSnapshot[],
  records: readonly ResidualRiskRecord[],
): ResidualRiskRecord[] {
  const filesByPath = new Map(files.map((file) => [file.path, file]));
  const emitted = new Set<string>();
  const specialized: ResidualRiskRecord[] = [];
  for (const record of records) {
    const framework = record.frameworkModel;
    if (framework?.id !== "node-http-ssrf") continue;
    const sinkFile = filesByPath.get(framework.sink.path);
    if (
      sinkFile === undefined ||
      !JAVASCRIPT_EXTENSIONS.has(sinkFile.extension) ||
      javascriptTestOrExamplePath(sinkFile.path)
    ) {
      continue;
    }
    const sink =
      nodeNativeHttpUrlArgument(sinkFile.lines, framework.sink.line) ??
      nodeHttpUrlSink(sinkFile.lines, framework.sink.line);
    if (sink?.urlExpression === undefined) continue;
    const wrapper = exportedJavascriptFunctions(sinkFile.lines).find(
      (candidate) =>
        framework.sink.line >= candidate.startLine &&
        framework.sink.line <= candidate.endLine,
    );
    if (wrapper === undefined) continue;
    const guard = nodeIpv4OnlyHostGuard(
      sinkFile.lines,
      wrapper,
      framework.sink.line,
      sink.urlExpression,
    );
    if (guard === undefined) continue;
    const key = `${framework.source.path}\0${framework.source.line}\0${framework.sink.path}\0${framework.sink.line}`;
    if (emitted.has(key)) continue;
    emitted.add(key);
    specialized.push({
      ...record,
      categories: [
        "framework-dataflow:node-ssrf-ipv6-transition-incomplete-guard",
        `modeled-source:${framework.source.kind}`,
        `modeled-sink:${framework.sink.kind}`,
        "broken-control:ipv4-only-private-address-denylist",
      ],
      priority: Math.max(record.priority, 120),
      frameworkModel: {
        ...framework,
        id: "node-ssrf-ipv6-transition-incomplete-guard",
        sink: { ...framework.sink, cweIds: ["CWE-918", "CWE-1389"] },
        candidateControls: [
          ...framework.candidateControls.filter(
            (control) =>
              control.kind !== "network-address-validation-or-pinning",
          ),
          {
            kind: "incomplete-ipv6-transition-address-guard",
            path: sinkFile.path,
            line: guard.line,
          },
        ].filter(
          (control, index, all) =>
            all.findIndex(
              (candidate) =>
                candidate.kind === control.kind &&
                candidate.path === control.path &&
                candidate.line === control.line,
            ) === index,
        ),
      },
    });
  }
  return specialized;
}

function javascriptTestOrExamplePath(path: string): boolean {
  return (
    /(?:^|\/)(?:__tests__|examples?|test|tests|tests-ts)(?:\/|$)/iu.test(
      path,
    ) || /\.(?:spec|test)\.[^./]+$/iu.test(path)
  );
}

function javaFileGetNamePathBoundaryRecords(
  files: readonly SourceFileSnapshot[],
  records: readonly ResidualRiskRecord[],
): ResidualRiskRecord[] {
  const filesByPath = new Map(files.map((file) => [file.path, file]));
  const projectGraph = javaBasenameProjectGraph(files);
  const packageTypes = javaPackageTypeIndex(files);
  const helperSummaries = javaFileBasenameHelperSummaries(
    files,
    packageTypes,
    projectGraph,
  );
  const emitted = new Set<string>();
  const specialized: ResidualRiskRecord[] = [];
  for (const record of records) {
    const framework = record.frameworkModel;
    if (framework?.id !== "spring-http-path") continue;
    const sinkFile = filesByPath.get(framework.sink.path);
    if (
      sinkFile?.extension !== ".java" ||
      javaTestOrExamplePath(sinkFile.path)
    ) {
      continue;
    }
    const boundary = javaFileGetNamePathBoundary(
      sinkFile,
      files,
      framework.sink.line,
      new Set(
        framework.propagators
          .filter(
            (propagator) =>
              propagator.kind === "wrapper-parameter" &&
              propagator.path === sinkFile.path,
          )
          .flatMap((propagator) =>
            propagator.symbol === undefined ? [] : [propagator.symbol],
          ),
      ),
      javaSamePackageTopLevelTypes(packageTypes, files, sinkFile, projectGraph),
      helperSummaries,
      projectGraph,
    );
    if (boundary === undefined) continue;
    const key = `${framework.source.path}\0${framework.source.line}\0${framework.sink.path}\0${framework.sink.line}`;
    if (emitted.has(key)) continue;
    emitted.add(key);
    specialized.push({
      ...record,
      categories: [
        "framework-dataflow:java-file-getname-path-boundary",
        `modeled-source:${framework.source.kind}`,
        `modeled-sink:${framework.sink.kind}`,
        "broken-control:java-io-file-basename-reduction",
        ...(boundary.parentRejectionLine === undefined
          ? []
          : ["candidate-control:parent-path-component-rejection"]),
      ],
      priority: Math.max(record.priority, 121),
      frameworkModel: {
        ...framework,
        id: "java-file-getname-path-boundary",
        candidateControls: [
          ...framework.candidateControls,
          {
            kind: "incomplete-java-io-file-getname-reduction",
            path: boundary.reductionPath,
            line: boundary.reductionLine,
          },
          ...(boundary.parentRejectionLine === undefined
            ? []
            : [
                {
                  kind: "parent-path-component-rejection",
                  path: sinkFile.path,
                  line: boundary.parentRejectionLine,
                },
              ]),
        ].filter(
          (control, index, all) =>
            all.findIndex(
              (candidate) =>
                candidate.kind === control.kind &&
                candidate.path === control.path &&
                candidate.line === control.line,
            ) === index,
        ),
      },
    });
  }
  return specialized;
}

function javaTestOrExamplePath(path: string): boolean {
  return (
    /(?:^|\/)(?:examples|test|tests)(?:\/|$)/iu.test(path) ||
    /(?:^|\/)src\/test(?:\/|$)/iu.test(path) ||
    /(?:Test|Tests)\.java$/u.test(path)
  );
}

function javaLexicalBlockContext(structuralLines: readonly string[]): {
  paths: string[];
  switchAncestors: boolean[];
} {
  const paths: string[] = [];
  const switchAncestors: boolean[] = [];
  const stack: Array<{ id: number; switchBlock: boolean }> = [];
  let nextBlock = 1;
  let word = "";
  let awaitingSwitchParenthesis = false;
  let switchParenthesisDepth: number | undefined;
  for (const line of structuralLines) {
    paths.push(stack.map(({ id }) => id).join("."));
    switchAncestors.push(stack.some(({ switchBlock }) => switchBlock));
    for (const character of line) {
      if (/[A-Za-z0-9_$]/u.test(character)) {
        word += character;
        continue;
      }
      if (word === "switch" && switchParenthesisDepth === undefined) {
        awaitingSwitchParenthesis = true;
      }
      word = "";
      if (character === "(") {
        if (awaitingSwitchParenthesis) {
          switchParenthesisDepth = 1;
          awaitingSwitchParenthesis = false;
        } else if (switchParenthesisDepth !== undefined) {
          switchParenthesisDepth += 1;
        }
      } else if (character === ")" && switchParenthesisDepth !== undefined) {
        switchParenthesisDepth = Math.max(0, switchParenthesisDepth - 1);
      }
      if (character === "{") {
        const switchBlock = switchParenthesisDepth !== undefined;
        stack.push({
          id: nextBlock,
          switchBlock,
        });
        nextBlock += 1;
        if (switchParenthesisDepth === 0) {
          switchParenthesisDepth = undefined;
        }
      } else if (character === "}") {
        stack.pop();
      } else if (character === ";" && switchParenthesisDepth === undefined) {
        awaitingSwitchParenthesis = false;
      }
    }
    if (word === "switch" && switchParenthesisDepth === undefined) {
      awaitingSwitchParenthesis = true;
    }
    word = "";
  }
  return { paths, switchAncestors };
}

function matchingStructuralBrace(value: string, open: number): number {
  if (open < 0 || value[open] !== "{") return -1;
  let depth = 0;
  for (let index = open; index < value.length; index += 1) {
    if (value[index] === "{") depth += 1;
    else if (value[index] === "}") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function stripBalancedOuterParentheses(value: string): string {
  let result = value.trim();
  while (
    result.startsWith("(") &&
    matchingCallParenthesis(result, 0) === result.length - 1
  ) {
    result = result.slice(1, -1).trim();
  }
  return result;
}

function javaSimpleBranchCompletesAbruptly(
  branch: string,
  braced: boolean,
): boolean {
  const structural = cFamilyStructuralLines(branch.split(/\r?\n/u))
    .join("\n")
    .trim();
  if (!braced) {
    return /^(?:return\b[^;]*|throw\b[^;]+)\s*;/u.test(structural);
  }
  if (
    structural === "" ||
    /[{}]|->|\b(?:if|else|switch|try|catch|finally|for|while|do|synchronized)\b/u.test(
      structural,
    )
  ) {
    return false;
  }
  const statements = structural
    .split(";")
    .map((statement) => statement.trim())
    .filter((statement) => statement !== "");
  const finalStatement = statements.at(-1) ?? "";
  return /^(?:return\b|throw\b)/u.test(finalStatement);
}

function javaDominatingEqualityRejection(
  lines: readonly string[],
  structuralLines: readonly string[],
  startLine: number,
  sinkLine: number,
  identifiers: ReadonlySet<string>,
  rejectedValuePattern: string,
): number | undefined {
  const blockContext = javaLexicalBlockContext(structuralLines);
  const sinkIndex = sinkLine - 1;
  const identifierPattern = [...identifiers]
    .map((identifier) => escapeRegularExpression(identifier))
    .join("|");
  if (identifierPattern === "") return undefined;
  const equality = new RegExp(
    String.raw`^(?:(?:${identifierPattern})\s*\.\s*equals\s*\(\s*${rejectedValuePattern}\s*\)|${rejectedValuePattern}\s*\.\s*equals\s*\(\s*(?:${identifierPattern})\s*\))$`,
    "u",
  );

  for (
    let index = startLine;
    index < Math.min(sinkIndex, structuralLines.length);
    index += 1
  ) {
    const firstLine = structuralLines[index] ?? "";
    const ifMatch = /\bif\s*\(/u.exec(firstLine);
    if (
      ifMatch === null ||
      firstLine.slice(0, ifMatch.index).trim() !== "" ||
      blockContext.paths[index] !== blockContext.paths[sinkIndex] ||
      blockContext.switchAncestors[index] === true
    ) {
      continue;
    }
    const endIndex = Math.min(sinkIndex, index + 16);
    const rawWindow = lines.slice(index, endIndex).join("\n");
    const structuralWindow = structuralLines.slice(index, endIndex).join("\n");
    const structuralIf = /\bif\s*\(/u.exec(structuralWindow);
    if (structuralIf === null) continue;
    const open = structuralWindow.indexOf("(", structuralIf.index);
    const close = matchingCallParenthesis(structuralWindow, open);
    if (open < 0 || close < 0) continue;
    const condition = stripBalancedOuterParentheses(
      rawWindow.slice(open + 1, close),
    );
    if (!equality.test(condition)) continue;

    let consequent = close + 1;
    while (/\s/u.test(structuralWindow[consequent] ?? "")) consequent += 1;
    const braced = structuralWindow[consequent] === "{";
    if (braced) {
      const endBrace = matchingStructuralBrace(structuralWindow, consequent);
      if (endBrace < 0) continue;
      if (
        javaSimpleBranchCompletesAbruptly(
          rawWindow.slice(consequent + 1, endBrace),
          true,
        )
      ) {
        return index + 1;
      }
      continue;
    }
    const statementEnd = structuralWindow.indexOf(";", consequent);
    if (
      statementEnd >= 0 &&
      javaSimpleBranchCompletesAbruptly(
        rawWindow.slice(consequent, statementEnd + 1),
        false,
      )
    ) {
      return index + 1;
    }
  }
  return undefined;
}

function javaExpressionIsExactIdentifier(
  expression: string,
  identifiers: Iterable<string>,
): boolean {
  return [...identifiers].some((identifier) =>
    new RegExp(
      String.raw`^\s*\(?\s*${escapeRegularExpression(identifier)}\s*\)?\s*$`,
      "u",
    ).test(expression),
  );
}

function javaDeclaredParameterType(parameter: {
  name: string;
  declaration: string;
}): string {
  return parameter.declaration
    .replace(
      new RegExp(
        `${escapeRegularExpression(parameter.name)}\\s*(?:\\[\\s*\\])?\\s*$`,
        "u",
      ),
      "",
    )
    .replace(/@[A-Za-z_$][\w$.]*(?:\([^)]*\))?/gu, " ")
    .replace(/\b(?:final|volatile|transient)\b/gu, " ")
    .replace(/\s*\.\s*/gu, ".")
    .replace(/\s+/gu, " ")
    .trim();
}

function javaStraightLineReturn(
  lines: readonly string[],
  method: JavaMethodDeclaration,
):
  | {
      beforeReturn: string;
      expression: string;
      returnLine: number;
      bodyLineOffset: number;
    }
  | undefined {
  const methodLines = lines.slice(method.startLine - 1, method.endLine);
  const rawMethod = methodLines.join("\n");
  const structuralMethod = cFamilyStructuralLines(methodLines).join("\n");
  const open = structuralMethod.indexOf("{");
  const close = matchingStructuralBrace(structuralMethod, open);
  if (open < 0 || close < 0) return undefined;
  const structuralBody = structuralMethod.slice(open + 1, close);
  if (
    /[{}]|->|\b(?:if|else|switch|try|catch|finally|for|while|do|synchronized|throw|break|continue|yield)\b/u.test(
      structuralBody,
    )
  ) {
    return undefined;
  }
  const returns = [...structuralBody.matchAll(/\breturn\b([\s\S]*?);/gu)];
  if (returns.length !== 1 || returns[0]?.index === undefined) {
    return undefined;
  }
  const returnMatch = returns[0];
  const returnEnd = returnMatch.index + returnMatch[0].length;
  if (structuralBody.slice(returnEnd).trim() !== "") return undefined;
  const rawBody = rawMethod.slice(open + 1, close);
  const expressionStart =
    returnMatch.index + returnMatch[0].indexOf("return") + "return".length;
  const expressionEnd = returnEnd - 1;
  const bodyLineOffset = rawMethod.slice(0, open + 1).split("\n").length - 1;
  return {
    beforeReturn: rawBody.slice(0, returnMatch.index),
    expression: rawBody.slice(expressionStart, expressionEnd),
    returnLine:
      method.startLine +
      bodyLineOffset +
      rawBody.slice(0, returnMatch.index).split("\n").length -
      1,
    bodyLineOffset,
  };
}

function javaBasenameHelperSummaries(
  lines: readonly string[],
  source: {
    path: string;
    packageName?: string;
    projectRoot: string;
  },
  returnTypePattern: string,
  inputTypes: ReadonlyArray<{
    kind: JavaBasenameHelperSummary["inputKind"];
    pattern: string;
  }>,
  constructions: (
    expression: string,
  ) => Array<{ argument: string; reduced: boolean }>,
  reductionMethod: "getFileName" | "getName",
): JavaBasenameHelperSummary[] {
  const methods = javaMethodDeclarations(lines);
  const summaries: JavaBasenameHelperSummary[] = [];
  for (const method of methods) {
    if (
      methods.filter((candidate) => candidate.symbol === method.symbol)
        .length !== 1 ||
      !new RegExp(String.raw`^(?:${returnTypePattern})$`, "u").test(
        method.returnType,
      )
    ) {
      continue;
    }
    const body = javaStraightLineReturn(lines, method);
    if (body === undefined) continue;
    for (const [parameterIndex, parameter] of method.parameters.entries()) {
      const parameterType = javaDeclaredParameterType(parameter);
      const inputKind = inputTypes.find(({ pattern }) =>
        new RegExp(String.raw`^(?:${pattern})$`, "u").test(parameterType),
      )?.kind;
      if (inputKind === undefined) continue;
      const aliases = new Set([parameter.name]);
      const receivers = new Set<string>(
        inputKind === "path" || inputKind === "file" ? [parameter.name] : [],
      );
      const reductions = new Map<string, number>();
      const assignment = /\b([A-Za-z_$][\w$]*)\s*=(?!=)\s*([^;]+);/gu;
      for (const match of body.beforeReturn.matchAll(assignment)) {
        const target = match[1];
        const value = match[2];
        if (target === undefined || value === undefined) continue;
        const line =
          method.startLine +
          body.bodyLineOffset +
          body.beforeReturn.slice(0, match.index ?? 0).split("\n").length -
          1;
        const exactAlias = javaExpressionIsExactIdentifier(value, aliases);
        const exactReceiverAlias = javaExpressionIsExactIdentifier(
          value,
          receivers,
        );
        const factoryResults = constructions(value);
        const directConstruction = factoryResults.some(({ argument }) =>
          javaExpressionIsExactIdentifier(argument, aliases),
        );
        const directReduction = factoryResults.some(
          ({ argument, reduced }) =>
            reduced && javaExpressionIsExactIdentifier(argument, aliases),
        );
        const receiverReduction = [...receivers].some((identifier) =>
          new RegExp(
            String.raw`^\s*${escapeRegularExpression(identifier)}\s*\.\s*${reductionMethod}\s*\(\s*\)\s*$`,
            "u",
          ).test(value),
        );
        const inheritedOrigin = [...reductions].find(([identifier]) =>
          javaExpressionIsExactIdentifier(value, [identifier]),
        )?.[1];

        if (exactAlias) aliases.add(target);
        else aliases.delete(target);
        if (directConstruction || exactReceiverAlias) receivers.add(target);
        else receivers.delete(target);
        if (directReduction || receiverReduction) reductions.set(target, line);
        else if (inheritedOrigin !== undefined)
          reductions.set(target, inheritedOrigin);
        else reductions.delete(target);
      }

      const returnedFactories = constructions(body.expression);
      const directReturnReduction = returnedFactories.some(
        ({ argument, reduced }) =>
          reduced && javaExpressionIsExactIdentifier(argument, aliases),
      );
      const receiverReturnReduction = [...receivers].some((identifier) =>
        new RegExp(
          String.raw`^\s*${escapeRegularExpression(identifier)}\s*\.\s*${reductionMethod}\s*\(\s*\)\s*$`,
          "u",
        ).test(body.expression),
      );
      const returnedOrigin = [...reductions].find(([identifier]) =>
        javaExpressionIsExactIdentifier(body.expression, [identifier]),
      )?.[1];
      const reductionLine =
        directReturnReduction || receiverReturnReduction
          ? body.returnLine
          : returnedOrigin;
      if (reductionLine === undefined) continue;
      summaries.push({
        ownerType: method.ownerType,
        access: method.access,
        isStatic: method.isStatic,
        symbol: method.symbol,
        parameterIndex,
        parameterCount: method.parameters.length,
        inputKind,
        reductionLine,
        sourcePath: source.path,
        ...(source.packageName === undefined
          ? {}
          : { packageName: source.packageName }),
        projectRoot: source.projectRoot,
      });
    }
  }
  return summaries;
}

function javaExactBasenameHelperCall(
  expression: string,
  ownerType: string,
  summaries: readonly JavaBasenameHelperSummary[],
  stringInputs: ReadonlySet<string>,
  pathInputs: ReadonlySet<string>,
  fileInputs: ReadonlySet<string>,
): JavaBasenameHelperSummary | undefined {
  const structural = cFamilyStructuralLines(expression.split(/\r?\n/u)).join(
    "\n",
  );
  const matches = summaries.filter((summary) => {
    const call = new RegExp(
      String.raw`^\s*(?:(?:this|${escapeRegularExpression(ownerType)})\s*\.\s*)?${escapeRegularExpression(summary.symbol)}\s*\(`,
      "u",
    ).exec(structural);
    if (call === null) return false;
    const open = structural.indexOf("(", call.index);
    const close = matchingCallParenthesis(structural, open);
    if (open < 0 || close < 0 || structural.slice(close + 1).trim() !== "") {
      return false;
    }
    const arguments_ = splitJavascriptArguments(
      expression.slice(open + 1, close),
    );
    if (arguments_.length !== summary.parameterCount) return false;
    const inputs =
      summary.inputKind === "path"
        ? pathInputs
        : summary.inputKind === "file"
          ? fileInputs
          : stringInputs;
    return javaExpressionIsExactIdentifier(
      arguments_[summary.parameterIndex] ?? "",
      inputs,
    );
  });
  return matches.length === 1 ? matches[0] : undefined;
}

function javaSingleTypeImports(lines: readonly string[]): string[] {
  const structural = cFamilyStructuralLines(lines)
    .join("\n")
    .replace(/\s*\.\s*/gu, ".");
  return [
    ...structural.matchAll(
      /^\s*import\s+(?!static\b)([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\s*;/gmu,
    ),
  ].flatMap((match) =>
    match[1] === undefined || match[1].endsWith(".*") ? [] : [match[1]],
  );
}

function javaExternalHelperOwnerIsUnique(
  files: readonly SourceFileSnapshot[],
  summary: JavaBasenameHelperSummary,
  sinkProjectRoot: string,
  projectGraph: JavaBasenameProjectGraph,
): boolean {
  const visibleRoots = javaBasenameVisibleProjectRoots(
    projectGraph,
    sinkProjectRoot,
  );
  return (
    files.filter(
      (file) =>
        file.extension === ".java" &&
        !javaTestOrExamplePath(file.path) &&
        visibleRoots.has(javaBasenameProjectRootForPath(files, file.path)) &&
        javaPackageName(file.lines) === summary.packageName &&
        javaTopLevelTypeNames(file.lines).has(summary.ownerType),
    ).length === 1
  );
}

function javaExactExternalBasenameHelperCall(
  expression: string,
  sinkFile: SourceFileSnapshot,
  files: readonly SourceFileSnapshot[],
  projectGraph: JavaBasenameProjectGraph,
  summaries: readonly JavaBasenameHelperSummary[],
  stringInputs: ReadonlySet<string>,
  pathInputs: ReadonlySet<string>,
  fileInputs: ReadonlySet<string>,
): JavaBasenameHelperSummary | undefined {
  const sinkPackage = javaPackageName(sinkFile.lines);
  const sinkProjectRoot = javaBasenameProjectRootForPath(files, sinkFile.path);
  const imports = javaSingleTypeImports(sinkFile.lines);
  const structural = cFamilyStructuralLines(expression.split(/\r?\n/u)).join(
    "\n",
  );
  const matches = summaries.filter((summary) => {
    if (
      summary.sourcePath === sinkFile.path ||
      !javaBasenameProjectCanRead(
        projectGraph,
        sinkProjectRoot,
        summary.projectRoot,
        sinkFile.path,
        summary.sourcePath,
      ) ||
      !summary.isStatic ||
      summary.access === "private" ||
      !javaExternalHelperOwnerIsUnique(
        files,
        summary,
        sinkProjectRoot,
        projectGraph,
      )
    ) {
      return false;
    }
    const samePackage = summary.packageName === sinkPackage;
    if (!samePackage) {
      if (summary.access !== "public") return false;
      const helperFile = files.find((file) => file.path === summary.sourcePath);
      if (
        helperFile === undefined ||
        !new RegExp(
          String.raw`\bpublic\s+(?:final\s+|abstract\s+)?(?:class|record)\s+${escapeRegularExpression(summary.ownerType)}\b`,
          "u",
        ).test(cFamilyStructuralLines(helperFile.lines).join("\n"))
      ) {
        return false;
      }
    }
    const qualifiedOwner =
      summary.packageName === undefined
        ? summary.ownerType
        : `${summary.packageName}.${summary.ownerType}`;
    const sameSimpleImports = imports.filter(
      (candidate) => candidate.split(".").at(-1) === summary.ownerType,
    );
    const simpleOwnerEligible = samePackage
      ? sameSimpleImports.every((candidate) => candidate === qualifiedOwner)
      : sameSimpleImports.length === 1 &&
        sameSimpleImports[0] === qualifiedOwner;
    const ownerPatterns = [
      ...(summary.packageName === undefined
        ? []
        : [
            qualifiedOwner
              .split(".")
              .map(escapeRegularExpression)
              .join(String.raw`\s*\.\s*`),
          ]),
      ...(simpleOwnerEligible
        ? [escapeRegularExpression(summary.ownerType)]
        : []),
    ];
    if (ownerPatterns.length === 0) return false;
    const call = new RegExp(
      String.raw`^\s*(?:${ownerPatterns.join("|")})\s*\.\s*${escapeRegularExpression(summary.symbol)}\s*\(`,
      "u",
    ).exec(structural);
    if (call === null) return false;
    const open = structural.indexOf("(", call.index);
    const close = matchingCallParenthesis(structural, open);
    if (open < 0 || close < 0 || structural.slice(close + 1).trim() !== "") {
      return false;
    }
    const arguments_ = splitJavascriptArguments(
      expression.slice(open + 1, close),
    );
    if (arguments_.length !== summary.parameterCount) return false;
    const inputs =
      summary.inputKind === "path"
        ? pathInputs
        : summary.inputKind === "file"
          ? fileInputs
          : stringInputs;
    return javaExpressionIsExactIdentifier(
      arguments_[summary.parameterIndex] ?? "",
      inputs,
    );
  });
  return matches.length === 1 ? matches[0] : undefined;
}

function javaFileGetNamePathBoundary(
  sinkFile: SourceFileSnapshot,
  files: readonly SourceFileSnapshot[],
  sinkLine: number,
  provenSinkParameters: ReadonlySet<string>,
  samePackageTopLevelTypes: ReadonlySet<string>,
  helperSummaries: readonly JavaBasenameHelperSummary[],
  projectGraph: JavaBasenameProjectGraph,
): JavaBasenameBoundary | undefined {
  const lines = sinkFile.lines;
  const method = exportedJavaMethods(lines).find(
    (candidate) =>
      sinkLine >= candidate.startLine && sinkLine <= candidate.endLine,
  );
  if (method === undefined) return undefined;
  const structuralLines = cFamilyStructuralLines(lines);
  const structuralText = structuralLines.join("\n");
  const fileSingleImported = /^\s*import\s+java\.io\.File\s*;/mu.test(
    structuralText,
  );
  const ioWildcardImported = /^\s*import\s+java\.io\.\*\s*;/mu.test(
    structuralText,
  );
  const fileShadowed = /\b(?:class|enum|interface|record)\s+File\b/u.test(
    structuralText,
  );
  const simpleFileIsOfficial =
    !fileShadowed &&
    (fileSingleImported ||
      (ioWildcardImported && !samePackageTopLevelTypes.has("File")));
  const fileType = simpleFileIsOfficial
    ? String.raw`(?:(?:java\s*\.\s*io\s*\.\s*)?File)`
    : String.raw`(?:java\s*\.\s*io\s*\.\s*File)`;
  const sinkExpression = javaCallExpression(lines, sinkLine, method.endLine);
  const bodyLines = structuralLines.slice(method.startLine - 1, sinkLine - 1);
  const body = bodyLines.join("\n");
  const eligibleParameters =
    provenSinkParameters.size === 0
      ? method.parameters
      : method.parameters.filter((parameter) =>
          provenSinkParameters.has(parameter.name),
        );
  if (eligibleParameters.length === 0) return undefined;
  const tainted = new Set(
    eligibleParameters.map((parameter) => parameter.name),
  );
  const fileReceivers = new Set<string>();
  const pathReceivers = new Set<string>();
  const basenameOrigins = new Map<string, JavaBasenameOrigin>();
  const referencesAny = (
    expression: string,
    identifiers: Iterable<string>,
  ): boolean =>
    [...identifiers].some((identifier) =>
      cFamilyLineReferencesIdentifier(expression, identifier),
    );
  const fileConstructions = (
    expression: string,
  ): Array<{ argument: string; reduced: boolean }> => {
    const starts = expression.matchAll(
      new RegExp(String.raw`\bnew\s+${fileType}\s*\(`, "gu"),
    );
    return [...starts].flatMap((match) => {
      if (match.index === undefined) return [];
      const relativeOpen = match[0].lastIndexOf("(");
      const open = match.index + relativeOpen;
      const close = matchingCallParenthesis(expression, open);
      if (relativeOpen < 0 || close < 0) return [];
      return [
        {
          argument: expression.slice(open + 1, close),
          reduced: /^\s*\.\s*getName\s*\(\s*\)/u.test(
            expression.slice(close + 1),
          ),
        },
      ];
    });
  };
  const localHelperSummaries = helperSummaries.filter(
    (summary) => summary.sourcePath === sinkFile.path,
  );
  const assignment = /\b([A-Za-z_$][\w$]*)\s*=(?!=)\s*([^;]+);/gu;
  for (const match of body.matchAll(assignment)) {
    const target = match[1];
    const value = match[2];
    if (target === undefined || value === undefined) continue;
    const line =
      method.startLine + body.slice(0, match.index ?? 0).split("\n").length - 1;
    const derivesFromTaint = referencesAny(value, tainted);
    const priorFileReceiver = [...fileReceivers].find((identifier) =>
      cFamilyLineReferencesIdentifier(value, identifier),
    );
    const constructions = fileConstructions(value);
    const localHelperSummary = javaExactBasenameHelperCall(
      value,
      method.ownerType,
      localHelperSummaries,
      tainted,
      pathReceivers,
      fileReceivers,
    );
    const helperSummary =
      localHelperSummary ??
      javaExactExternalBasenameHelperCall(
        value,
        sinkFile,
        files,
        projectGraph,
        helperSummaries,
        tainted,
        pathReceivers,
        fileReceivers,
      );
    const directFileConstruction = constructions.some(({ argument }) =>
      referencesAny(argument, tainted),
    );
    const directReduction = constructions.some(
      ({ argument, reduced }) => reduced && referencesAny(argument, tainted),
    );
    const receiverReduction = [...fileReceivers].some((identifier) =>
      new RegExp(
        String.raw`\b${escapeRegularExpression(identifier)}\s*\.\s*getName\s*\(\s*\)`,
        "u",
      ).test(value),
    );
    const inheritedOrigin = [...basenameOrigins].find(([identifier]) =>
      cFamilyLineReferencesIdentifier(value, identifier),
    )?.[1];

    if (derivesFromTaint) tainted.add(target);
    else tainted.delete(target);

    if (
      (directFileConstruction && derivesFromTaint) ||
      priorFileReceiver !== undefined
    ) {
      fileReceivers.add(target);
    } else {
      fileReceivers.delete(target);
    }

    if (helperSummary !== undefined) {
      basenameOrigins.set(target, {
        evidenceLine: helperSummary.reductionLine,
        evidencePath: helperSummary.sourcePath,
        guardStartLine: line,
      });
    } else if (directReduction || receiverReduction) {
      basenameOrigins.set(target, {
        evidenceLine: line,
        evidencePath: sinkFile.path,
        guardStartLine: line,
      });
    } else if (inheritedOrigin !== undefined) {
      basenameOrigins.set(target, inheritedOrigin);
    } else {
      basenameOrigins.delete(target);
    }
  }

  const directSinkReduction = fileConstructions(sinkExpression).some(
    ({ argument, reduced }) => reduced && referencesAny(argument, tainted),
  );
  if (directSinkReduction) {
    return {
      reductionLine: sinkLine,
      reductionPath: sinkFile.path,
    };
  }
  const reachingBasenames = [...basenameOrigins].filter(([identifier]) =>
    cFamilyLineReferencesIdentifier(sinkExpression, identifier),
  );
  if (reachingBasenames.length === 0) return undefined;
  const selectedOrigin = reachingBasenames
    .map(([, origin]) => origin)
    .sort(
      (left, right) =>
        left.evidencePath.localeCompare(right.evidencePath) ||
        left.evidenceLine - right.evidenceLine ||
        left.guardStartLine - right.guardStartLine,
    )[0]!;
  const originKey = (origin: JavaBasenameOrigin): string =>
    `${origin.evidencePath}\0${origin.evidenceLine}\0${origin.guardStartLine}`;
  const selectedOriginKey = originKey(selectedOrigin);
  const basenameIdentifiers = new Set(
    [...basenameOrigins]
      .filter(([, origin]) => originKey(origin) === selectedOriginKey)
      .map(([identifier]) => identifier),
  );
  const parentRejectionLine = javaDominatingEqualityRejection(
    lines,
    structuralLines,
    selectedOrigin.guardStartLine,
    sinkLine,
    basenameIdentifiers,
    String.raw`"\.\."`,
  );
  return parentRejectionLine === undefined
    ? {
        reductionLine: selectedOrigin.evidenceLine,
        reductionPath: selectedOrigin.evidencePath,
      }
    : {
        reductionLine: selectedOrigin.evidenceLine,
        reductionPath: selectedOrigin.evidencePath,
        parentRejectionLine,
      };
}

function javaBraceSurface(
  lines: readonly string[],
  maximumDepth: number,
): string {
  const structural = cFamilyStructuralLines(lines).join("\n");
  let depth = 0;
  let surface = "";
  for (const character of structural) {
    if (character === "{") {
      if (depth <= maximumDepth) surface += character;
      depth += 1;
      continue;
    }
    if (character === "}") {
      depth = Math.max(0, depth - 1);
      if (depth <= maximumDepth) surface += character;
      continue;
    }
    if (depth <= maximumDepth) {
      surface += character;
    } else if (character === "\n") {
      surface += "\n";
    }
  }
  return surface;
}

function javaPackageName(lines: readonly string[]): string | undefined {
  const structural = cFamilyStructuralLines(lines).join("\n");
  const declaration =
    /^\s*package\s+([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*;/mu.exec(
      structural,
    )?.[1];
  return declaration?.replace(/\s+/gu, "");
}

function javaTopLevelTypeNames(lines: readonly string[]): Set<string> {
  const surface = javaBraceSurface(lines, 0);
  return new Set(
    [
      ...surface.matchAll(
        /\b(?:class|enum|interface|record)\s+([A-Za-z_$][\w$]*)\b/gu,
      ),
    ].flatMap((match) => (match[1] === undefined ? [] : [match[1]])),
  );
}

function javaPackageTypeIndex(
  files: readonly SourceFileSnapshot[],
): ReadonlyMap<string, ReadonlySet<string>> {
  const projectRoots = files
    .filter((file) => javaProjectBoundaryFile(file.path))
    .map((file) => posix.dirname(file.path))
    .sort((left, right) => right.length - left.length);
  const mutable = new Map<string, Set<string>>();
  for (const file of files) {
    if (file.extension !== ".java" || javaTestOrExamplePath(file.path)) {
      continue;
    }
    const projectRoot =
      projectRoots.find((candidate) =>
        pathWithinDirectory(file.path, candidate),
      ) ?? ".";
    const key = `${projectRoot}\0${javaPackageName(file.lines) ?? "<unnamed>"}`;
    const types = mutable.get(key) ?? new Set<string>();
    for (const name of javaTopLevelTypeNames(file.lines)) types.add(name);
    mutable.set(key, types);
  }
  return mutable;
}

function javaSamePackageTopLevelTypes(
  index: ReadonlyMap<string, ReadonlySet<string>>,
  files: readonly SourceFileSnapshot[],
  sinkFile: SourceFileSnapshot,
  projectGraph: JavaBasenameProjectGraph,
): ReadonlySet<string> {
  const projectRoot = javaBasenameProjectRootForPath(files, sinkFile.path);
  const packageName = javaPackageName(sinkFile.lines) ?? "<unnamed>";
  const types = new Set<string>();
  for (const visibleRoot of javaBasenameVisibleProjectRoots(
    projectGraph,
    projectRoot,
  )) {
    const key = `${visibleRoot}\0${packageName}`;
    for (const type of index.get(key) ?? []) types.add(type);
  }
  return types;
}

function javaFileBasenameHelperSummaries(
  files: readonly SourceFileSnapshot[],
  packageTypes: ReadonlyMap<string, ReadonlySet<string>>,
  projectGraph: JavaBasenameProjectGraph,
): JavaBasenameHelperSummary[] {
  return files.flatMap((file) => {
    if (file.extension !== ".java" || javaTestOrExamplePath(file.path)) {
      return [];
    }
    const structuralText = cFamilyStructuralLines(file.lines).join("\n");
    const samePackageTypes = javaSamePackageTopLevelTypes(
      packageTypes,
      files,
      file,
      projectGraph,
    );
    const fileSingleImported = /^\s*import\s+java\.io\.File\s*;/mu.test(
      structuralText,
    );
    const ioWildcardImported = /^\s*import\s+java\.io\.\*\s*;/mu.test(
      structuralText,
    );
    const fileShadowed = /\b(?:class|enum|interface|record)\s+File\b/u.test(
      structuralText,
    );
    const simpleFileIsOfficial =
      !fileShadowed &&
      (fileSingleImported ||
        (ioWildcardImported && !samePackageTypes.has("File")));
    const fileType = simpleFileIsOfficial
      ? String.raw`(?:(?:java\s*\.\s*io\s*\.\s*)?File)`
      : String.raw`(?:java\s*\.\s*io\s*\.\s*File)`;
    const stringType = !samePackageTypes.has("String")
      ? String.raw`(?:(?:java\s*\.\s*lang\s*\.\s*)?String)`
      : String.raw`(?:java\s*\.\s*lang\s*\.\s*String)`;
    const constructions = (
      expression: string,
    ): Array<{ argument: string; reduced: boolean }> =>
      [
        ...expression.matchAll(
          new RegExp(String.raw`\bnew\s+${fileType}\s*\(`, "gu"),
        ),
      ].flatMap((match) => {
        if (match.index === undefined) return [];
        const relativeOpen = match[0].lastIndexOf("(");
        const open = match.index + relativeOpen;
        const close = matchingCallParenthesis(expression, open);
        if (relativeOpen < 0 || close < 0) return [];
        return [
          {
            argument: expression.slice(open + 1, close),
            reduced: /^\s*\.\s*getName\s*\(\s*\)/u.test(
              expression.slice(close + 1),
            ),
          },
        ];
      });
    return javaBasenameHelperSummaries(
      file.lines,
      {
        path: file.path,
        ...(javaPackageName(file.lines) === undefined
          ? {}
          : { packageName: javaPackageName(file.lines) }),
        projectRoot: javaBasenameProjectRootForPath(files, file.path),
      },
      stringType,
      [
        { kind: "string", pattern: stringType },
        { kind: "file", pattern: fileType },
      ],
      constructions,
      "getName",
    );
  });
}

function javaPathBasenameHelperSummaries(
  files: readonly SourceFileSnapshot[],
  packageTypes: ReadonlyMap<string, ReadonlySet<string>>,
  projectGraph: JavaBasenameProjectGraph,
): JavaBasenameHelperSummary[] {
  return files.flatMap((file) => {
    if (file.extension !== ".java" || javaTestOrExamplePath(file.path)) {
      return [];
    }
    const structuralLines = cFamilyStructuralLines(file.lines);
    const structuralText = structuralLines.join("\n");
    const samePackageTypes = javaSamePackageTopLevelTypes(
      packageTypes,
      files,
      file,
      projectGraph,
    );
    const pathSingleImported = /^\s*import\s+java\.nio\.file\.Path\s*;/mu.test(
      structuralText,
    );
    const pathsSingleImported =
      /^\s*import\s+java\.nio\.file\.Paths\s*;/mu.test(structuralText);
    const wildcardImported = /^\s*import\s+java\.nio\.file\.\*\s*;/mu.test(
      structuralText,
    );
    const pathShadowed = /\b(?:class|enum|interface|record)\s+Path\b/u.test(
      structuralText,
    );
    const pathsShadowed = /\b(?:class|enum|interface|record)\s+Paths\b/u.test(
      structuralText,
    );
    const simplePathIsOfficial =
      !pathShadowed &&
      (pathSingleImported ||
        (wildcardImported && !samePackageTypes.has("Path")));
    const simplePathsIsOfficial =
      !pathsShadowed &&
      (pathsSingleImported ||
        (wildcardImported && !samePackageTypes.has("Paths")));
    const staticPathOfImported = javaStaticFactoryImportIsExact(
      structuralText,
      "java.nio.file.Path",
      "of",
    );
    const staticPathsGetImported = javaStaticFactoryImportIsExact(
      structuralText,
      "java.nio.file.Paths",
      "get",
    );
    const factoryTypes = [
      String.raw`java\s*\.\s*nio\s*\.\s*file\s*\.\s*Path\s*\.\s*of`,
      String.raw`java\s*\.\s*nio\s*\.\s*file\s*\.\s*Paths\s*\.\s*get`,
      ...(simplePathIsOfficial ? [String.raw`Path\s*\.\s*of`] : []),
      ...(simplePathsIsOfficial ? [String.raw`Paths\s*\.\s*get`] : []),
      ...(staticPathOfImported &&
      !javaCompilationUnitDeclaresMethod(structuralLines, "of")
        ? [String.raw`(?<![A-Za-z0-9_$.])of`]
        : []),
      ...(staticPathsGetImported &&
      !javaCompilationUnitDeclaresMethod(structuralLines, "get")
        ? [String.raw`(?<![A-Za-z0-9_$.])get`]
        : []),
    ];
    const factoryStart = new RegExp(
      String.raw`\b(?:${factoryTypes.join("|")})\s*\(`,
      "gu",
    );
    const constructions = (
      expression: string,
    ): Array<{ argument: string; reduced: boolean }> => {
      expression = expression.replace(/\s*\.\s*/gu, ".");
      factoryStart.lastIndex = 0;
      return [...expression.matchAll(factoryStart)].flatMap((match) => {
        if (match.index === undefined) return [];
        const relativeOpen = match[0].lastIndexOf("(");
        const open = match.index + relativeOpen;
        const close = matchingCallParenthesis(expression, open);
        if (relativeOpen < 0 || close < 0) return [];
        return [
          {
            argument: expression.slice(open + 1, close),
            reduced: /^\s*\.\s*getFileName\s*\(\s*\)/u.test(
              expression.slice(close + 1),
            ),
          },
        ];
      });
    };
    const pathType = simplePathIsOfficial
      ? String.raw`(?:(?:java\s*\.\s*nio\s*\.\s*file\s*\.\s*)?Path)`
      : String.raw`(?:java\s*\.\s*nio\s*\.\s*file\s*\.\s*Path)`;
    const stringType = !samePackageTypes.has("String")
      ? String.raw`(?:(?:java\s*\.\s*lang\s*\.\s*)?String)`
      : String.raw`(?:java\s*\.\s*lang\s*\.\s*String)`;
    return javaBasenameHelperSummaries(
      file.lines,
      {
        path: file.path,
        ...(javaPackageName(file.lines) === undefined
          ? {}
          : { packageName: javaPackageName(file.lines) }),
        projectRoot: javaBasenameProjectRootForPath(files, file.path),
      },
      pathType,
      [
        { kind: "string", pattern: stringType },
        { kind: "path", pattern: pathType },
      ],
      constructions,
      "getFileName",
    );
  });
}

function javaCompilationUnitDeclaresMethod(
  lines: readonly string[],
  methodName: string,
): boolean {
  const surface = javaBraceSurface(lines, 1);
  const escaped = escapeRegularExpression(methodName);
  return new RegExp(
    String.raw`(?:^|[;{}])\s*(?:(?:@[A-Za-z_$][\w$.]*(?:\([^;{}]*\))?)\s*)*(?:(?:public|protected|private|abstract|default|final|native|static|strictfp|synchronized)\s+)*(?:<[^;{}]+>\s+)?[A-Za-z_$][\w$.[\]<>?,]*(?:\s*\[\s*\])?\s+${escaped}\s*\(`,
    "mu",
  ).test(surface);
}

function javaStaticFactoryImportIsExact(
  structuralText: string,
  owner: string,
  methodName: string,
): boolean {
  const normalized = structuralText.replace(/\s*\.\s*/gu, ".");
  const imports = [
    ...normalized.matchAll(
      /^\s*import\s+static\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\.\*)+)\s*;/gmu,
    ),
  ].flatMap((match) => (match[1] === undefined ? [] : [match[1]]));
  const exact = `${owner}.${methodName}`;
  const wildcard = `${owner}.*`;
  if (!imports.includes(exact) && !imports.includes(wildcard)) return false;
  return !imports.some(
    (candidate) =>
      candidate !== exact &&
      candidate !== wildcard &&
      (candidate.endsWith(`.${methodName}`) || candidate.endsWith(".*")),
  );
}

function javaPathGetFileNamePathBoundaryRecords(
  files: readonly SourceFileSnapshot[],
  records: readonly ResidualRiskRecord[],
): ResidualRiskRecord[] {
  const filesByPath = new Map(files.map((file) => [file.path, file]));
  const projectGraph = javaBasenameProjectGraph(files);
  const packageTypes = javaPackageTypeIndex(files);
  const helperSummaries = javaPathBasenameHelperSummaries(
    files,
    packageTypes,
    projectGraph,
  );
  const emitted = new Set<string>();
  const specialized: ResidualRiskRecord[] = [];
  for (const record of records) {
    const framework = record.frameworkModel;
    if (framework?.id !== "spring-http-path") continue;
    const sinkFile = filesByPath.get(framework.sink.path);
    if (
      sinkFile?.extension !== ".java" ||
      javaTestOrExamplePath(sinkFile.path)
    ) {
      continue;
    }
    const boundary = javaPathGetFileNamePathBoundary(
      sinkFile,
      files,
      framework.sink.line,
      new Set(
        framework.propagators
          .filter(
            (propagator) =>
              propagator.kind === "wrapper-parameter" &&
              propagator.path === sinkFile.path,
          )
          .flatMap((propagator) =>
            propagator.symbol === undefined ? [] : [propagator.symbol],
          ),
      ),
      javaSamePackageTopLevelTypes(packageTypes, files, sinkFile, projectGraph),
      helperSummaries,
      projectGraph,
    );
    if (boundary === undefined) continue;
    const key = `${framework.source.path}\0${framework.source.line}\0${framework.sink.path}\0${framework.sink.line}`;
    if (emitted.has(key)) continue;
    emitted.add(key);
    specialized.push({
      ...record,
      categories: [
        "framework-dataflow:java-path-getfilename-path-boundary",
        `modeled-source:${framework.source.kind}`,
        `modeled-sink:${framework.sink.kind}`,
        "broken-control:java-nio-path-basename-reduction",
        ...(boundary.parentRejectionLine === undefined
          ? []
          : ["candidate-control:parent-path-component-rejection"]),
      ],
      priority: Math.max(record.priority, 122),
      frameworkModel: {
        ...framework,
        id: "java-path-getfilename-path-boundary",
        candidateControls: [
          ...framework.candidateControls.filter(
            (control) => control.kind !== "single-path-component-validation",
          ),
          {
            kind: "incomplete-java-nio-path-getfilename-reduction",
            path: boundary.reductionPath,
            line: boundary.reductionLine,
          },
          ...(boundary.parentRejectionLine === undefined
            ? []
            : [
                {
                  kind: "parent-path-component-rejection",
                  path: sinkFile.path,
                  line: boundary.parentRejectionLine,
                },
              ]),
        ].filter(
          (control, index, all) =>
            all.findIndex(
              (candidate) =>
                candidate.kind === control.kind &&
                candidate.path === control.path &&
                candidate.line === control.line,
            ) === index,
        ),
      },
    });
  }
  return specialized;
}

function javaPathGetFileNamePathBoundary(
  sinkFile: SourceFileSnapshot,
  files: readonly SourceFileSnapshot[],
  sinkLine: number,
  provenSinkParameters: ReadonlySet<string>,
  samePackageTopLevelTypes: ReadonlySet<string>,
  helperSummaries: readonly JavaBasenameHelperSummary[],
  projectGraph: JavaBasenameProjectGraph,
): JavaBasenameBoundary | undefined {
  const lines = sinkFile.lines;
  const method = exportedJavaMethods(lines).find(
    (candidate) =>
      sinkLine >= candidate.startLine && sinkLine <= candidate.endLine,
  );
  if (method === undefined) return undefined;
  const structuralLines = cFamilyStructuralLines(lines);
  const structuralText = structuralLines.join("\n");
  const pathSingleImported = /^\s*import\s+java\.nio\.file\.Path\s*;/mu.test(
    structuralText,
  );
  const pathsSingleImported = /^\s*import\s+java\.nio\.file\.Paths\s*;/mu.test(
    structuralText,
  );
  const nioFileWildcardImported = /^\s*import\s+java\.nio\.file\.\*\s*;/mu.test(
    structuralText,
  );
  const pathShadowed = /\b(?:class|enum|interface|record)\s+Path\b/u.test(
    structuralText,
  );
  const pathsShadowed = /\b(?:class|enum|interface|record)\s+Paths\b/u.test(
    structuralText,
  );
  const simplePathIsOfficial =
    !pathShadowed &&
    (pathSingleImported ||
      (nioFileWildcardImported && !samePackageTopLevelTypes.has("Path")));
  const simplePathsIsOfficial =
    !pathsShadowed &&
    (pathsSingleImported ||
      (nioFileWildcardImported && !samePackageTopLevelTypes.has("Paths")));
  const localOfMethod = javaCompilationUnitDeclaresMethod(
    structuralLines,
    "of",
  );
  const localGetMethod = javaCompilationUnitDeclaresMethod(
    structuralLines,
    "get",
  );
  const staticPathOfImported = javaStaticFactoryImportIsExact(
    structuralText,
    "java.nio.file.Path",
    "of",
  );
  const staticPathsGetImported = javaStaticFactoryImportIsExact(
    structuralText,
    "java.nio.file.Paths",
    "get",
  );
  const pathType = simplePathIsOfficial
    ? String.raw`(?:(?:java\s*\.\s*nio\s*\.\s*file\s*\.\s*)?Path)`
    : String.raw`(?:java\s*\.\s*nio\s*\.\s*file\s*\.\s*Path)`;
  const factoryTypes = [
    String.raw`java\s*\.\s*nio\s*\.\s*file\s*\.\s*Path\s*\.\s*of`,
    String.raw`java\s*\.\s*nio\s*\.\s*file\s*\.\s*Paths\s*\.\s*get`,
    ...(simplePathIsOfficial ? [String.raw`Path\s*\.\s*of`] : []),
    ...(simplePathsIsOfficial ? [String.raw`Paths\s*\.\s*get`] : []),
    ...(staticPathOfImported && !localOfMethod
      ? [String.raw`(?<![A-Za-z0-9_$.])of`]
      : []),
    ...(staticPathsGetImported && !localGetMethod
      ? [String.raw`(?<![A-Za-z0-9_$.])get`]
      : []),
  ];
  const factoryStart = new RegExp(
    String.raw`\b(?:${factoryTypes.join("|")})\s*\(`,
    "gu",
  );
  const sinkExpression = javaCallExpression(lines, sinkLine, method.endLine);
  const bodyLines = structuralLines.slice(method.startLine - 1, sinkLine - 1);
  const body = bodyLines.join("\n");
  const eligibleParameters =
    provenSinkParameters.size === 0
      ? method.parameters
      : method.parameters.filter((parameter) =>
          provenSinkParameters.has(parameter.name),
        );
  if (eligibleParameters.length === 0) return undefined;
  const tainted = new Set(
    eligibleParameters.map((parameter) => parameter.name),
  );
  const pathReceivers = new Set(
    eligibleParameters
      .filter((parameter) =>
        new RegExp(
          String.raw`\b${pathType}\s+${escapeRegularExpression(parameter.name)}\b`,
          "u",
        ).test(parameter.declaration),
      )
      .map((parameter) => parameter.name),
  );
  const fileReceivers = new Set<string>();
  const basenameOrigins = new Map<string, JavaBasenameOrigin>();
  const referencesAny = (
    expression: string,
    identifiers: Iterable<string>,
  ): boolean =>
    [...identifiers].some((identifier) =>
      cFamilyLineReferencesIdentifier(expression, identifier),
    );
  const exactAliasOf = (
    expression: string,
    identifiers: Iterable<string>,
  ): boolean =>
    [...identifiers].some((identifier) =>
      new RegExp(
        String.raw`^\s*\(?\s*${escapeRegularExpression(identifier)}\s*\)?\s*$`,
        "u",
      ).test(expression),
    );
  const pathFactories = (
    expression: string,
  ): Array<{ argument: string; reduced: boolean }> => {
    expression = expression.replace(/\s*\.\s*/gu, ".");
    factoryStart.lastIndex = 0;
    return [...expression.matchAll(factoryStart)].flatMap((match) => {
      if (match.index === undefined) return [];
      const relativeOpen = match[0].lastIndexOf("(");
      const open = match.index + relativeOpen;
      const close = matchingCallParenthesis(expression, open);
      if (relativeOpen < 0 || close < 0) return [];
      return [
        {
          argument: expression.slice(open + 1, close),
          reduced: /^\s*\.\s*getFileName\s*\(\s*\)/u.test(
            expression.slice(close + 1),
          ),
        },
      ];
    });
  };
  const localHelperSummaries = helperSummaries.filter(
    (summary) => summary.sourcePath === sinkFile.path,
  );
  const assignment = /\b([A-Za-z_$][\w$]*)\s*=(?!=)\s*([^;]+);/gu;
  for (const match of body.matchAll(assignment)) {
    const target = match[1];
    const value = match[2];
    if (target === undefined || value === undefined) continue;
    const line =
      method.startLine + body.slice(0, match.index ?? 0).split("\n").length - 1;
    const derivesFromTaint = referencesAny(value, tainted);
    const constructions = pathFactories(value);
    const localHelperSummary = javaExactBasenameHelperCall(
      value,
      method.ownerType,
      localHelperSummaries,
      tainted,
      pathReceivers,
      fileReceivers,
    );
    const helperSummary =
      localHelperSummary ??
      javaExactExternalBasenameHelperCall(
        value,
        sinkFile,
        files,
        projectGraph,
        helperSummaries,
        tainted,
        pathReceivers,
        fileReceivers,
      );
    const directPathConstruction = constructions.some(({ argument }) =>
      referencesAny(argument, tainted),
    );
    const directReduction = constructions.some(
      ({ argument, reduced }) => reduced && referencesAny(argument, tainted),
    );
    const receiverReduction = [...pathReceivers].some((identifier) =>
      new RegExp(
        String.raw`\b${escapeRegularExpression(identifier)}\s*\.\s*getFileName\s*\(\s*\)`,
        "u",
      ).test(value),
    );
    const inheritedOrigin = [...basenameOrigins].find(([identifier]) =>
      cFamilyLineReferencesIdentifier(value, identifier),
    )?.[1];

    if (derivesFromTaint) tainted.add(target);
    else tainted.delete(target);

    if (
      directPathConstruction ||
      exactAliasOf(value, pathReceivers) ||
      helperSummary !== undefined
    ) {
      pathReceivers.add(target);
    } else {
      pathReceivers.delete(target);
    }

    if (helperSummary !== undefined) {
      basenameOrigins.set(target, {
        evidenceLine: helperSummary.reductionLine,
        evidencePath: helperSummary.sourcePath,
        guardStartLine: line,
      });
    } else if (directReduction || receiverReduction) {
      basenameOrigins.set(target, {
        evidenceLine: line,
        evidencePath: sinkFile.path,
        guardStartLine: line,
      });
    } else if (inheritedOrigin !== undefined) {
      basenameOrigins.set(target, inheritedOrigin);
    } else {
      basenameOrigins.delete(target);
    }
  }

  const directSinkReduction = pathFactories(sinkExpression).some(
    ({ argument, reduced }) => reduced && referencesAny(argument, tainted),
  );
  const receiverSinkReduction = [...pathReceivers].some((identifier) =>
    new RegExp(
      String.raw`\b${escapeRegularExpression(identifier)}\s*\.\s*getFileName\s*\(\s*\)`,
      "u",
    ).test(sinkExpression),
  );
  if (directSinkReduction || receiverSinkReduction) {
    return {
      reductionLine: sinkLine,
      reductionPath: sinkFile.path,
    };
  }
  const reachingBasenames = [...basenameOrigins].filter(([identifier]) =>
    cFamilyLineReferencesIdentifier(sinkExpression, identifier),
  );
  if (reachingBasenames.length === 0) return undefined;
  const selectedOrigin = reachingBasenames
    .map(([, origin]) => origin)
    .sort(
      (left, right) =>
        left.evidencePath.localeCompare(right.evidencePath) ||
        left.evidenceLine - right.evidenceLine ||
        left.guardStartLine - right.guardStartLine,
    )[0]!;
  const originKey = (origin: JavaBasenameOrigin): string =>
    `${origin.evidencePath}\0${origin.evidenceLine}\0${origin.guardStartLine}`;
  const selectedOriginKey = originKey(selectedOrigin);
  const basenameIdentifiers = new Set(
    [...basenameOrigins]
      .filter(([, origin]) => originKey(origin) === selectedOriginKey)
      .map(([identifier]) => identifier),
  );
  const parentFactories = factoryTypes.join("|");
  const parentRejectionLine = javaDominatingEqualityRejection(
    lines,
    structuralLines,
    selectedOrigin.guardStartLine,
    sinkLine,
    basenameIdentifiers,
    String.raw`(?:${parentFactories})\s*\(\s*"\.\."\s*\)`,
  );
  return parentRejectionLine === undefined
    ? {
        reductionLine: selectedOrigin.evidenceLine,
        reductionPath: selectedOrigin.evidencePath,
      }
    : {
        reductionLine: selectedOrigin.evidenceLine,
        reductionPath: selectedOrigin.evidencePath,
        parentRejectionLine,
      };
}

function nodeIpv4OnlyHostGuard(
  lines: readonly string[],
  wrapper: ExportedJavascriptFunction,
  sinkLine: number,
  sinkExpression: string,
): { line: number } | undefined {
  const codeLines = javascriptCodeLinesWithoutComments(lines);
  const structuralLines = javascriptStructuralLines(lines);
  const valueIdentifiers = new Set(
    javascriptExpressionIdentifiers(sinkExpression).filter(
      (identifier) =>
        !["fetch", "get", "got", "http", "https", "request", "undici"].includes(
          identifier,
        ),
    ),
  );
  if (valueIdentifiers.size === 0) return undefined;

  const aliases = new Set(valueIdentifiers);
  for (
    let index = wrapper.startLine - 1;
    index < Math.min(sinkLine - 1, wrapper.endLine);
    index += 1
  ) {
    const code = structuralLines[index] ?? "";
    const assignment =
      /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([\s\S]+)$/u.exec(code);
    if (
      assignment?.[1] !== undefined &&
      assignment[2] !== undefined &&
      [...aliases].some((identifier) =>
        lineReferencesIdentifier(assignment[2]!, identifier),
      ) &&
      /\b(?:host|hostname|new\s+URL|parse|process)\b|\.\s*(?:host|hostname)\b/iu.test(
        assignment[2],
      )
    ) {
      aliases.add(assignment[1]);
    }
  }

  const wrapperText = codeLines
    .slice(wrapper.startLine - 1, Math.min(sinkLine, wrapper.endLine))
    .join("\n");

  for (
    let index = wrapper.startLine - 1;
    index < Math.min(sinkLine - 1, wrapper.endLine);
    index += 1
  ) {
    const structural = structuralLines[index] ?? "";
    const original = codeLines[index] ?? "";
    if (!/\bif\s*\(/u.test(structural)) continue;
    if (
      ![...aliases].some((identifier) =>
        lineReferencesIdentifier(structural, identifier),
      )
    ) {
      continue;
    }
    const explicitIpv4Classifier =
      /\b(?:isPrivate|isReserved|isRfc1918|isLoopback)(?:DottedQuad|IPv?4)|\b(?:dottedQuad|ipv4)(?:Address)?IsPrivate\b/iu.test(
        structural,
      );
    const ipv4LiteralGuard =
      /(?:10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)/u.test(
        original,
      );
    if (!explicitIpv4Classifier && !ipv4LiteralGuard) continue;
    const failClosedWindow = structuralLines
      .slice(index, Math.min(index + 4, sinkLine - 1))
      .join("\n");
    if (!/\b(?:return|throw)\b/u.test(failClosedWindow)) continue;
    if (
      nodeHasCompleteIpv6TransitionCanonicalization(
        lines,
        wrapperText,
        structural,
      )
    ) {
      continue;
    }
    return { line: index + 1 };
  }
  return undefined;
}

function nodeHasCompleteIpv6TransitionCanonicalization(
  lines: readonly string[],
  wrapperText: string,
  guardExpression: string,
): boolean {
  const assignment =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*(?:canonical|normalize|unwrap|transition)[A-Za-z_$\d]*)\s*\(/iu.exec(
      wrapperText,
    );
  const canonicalValue = assignment?.[1];
  const canonicalizer = assignment?.[2];
  if (
    canonicalValue === undefined ||
    canonicalizer === undefined ||
    !lineReferencesIdentifier(guardExpression, canonicalValue)
  ) {
    return false;
  }
  const structuralLines = javascriptStructuralLines(lines);
  const declaration = new RegExp(
    `(?:\\bfunction\\s+${escapeRegularExpression(canonicalizer)}\\s*\\(|\\b(?:const|let|var)\\s+${escapeRegularExpression(canonicalizer)}\\s*=)`,
    "u",
  );
  const declarationIndex = structuralLines.findIndex((line) =>
    declaration.test(line),
  );
  if (declarationIndex < 0) return false;
  const endLine = javascriptFunctionEndLine(lines, declarationIndex);
  const definition = javascriptCodeLinesWithoutComments(
    lines.slice(declarationIndex, endLine),
  ).join("\n");
  const mapped = /::ffff:|isIPv4MappedAddress|ipv4Mapped|mappedIpv4/iu.test(
    definition,
  );
  const nat64 = /64:ff9b:|nat64/iu.test(definition);
  const sixToFour = /2002:|6to4|sixToFour/iu.test(definition);
  const extractsEmbeddedAddress =
    /toIPv4Address|embeddedIpv4|extract[A-Za-z_$\d]*Ipv4|(?:slice|substring)\s*\(/iu.test(
      definition,
    );
  return mapped && nat64 && sixToFour && extractsEmbeddedAddress;
}

function frameworkCrossFileDataflowRecords(
  files: readonly SourceFileSnapshot[],
): ResidualRiskRecord[] {
  return [
    ...frameworkDirectCrossFileDataflowRecords(files),
    ...frameworkDirectPythonDataflowRecords(files),
    ...frameworkDirectJavaDataflowRecords(files),
    ...frameworkDirectDotnetDataflowRecords(files),
    ...frameworkMultiHopDataflowRecords(files),
    ...frameworkPythonMultiHopDataflowRecords(files),
    ...frameworkJavaMultiHopDataflowRecords(files),
    ...frameworkDotnetMultiHopDataflowRecords(files),
  ];
}

function frameworkDirectCrossFileDataflowRecords(
  files: readonly SourceFileSnapshot[],
): ResidualRiskRecord[] {
  const knownPaths = new Map(
    files.map((file) => [modelPathComparisonKey(file.path), file.path]),
  );
  const filesByPath = new Map(files.map((file) => [file.path, file]));
  const summaries = javascriptFrameworkWrapperSummaries(files);
  const summariesByFileAndSymbol = new Map<string, FrameworkWrapperSummary[]>();
  for (const summary of summaries) {
    const key = `${summary.file.path}\0${summary.symbol}`;
    const existing = summariesByFileAndSymbol.get(key) ?? [];
    existing.push(summary);
    summariesByFileAndSymbol.set(key, existing);
  }

  const records: ResidualRiskRecord[] = [];
  const emitted = new Set<string>();
  for (const caller of files) {
    if (!JAVASCRIPT_EXTENSIONS.has(caller.extension)) continue;
    const imports = importedJavascriptSymbols(caller.lines);
    for (const imported of imports) {
      const importedPath = resolveRelativeModelImport(
        caller.path,
        imported.moduleSpecifier,
        knownPaths,
      );
      if (importedPath === undefined) continue;
      const wrapperFile = filesByPath.get(importedPath);
      if (wrapperFile === undefined) continue;
      const matchingSummaries =
        summariesByFileAndSymbol.get(`${importedPath}\0${imported.imported}`) ??
        [];
      for (const summary of matchingSummaries) {
        const sources = matchingJavascriptModelLines(
          caller.lines,
          summary.model.sources,
          32,
        );
        if (sources.length === 0) continue;
        const calls = javascriptCallLines(caller.lines, imported.local);
        for (const call of calls) {
          const argument = call.arguments[summary.parameterIndex];
          if (argument === undefined) continue;
          const source = modeledCallSource(
            caller.lines,
            sources,
            call.line,
            argument,
            summary.model.sources,
          );
          if (source === undefined) continue;
          const key = [
            summary.model.id,
            caller.path,
            call.line,
            wrapperFile.path,
            summary.sink.line,
            summary.parameterIndex,
          ].join("\0");
          if (emitted.has(key)) continue;
          emitted.add(key);

          const sinkStart = Math.max(
            1,
            summary.sink.line - CONTEXT_LINES_BEFORE,
          );
          const sinkEnd = Math.min(
            wrapperFile.lines.length,
            summary.sink.line + CONTEXT_LINES_AFTER,
          );
          const sourceStart = Math.max(1, Math.min(source.line, call.line) - 2);
          const sourceEnd = Math.min(
            caller.lines.length,
            Math.max(source.line, call.line) + 2,
          );
          records.push({
            path: wrapperFile.path,
            line: summary.sink.line,
            categories: [
              `framework-dataflow:${summary.model.id}`,
              "framework-cross-file-wrapper",
              `modeled-source:${source.kind}`,
              `modeled-sink:${summary.sink.kind}`,
              ...summary.controls.map(
                (control) => `candidate-control:${control.kind}`,
              ),
            ],
            priority: 120,
            startLine: sinkStart,
            endLine: sinkEnd,
            excerpt: sourceExcerpt(wrapperFile.lines, sinkStart, sinkEnd),
            sourceExcerpt: sourceExcerpt(caller.lines, sourceStart, sourceEnd),
            frameworkModel: {
              schemaVersion: "1.2",
              id: summary.model.id,
              language: summary.model.language,
              scope: "cross-file-wrapper",
              source: {
                kind: source.kind,
                path: caller.path,
                line: source.line,
              },
              sink: {
                kind: summary.sink.kind,
                path: wrapperFile.path,
                line: summary.sink.line,
                cweIds: summary.sink.cweIds,
              },
              propagators: [
                {
                  kind: "relative-module-import",
                  path: caller.path,
                  line: imported.line,
                  symbol: `${imported.imported} as ${imported.local}`,
                },
                {
                  kind: "wrapper-call-argument",
                  path: caller.path,
                  line: call.line,
                  symbol: `${imported.local}[${summary.parameterIndex}]`,
                },
                {
                  kind: "wrapper-parameter",
                  path: wrapperFile.path,
                  line: summary.declarationLine,
                  symbol: summary.parameter,
                },
              ],
              candidateControls: summary.controls.map((control) => ({
                ...control,
                path: wrapperFile.path,
              })),
            },
          });
          if (records.length >= MAX_FRAMEWORK_CROSS_FILE_RECORDS) {
            return records;
          }
        }
      }
    }
  }
  return records;
}

function frameworkDirectPythonDataflowRecords(
  files: readonly SourceFileSnapshot[],
): ResidualRiskRecord[] {
  const knownPaths = new Map(
    files.map((file) => [modelPathComparisonKey(file.path), file.path]),
  );
  const filesByPath = new Map(files.map((file) => [file.path, file]));
  const summaries = pythonFrameworkWrapperSummaries(files);
  const summariesByFileAndSymbol = new Map<string, FrameworkWrapperSummary[]>();
  for (const summary of summaries) {
    const key = `${summary.file.path}\0${summary.symbol}`;
    const existing = summariesByFileAndSymbol.get(key) ?? [];
    existing.push(summary);
    summariesByFileAndSymbol.set(key, existing);
  }

  const records: ResidualRiskRecord[] = [];
  const emitted = new Set<string>();
  for (const caller of files) {
    if (!PYTHON_EXTENSIONS.has(caller.extension)) continue;
    const imports = importedPythonSymbols(caller.lines);
    for (const imported of imports) {
      const importedPath = resolveRelativePythonImport(
        caller.path,
        imported.moduleSpecifier,
        knownPaths,
      );
      if (importedPath === undefined) continue;
      const wrapperFile = filesByPath.get(importedPath);
      if (wrapperFile === undefined) continue;
      const matchingSummaries =
        summariesByFileAndSymbol.get(`${importedPath}\0${imported.imported}`) ??
        [];
      for (const summary of matchingSummaries) {
        const sources = matchingPythonModelLines(
          caller.lines,
          summary.model.sources,
          32,
        );
        if (sources.length === 0) continue;
        const calls = pythonCallLines(caller.lines, imported.local);
        for (const call of calls) {
          const argument = call.arguments[summary.parameterIndex];
          if (argument === undefined) continue;
          const source = modeledPythonCallSource(
            caller.lines,
            sources,
            call.line,
            argument,
            summary.model.sources,
          );
          if (source === undefined) continue;
          const key = [
            summary.model.id,
            caller.path,
            call.line,
            wrapperFile.path,
            summary.sink.line,
            summary.parameterIndex,
          ].join("\0");
          if (emitted.has(key)) continue;
          emitted.add(key);

          const sinkStart = Math.max(
            1,
            summary.sink.line - CONTEXT_LINES_BEFORE,
          );
          const sinkEnd = Math.min(
            wrapperFile.lines.length,
            summary.sink.line + CONTEXT_LINES_AFTER,
          );
          const sourceStart = Math.max(1, Math.min(source.line, call.line) - 2);
          const sourceEnd = Math.min(
            caller.lines.length,
            Math.max(source.line, call.line) + 2,
          );
          records.push({
            path: wrapperFile.path,
            line: summary.sink.line,
            categories: [
              `framework-dataflow:${summary.model.id}`,
              "framework-cross-file-wrapper",
              `modeled-source:${source.kind}`,
              `modeled-sink:${summary.sink.kind}`,
              ...summary.controls.map(
                (control) => `candidate-control:${control.kind}`,
              ),
            ],
            priority: 120,
            startLine: sinkStart,
            endLine: sinkEnd,
            excerpt: sourceExcerpt(wrapperFile.lines, sinkStart, sinkEnd),
            sourceExcerpt: sourceExcerpt(caller.lines, sourceStart, sourceEnd),
            frameworkModel: {
              schemaVersion: "1.2",
              id: summary.model.id,
              language: summary.model.language,
              scope: "cross-file-wrapper",
              source: {
                kind: source.kind,
                path: caller.path,
                line: source.line,
              },
              sink: {
                kind: summary.sink.kind,
                path: wrapperFile.path,
                line: summary.sink.line,
                cweIds: summary.sink.cweIds,
              },
              propagators: [
                {
                  kind: "relative-python-import",
                  path: caller.path,
                  line: imported.line,
                  symbol: `${imported.imported} as ${imported.local}`,
                },
                {
                  kind: "wrapper-call-argument",
                  path: caller.path,
                  line: call.line,
                  symbol: `${imported.local}[${summary.parameterIndex}]`,
                },
                {
                  kind: "wrapper-parameter",
                  path: wrapperFile.path,
                  line: summary.declarationLine,
                  symbol: summary.parameter,
                },
              ],
              candidateControls: summary.controls.map((control) => ({
                ...control,
                path: wrapperFile.path,
              })),
            },
          });
          if (records.length >= MAX_FRAMEWORK_CROSS_FILE_RECORDS) {
            return records;
          }
        }
      }
    }
  }
  return records;
}

function frameworkDirectJavaDataflowRecords(
  files: readonly SourceFileSnapshot[],
): ResidualRiskRecord[] {
  const summaries = javaFrameworkWrapperSummaries(files);
  const summariesByOwnerAndMethod = new Map<
    string,
    FrameworkWrapperSummary[]
  >();
  for (const summary of summaries) {
    if (summary.ownerType === undefined) continue;
    const key = `${summary.ownerType}\0${summary.symbol}`;
    const existing = summariesByOwnerAndMethod.get(key) ?? [];
    existing.push(summary);
    summariesByOwnerAndMethod.set(key, existing);
  }

  const ownerPaths = new Map<string, Set<string>>();
  for (const file of files) {
    if (file.extension !== ".java") continue;
    const ownerType = javaOwnerType(file.lines);
    if (ownerType === undefined) continue;
    const paths = ownerPaths.get(ownerType) ?? new Set<string>();
    paths.add(file.path);
    ownerPaths.set(ownerType, paths);
  }

  const records: ResidualRiskRecord[] = [];
  const emitted = new Set<string>();
  for (const caller of files) {
    if (caller.extension !== ".java") continue;
    const callerMethods = exportedJavaMethods(caller.lines);
    if (callerMethods.length === 0) continue;
    const receiverBindings = javaReceiverBindings(caller.lines);
    for (const [key, matchingSummaries] of summariesByOwnerAndMethod) {
      const [ownerType, method] = key.split("\0") as [string, string];
      if (ownerPaths.get(ownerType)?.size !== 1) continue;
      const bindings = [
        ...receiverBindings.filter(
          (binding) => binding.ownerType === ownerType,
        ),
        { receiver: ownerType, ownerType, line: 0 },
      ];
      for (const binding of bindings) {
        for (const call of javaMethodCallLines(
          caller.lines,
          binding.receiver,
          method,
        )) {
          const callerMethod = callerMethods.find(
            (candidate) =>
              call.line >= candidate.startLine &&
              call.line <= candidate.endLine,
          );
          if (callerMethod === undefined) continue;
          for (const summary of matchingSummaries) {
            if (summary.file.path === caller.path) continue;
            if (
              summary.parameterCount !== undefined &&
              call.arguments.length !== summary.parameterCount
            ) {
              continue;
            }
            const argument = call.arguments[summary.parameterIndex];
            if (argument === undefined) continue;
            const source =
              summary.model.id === "spring-mvc-jpa-mass-assignment" &&
              summary.valueType !== undefined
                ? modeledJavaMassAssignmentSource(
                    caller.lines,
                    callerMethod,
                    call.line,
                    argument,
                    summary.valueType,
                  )
                : modeledJavaCallSource(
                    caller.lines,
                    callerMethod,
                    call.line,
                    argument,
                    summary.model.sources,
                  );
            if (source === undefined) continue;
            const sourceControls =
              summary.model.id === "spring-mvc-jpa-mass-assignment"
                ? (() => {
                    const parameter = callerMethod.parameters.find(
                      (candidate) => candidate.name === argument.trim(),
                    );
                    return parameter === undefined
                      ? []
                      : javaSpringBindingControls(caller.lines, parameter);
                  })()
                : [];
            const candidateControls = [
              ...summary.controls.map((control) => ({
                ...control,
                path: summary.file.path,
              })),
              ...sourceControls.map((control) => ({
                ...control,
                path: caller.path,
              })),
            ];
            const recordKey = [
              summary.model.id,
              caller.path,
              call.line,
              summary.file.path,
              summary.sink.line,
              summary.parameterIndex,
            ].join("\0");
            if (emitted.has(recordKey)) continue;
            emitted.add(recordKey);

            const sinkStart = Math.max(
              1,
              summary.sink.line - CONTEXT_LINES_BEFORE,
            );
            const sinkEnd = Math.min(
              summary.file.lines.length,
              summary.sink.line + CONTEXT_LINES_AFTER,
            );
            const sourceStart = Math.max(
              1,
              Math.min(source.line, call.line) - 2,
            );
            const sourceEnd = Math.min(
              caller.lines.length,
              Math.max(source.line, call.line) + 2,
            );
            records.push({
              path: summary.file.path,
              line: summary.sink.line,
              categories: [
                `framework-dataflow:${summary.model.id}`,
                "framework-cross-file-wrapper",
                `modeled-source:${source.kind}`,
                `modeled-sink:${summary.sink.kind}`,
                ...candidateControls.map(
                  (control) => `candidate-control:${control.kind}`,
                ),
              ],
              priority: 121,
              startLine: sinkStart,
              endLine: sinkEnd,
              excerpt: sourceExcerpt(summary.file.lines, sinkStart, sinkEnd),
              sourceExcerpt: sourceExcerpt(
                caller.lines,
                sourceStart,
                sourceEnd,
              ),
              frameworkModel: {
                schemaVersion: "1.2",
                id: summary.model.id,
                language: summary.model.language,
                scope: "cross-file-wrapper",
                source: {
                  kind: source.kind,
                  path: caller.path,
                  line: source.line,
                },
                sink: {
                  kind: summary.sink.kind,
                  path: summary.file.path,
                  line: summary.sink.line,
                  cweIds: summary.sink.cweIds,
                },
                propagators: [
                  {
                    kind: "java-type-binding",
                    path: caller.path,
                    line: binding.line || call.line,
                    symbol: `${binding.receiver}:${ownerType}`,
                  },
                  {
                    kind: "wrapper-call-argument",
                    path: caller.path,
                    line: call.line,
                    symbol: `${binding.receiver}.${method}[${summary.parameterIndex}]`,
                  },
                  {
                    kind: "wrapper-parameter",
                    path: summary.file.path,
                    line: summary.declarationLine,
                    symbol: summary.parameter,
                  },
                ],
                candidateControls,
              },
            });
            if (records.length >= MAX_FRAMEWORK_CROSS_FILE_RECORDS) {
              return records;
            }
          }
        }
      }
    }
  }
  return records;
}

function frameworkDirectDotnetDataflowRecords(
  files: readonly SourceFileSnapshot[],
): ResidualRiskRecord[] {
  const summaries = dotnetFrameworkWrapperSummaries(files);
  const summariesByOwnerAndMethod = new Map<
    string,
    FrameworkWrapperSummary[]
  >();
  for (const summary of summaries) {
    if (summary.ownerType === undefined) continue;
    const key = `${summary.ownerType}\0${summary.symbol}`;
    const existing = summariesByOwnerAndMethod.get(key) ?? [];
    existing.push(summary);
    summariesByOwnerAndMethod.set(key, existing);
  }

  const ownerPaths = new Map<string, Set<string>>();
  for (const file of files) {
    if (file.extension !== ".cs") continue;
    const ownerType = dotnetOwnerType(file.lines);
    if (ownerType === undefined) continue;
    const paths = ownerPaths.get(ownerType) ?? new Set<string>();
    paths.add(file.path);
    ownerPaths.set(ownerType, paths);
  }

  const records: ResidualRiskRecord[] = [];
  const emitted = new Set<string>();
  for (const caller of files) {
    if (caller.extension !== ".cs") continue;
    const callerMethods = exportedDotnetMethods(caller.lines);
    if (callerMethods.length === 0) continue;
    const receiverBindings = javaReceiverBindings(caller.lines);
    for (const [key, matchingSummaries] of summariesByOwnerAndMethod) {
      const [ownerType, method] = key.split("\0") as [string, string];
      if (ownerPaths.get(ownerType)?.size !== 1) continue;
      const bindings = [
        ...receiverBindings.filter(
          (binding) => binding.ownerType === ownerType,
        ),
        { receiver: ownerType, ownerType, line: 0 },
      ];
      for (const binding of bindings) {
        for (const call of javaMethodCallLines(
          caller.lines,
          binding.receiver,
          method,
        )) {
          const callerMethod = callerMethods.find(
            (candidate) =>
              call.line >= candidate.startLine &&
              call.line <= candidate.endLine,
          );
          if (callerMethod === undefined) continue;
          for (const summary of matchingSummaries) {
            if (summary.file.path === caller.path) continue;
            if (
              summary.parameterCount !== undefined &&
              call.arguments.length !== summary.parameterCount
            ) {
              continue;
            }
            const argument = call.arguments[summary.parameterIndex];
            if (argument === undefined) continue;
            const source = modeledDotnetCallSource(
              caller.lines,
              callerMethod,
              call.line,
              argument,
              summary.model.sources,
              summary.model.id === "aspnet-http-object-authorization",
              files,
              caller.path,
            );
            if (source === undefined) continue;
            const recordKey = [
              summary.model.id,
              caller.path,
              call.line,
              summary.file.path,
              summary.sink.line,
              summary.parameterIndex,
            ].join("\0");
            if (emitted.has(recordKey)) continue;
            emitted.add(recordKey);

            const sinkStart = Math.max(
              1,
              summary.sink.line - CONTEXT_LINES_BEFORE,
            );
            const sinkEnd = Math.min(
              summary.file.lines.length,
              summary.sink.line + CONTEXT_LINES_AFTER,
            );
            const sourceStart = Math.max(
              1,
              Math.min(source.line, call.line) - 2,
            );
            const sourceEnd = Math.min(
              caller.lines.length,
              Math.max(source.line, call.line) + 2,
            );
            records.push({
              path: summary.file.path,
              line: summary.sink.line,
              categories: [
                `framework-dataflow:${summary.model.id}`,
                "framework-cross-file-wrapper",
                `modeled-source:${source.kind}`,
                `modeled-sink:${summary.sink.kind}`,
                ...summary.controls.map(
                  (control) => `candidate-control:${control.kind}`,
                ),
              ],
              priority: 121,
              startLine: sinkStart,
              endLine: sinkEnd,
              excerpt: sourceExcerpt(summary.file.lines, sinkStart, sinkEnd),
              sourceExcerpt: sourceExcerpt(
                caller.lines,
                sourceStart,
                sourceEnd,
              ),
              frameworkModel: {
                schemaVersion: "1.2",
                id: summary.model.id,
                language: summary.model.language,
                scope: "cross-file-wrapper",
                source: {
                  kind: source.kind,
                  path: caller.path,
                  line: source.line,
                },
                sink: {
                  kind: summary.sink.kind,
                  path: summary.file.path,
                  line: summary.sink.line,
                  cweIds: summary.sink.cweIds,
                },
                propagators: [
                  {
                    kind: "dotnet-type-binding",
                    path: caller.path,
                    line: binding.line || call.line,
                    symbol: `${binding.receiver}:${ownerType}`,
                  },
                  {
                    kind: "wrapper-call-argument",
                    path: caller.path,
                    line: call.line,
                    symbol: `${binding.receiver}.${method}[${summary.parameterIndex}]`,
                  },
                  {
                    kind: "wrapper-parameter",
                    path: summary.file.path,
                    line: summary.declarationLine,
                    symbol: summary.parameter,
                  },
                ],
                candidateControls: summary.controls.map((control) => ({
                  ...control,
                  path: summary.file.path,
                })),
              },
            });
            if (records.length >= MAX_FRAMEWORK_CROSS_FILE_RECORDS) {
              return records;
            }
          }
        }
      }
    }
  }
  return records;
}

function importedFrameworkRelayChain(
  summary: FrameworkRelaySummary,
): ImportedFrameworkRelayChain | undefined {
  const relays: FrameworkRelaySummary[] = [];
  const paths = new Set<string>();
  let current: FrameworkWrapperSummary | FrameworkRelaySummary = summary;
  while ("downstream" in current) {
    if (
      relays.length >= MAX_RELATIVE_IMPORT_RELAY_LAYERS ||
      paths.has(current.file.path)
    ) {
      return undefined;
    }
    relays.push(current);
    paths.add(current.file.path);
    current = current.downstream;
  }
  if (paths.has(current.file.path)) return undefined;
  return { relays, sink: current };
}

function importedFrameworkSummaryPaths(
  summary: FrameworkWrapperSummary | FrameworkRelaySummary,
): ReadonlySet<string> | undefined {
  if (!("downstream" in summary)) return new Set([summary.file.path]);
  const chain = importedFrameworkRelayChain(summary);
  return chain === undefined
    ? undefined
    : new Set([
        ...chain.relays.map((relay) => relay.file.path),
        chain.sink.file.path,
      ]);
}

function frameworkMultiHopDataflowRecords(
  files: readonly SourceFileSnapshot[],
): ResidualRiskRecord[] {
  const knownPaths = new Map(
    files.map((file) => [modelPathComparisonKey(file.path), file.path]),
  );
  const sinkSummaries = javascriptFrameworkWrapperSummaries(files);
  const relaySummaries: FrameworkRelaySummary[] = [];
  let downstreamSummaries: readonly (
    | FrameworkWrapperSummary
    | FrameworkRelaySummary
  )[] = sinkSummaries;
  for (let layer = 0; layer < MAX_RELATIVE_IMPORT_RELAY_LAYERS; layer += 1) {
    const next = javascriptFrameworkRelaySummaries(
      files,
      downstreamSummaries,
      knownPaths,
    );
    relaySummaries.push(...next);
    downstreamSummaries = next;
  }
  const summariesByFileAndSymbol = new Map<string, FrameworkRelaySummary[]>();
  for (const summary of relaySummaries) {
    const key = `${summary.file.path}\0${summary.symbol}`;
    const existing = summariesByFileAndSymbol.get(key) ?? [];
    existing.push(summary);
    summariesByFileAndSymbol.set(key, existing);
  }

  const records: ResidualRiskRecord[] = [];
  const emitted = new Set<string>();
  for (const caller of files) {
    if (!JAVASCRIPT_EXTENSIONS.has(caller.extension)) continue;
    for (const imported of importedJavascriptSymbols(caller.lines)) {
      const importedPath = resolveRelativeModelImport(
        caller.path,
        imported.moduleSpecifier,
        knownPaths,
      );
      if (importedPath === undefined) continue;
      const matchingSummaries =
        summariesByFileAndSymbol.get(`${importedPath}\0${imported.imported}`) ??
        [];
      for (const summary of matchingSummaries) {
        const chain = importedFrameworkRelayChain(summary);
        if (chain === undefined || chain.relays.length === 0) continue;
        const sources = matchingJavascriptModelLines(
          caller.lines,
          summary.model.sources,
          32,
        );
        if (sources.length === 0) continue;
        for (const call of javascriptCallLines(caller.lines, imported.local)) {
          const argument = call.arguments[summary.parameterIndex];
          if (argument === undefined) continue;
          const source = modeledCallSource(
            caller.lines,
            sources,
            call.line,
            argument,
            summary.model.sources,
          );
          if (source === undefined) continue;
          const sinkSummary = chain.sink;
          const key = [
            summary.model.id,
            caller.path,
            call.line,
            ...chain.relays.flatMap((relay) => [
              relay.file.path,
              relay.downstreamCallLine,
              relay.parameterIndex,
            ]),
            sinkSummary.file.path,
            sinkSummary.sink.line,
            sinkSummary.parameterIndex,
          ].join("\0");
          if (emitted.has(key)) continue;
          emitted.add(key);

          const sinkStart = Math.max(
            1,
            sinkSummary.sink.line - CONTEXT_LINES_BEFORE,
          );
          const sinkEnd = Math.min(
            sinkSummary.file.lines.length,
            sinkSummary.sink.line + CONTEXT_LINES_AFTER,
          );
          const sourceStart = Math.max(1, Math.min(source.line, call.line) - 2);
          const sourceEnd = Math.min(
            caller.lines.length,
            Math.max(source.line, call.line) + 2,
          );
          const candidateControls = [
            ...chain.relays.flatMap((relay) =>
              relay.controls.map((control) => ({
                ...control,
                path: relay.file.path,
              })),
            ),
            ...sinkSummary.controls.map((control) => ({
              ...control,
              path: sinkSummary.file.path,
            })),
          ];
          records.push({
            path: sinkSummary.file.path,
            line: sinkSummary.sink.line,
            categories: [
              `framework-dataflow:${summary.model.id}`,
              "framework-cross-file-multi-hop-wrapper",
              `modeled-source:${source.kind}`,
              `modeled-sink:${sinkSummary.sink.kind}`,
              ...candidateControls.map(
                (control) => `candidate-control:${control.kind}`,
              ),
            ],
            priority: 122,
            startLine: sinkStart,
            endLine: sinkEnd,
            excerpt: sourceExcerpt(sinkSummary.file.lines, sinkStart, sinkEnd),
            sourceExcerpt: sourceExcerpt(caller.lines, sourceStart, sourceEnd),
            frameworkModel: {
              schemaVersion: "1.2",
              id: summary.model.id,
              language: summary.model.language,
              scope: "cross-file-multi-hop-wrapper",
              source: {
                kind: source.kind,
                path: caller.path,
                line: source.line,
              },
              sink: {
                kind: sinkSummary.sink.kind,
                path: sinkSummary.file.path,
                line: sinkSummary.sink.line,
                cweIds: sinkSummary.sink.cweIds,
              },
              propagators: [
                {
                  kind: "relative-module-import",
                  path: caller.path,
                  line: imported.line,
                  symbol: `${imported.imported} as ${imported.local}`,
                },
                {
                  kind: "wrapper-call-argument",
                  path: caller.path,
                  line: call.line,
                  symbol: `${imported.local}[${summary.parameterIndex}]`,
                },
                ...chain.relays.flatMap((relay) => [
                  {
                    kind: "wrapper-parameter",
                    path: relay.file.path,
                    line: relay.declarationLine,
                    symbol: relay.parameter,
                  },
                  {
                    kind: "relative-module-import",
                    path: relay.file.path,
                    line: relay.downstreamImport.line,
                    symbol: `${relay.downstreamImport.imported} as ${relay.downstreamImport.local}`,
                  },
                  {
                    kind: "wrapper-call-argument",
                    path: relay.file.path,
                    line: relay.downstreamCallLine,
                    symbol: `${relay.downstreamImport.local}[${relay.downstream.parameterIndex}]`,
                  },
                ]),
                {
                  kind: "wrapper-parameter",
                  path: sinkSummary.file.path,
                  line: sinkSummary.declarationLine,
                  symbol: sinkSummary.parameter,
                },
              ],
              candidateControls,
            },
          });
          if (records.length >= MAX_FRAMEWORK_MULTI_HOP_RECORDS) {
            return records;
          }
        }
      }
    }
  }
  return records;
}

function frameworkPythonMultiHopDataflowRecords(
  files: readonly SourceFileSnapshot[],
): ResidualRiskRecord[] {
  const knownPaths = new Map(
    files.map((file) => [modelPathComparisonKey(file.path), file.path]),
  );
  const sinkSummaries = pythonFrameworkWrapperSummaries(files);
  const relaySummaries: FrameworkRelaySummary[] = [];
  let downstreamSummaries: readonly (
    | FrameworkWrapperSummary
    | FrameworkRelaySummary
  )[] = sinkSummaries;
  for (let layer = 0; layer < MAX_RELATIVE_IMPORT_RELAY_LAYERS; layer += 1) {
    const next = pythonFrameworkRelaySummaries(
      files,
      downstreamSummaries,
      knownPaths,
    );
    relaySummaries.push(...next);
    downstreamSummaries = next;
  }
  const summariesByFileAndSymbol = new Map<string, FrameworkRelaySummary[]>();
  for (const summary of relaySummaries) {
    const key = `${summary.file.path}\0${summary.symbol}`;
    const existing = summariesByFileAndSymbol.get(key) ?? [];
    existing.push(summary);
    summariesByFileAndSymbol.set(key, existing);
  }

  const records: ResidualRiskRecord[] = [];
  const emitted = new Set<string>();
  for (const caller of files) {
    if (!PYTHON_EXTENSIONS.has(caller.extension)) continue;
    for (const imported of importedPythonSymbols(caller.lines)) {
      const importedPath = resolveRelativePythonImport(
        caller.path,
        imported.moduleSpecifier,
        knownPaths,
      );
      if (importedPath === undefined) continue;
      const matchingSummaries =
        summariesByFileAndSymbol.get(`${importedPath}\0${imported.imported}`) ??
        [];
      for (const summary of matchingSummaries) {
        const chain = importedFrameworkRelayChain(summary);
        if (chain === undefined || chain.relays.length === 0) continue;
        const sources = matchingPythonModelLines(
          caller.lines,
          summary.model.sources,
          32,
        );
        if (sources.length === 0) continue;
        for (const call of pythonCallLines(caller.lines, imported.local)) {
          const argument = call.arguments[summary.parameterIndex];
          if (argument === undefined) continue;
          const source = modeledPythonCallSource(
            caller.lines,
            sources,
            call.line,
            argument,
            summary.model.sources,
          );
          if (source === undefined) continue;
          const sinkSummary = chain.sink;
          const key = [
            summary.model.id,
            caller.path,
            call.line,
            ...chain.relays.flatMap((relay) => [
              relay.file.path,
              relay.downstreamCallLine,
              relay.parameterIndex,
            ]),
            sinkSummary.file.path,
            sinkSummary.sink.line,
            sinkSummary.parameterIndex,
          ].join("\0");
          if (emitted.has(key)) continue;
          emitted.add(key);

          const sinkStart = Math.max(
            1,
            sinkSummary.sink.line - CONTEXT_LINES_BEFORE,
          );
          const sinkEnd = Math.min(
            sinkSummary.file.lines.length,
            sinkSummary.sink.line + CONTEXT_LINES_AFTER,
          );
          const sourceStart = Math.max(1, Math.min(source.line, call.line) - 2);
          const sourceEnd = Math.min(
            caller.lines.length,
            Math.max(source.line, call.line) + 2,
          );
          const candidateControls = [
            ...chain.relays.flatMap((relay) =>
              relay.controls.map((control) => ({
                ...control,
                path: relay.file.path,
              })),
            ),
            ...sinkSummary.controls.map((control) => ({
              ...control,
              path: sinkSummary.file.path,
            })),
          ];
          records.push({
            path: sinkSummary.file.path,
            line: sinkSummary.sink.line,
            categories: [
              `framework-dataflow:${summary.model.id}`,
              "framework-cross-file-multi-hop-wrapper",
              `modeled-source:${source.kind}`,
              `modeled-sink:${sinkSummary.sink.kind}`,
              ...candidateControls.map(
                (control) => `candidate-control:${control.kind}`,
              ),
            ],
            priority: 122,
            startLine: sinkStart,
            endLine: sinkEnd,
            excerpt: sourceExcerpt(sinkSummary.file.lines, sinkStart, sinkEnd),
            sourceExcerpt: sourceExcerpt(caller.lines, sourceStart, sourceEnd),
            frameworkModel: {
              schemaVersion: "1.2",
              id: summary.model.id,
              language: summary.model.language,
              scope: "cross-file-multi-hop-wrapper",
              source: {
                kind: source.kind,
                path: caller.path,
                line: source.line,
              },
              sink: {
                kind: sinkSummary.sink.kind,
                path: sinkSummary.file.path,
                line: sinkSummary.sink.line,
                cweIds: sinkSummary.sink.cweIds,
              },
              propagators: [
                {
                  kind: "relative-python-import",
                  path: caller.path,
                  line: imported.line,
                  symbol: `${imported.imported} as ${imported.local}`,
                },
                {
                  kind: "wrapper-call-argument",
                  path: caller.path,
                  line: call.line,
                  symbol: `${imported.local}[${summary.parameterIndex}]`,
                },
                ...chain.relays.flatMap((relay) => [
                  {
                    kind: "wrapper-parameter",
                    path: relay.file.path,
                    line: relay.declarationLine,
                    symbol: relay.parameter,
                  },
                  {
                    kind: "relative-python-import",
                    path: relay.file.path,
                    line: relay.downstreamImport.line,
                    symbol: `${relay.downstreamImport.imported} as ${relay.downstreamImport.local}`,
                  },
                  {
                    kind: "wrapper-call-argument",
                    path: relay.file.path,
                    line: relay.downstreamCallLine,
                    symbol: `${relay.downstreamImport.local}[${relay.downstream.parameterIndex}]`,
                  },
                ]),
                {
                  kind: "wrapper-parameter",
                  path: sinkSummary.file.path,
                  line: sinkSummary.declarationLine,
                  symbol: sinkSummary.parameter,
                },
              ],
              candidateControls,
            },
          });
          if (records.length >= MAX_FRAMEWORK_MULTI_HOP_RECORDS) {
            return records;
          }
        }
      }
    }
  }
  return records;
}

function typedFrameworkRelayChain(
  summary: DotnetFrameworkRelaySummary,
): TypedFrameworkRelayChain | undefined {
  const relays: DotnetFrameworkRelaySummary[] = [];
  const paths = new Set<string>();
  let current: FrameworkWrapperSummary | DotnetFrameworkRelaySummary = summary;
  while ("downstream" in current) {
    if (
      relays.length >= MAX_TYPED_SERVICE_RELAY_LAYERS ||
      paths.has(current.file.path)
    ) {
      return undefined;
    }
    relays.push(current);
    paths.add(current.file.path);
    current = current.downstream;
  }
  if (paths.has(current.file.path)) return undefined;
  return { relays, sink: current };
}

function typedFrameworkSummaryPaths(
  summary: FrameworkWrapperSummary | DotnetFrameworkRelaySummary,
): ReadonlySet<string> | undefined {
  if (!("downstream" in summary)) return new Set([summary.file.path]);
  const chain = typedFrameworkRelayChain(summary);
  return chain === undefined
    ? undefined
    : new Set([
        ...chain.relays.map((relay) => relay.file.path),
        chain.sink.file.path,
      ]);
}

function frameworkJavaMultiHopDataflowRecords(
  files: readonly SourceFileSnapshot[],
): ResidualRiskRecord[] {
  const sinkSummaries = javaFrameworkWrapperSummaries(files);
  const ownerPaths = javaOwnerPaths(files);
  const relaySummaries: JavaFrameworkRelaySummary[] = [];
  let downstreamSummaries: readonly (
    | FrameworkWrapperSummary
    | JavaFrameworkRelaySummary
  )[] = sinkSummaries;
  for (let layer = 0; layer < MAX_TYPED_SERVICE_RELAY_LAYERS; layer += 1) {
    const next = javaFrameworkRelaySummaries(
      files,
      downstreamSummaries,
      ownerPaths,
    );
    relaySummaries.push(...next);
    downstreamSummaries = next;
  }
  const summariesByOwnerAndMethod = new Map<
    string,
    JavaFrameworkRelaySummary[]
  >();
  for (const summary of relaySummaries) {
    const key = `${summary.ownerType}\0${summary.symbol}`;
    const existing = summariesByOwnerAndMethod.get(key) ?? [];
    existing.push(summary);
    summariesByOwnerAndMethod.set(key, existing);
  }

  const records: ResidualRiskRecord[] = [];
  const emitted = new Set<string>();
  for (const caller of files) {
    if (caller.extension !== ".java") continue;
    const callerMethods = exportedJavaMethods(caller.lines);
    if (callerMethods.length === 0) continue;
    const receiverBindings = javaReceiverBindings(caller.lines);
    for (const [key, matchingSummaries] of summariesByOwnerAndMethod) {
      const [ownerType, method] = key.split("\0") as [string, string];
      if (ownerPaths.get(ownerType)?.size !== 1) continue;
      const bindings = [
        ...receiverBindings.filter(
          (binding) => binding.ownerType === ownerType,
        ),
        { receiver: ownerType, ownerType, line: 0 },
      ];
      for (const binding of bindings) {
        for (const call of javaMethodCallLines(
          caller.lines,
          binding.receiver,
          method,
        )) {
          const callerMethod = callerMethods.find(
            (candidate) =>
              call.line >= candidate.startLine &&
              call.line <= candidate.endLine,
          );
          if (callerMethod === undefined) continue;
          for (const summary of matchingSummaries) {
            if (summary.file.path === caller.path) continue;
            const chain = typedFrameworkRelayChain(summary);
            if (chain === undefined || chain.relays.length === 0) continue;
            if (call.arguments.length !== summary.parameterCount) continue;
            const argument = call.arguments[summary.parameterIndex];
            if (argument === undefined) continue;
            const sinkSummary = chain.sink;
            const source =
              summary.model.id === "spring-mvc-jpa-mass-assignment" &&
              sinkSummary.valueType !== undefined
                ? modeledJavaMassAssignmentSource(
                    caller.lines,
                    callerMethod,
                    call.line,
                    argument,
                    sinkSummary.valueType,
                  )
                : modeledJavaCallSource(
                    caller.lines,
                    callerMethod,
                    call.line,
                    argument,
                    summary.model.sources,
                  );
            if (source === undefined) continue;
            const sourceControls =
              summary.model.id === "spring-mvc-jpa-mass-assignment"
                ? (() => {
                    const parameter = callerMethod.parameters.find(
                      (candidate) => candidate.name === argument.trim(),
                    );
                    return parameter === undefined
                      ? []
                      : javaSpringBindingControls(caller.lines, parameter);
                  })()
                : [];
            const recordKey = [
              summary.model.id,
              caller.path,
              call.line,
              ...chain.relays.flatMap((relay) => [
                relay.file.path,
                relay.downstreamCallLine,
                relay.parameterIndex,
              ]),
              sinkSummary.file.path,
              sinkSummary.sink.line,
              sinkSummary.parameterIndex,
            ].join("\0");
            if (emitted.has(recordKey)) continue;
            emitted.add(recordKey);

            const sinkStart = Math.max(
              1,
              sinkSummary.sink.line - CONTEXT_LINES_BEFORE,
            );
            const sinkEnd = Math.min(
              sinkSummary.file.lines.length,
              sinkSummary.sink.line + CONTEXT_LINES_AFTER,
            );
            const sourceStart = Math.max(
              1,
              Math.min(source.line, call.line) - 2,
            );
            const sourceEnd = Math.min(
              caller.lines.length,
              Math.max(source.line, call.line) + 2,
            );
            const candidateControls = [
              ...sourceControls.map((control) => ({
                ...control,
                path: caller.path,
              })),
              ...chain.relays.flatMap((relay) =>
                relay.controls.map((control) => ({
                  ...control,
                  path: relay.file.path,
                })),
              ),
              ...sinkSummary.controls.map((control) => ({
                ...control,
                path: sinkSummary.file.path,
              })),
            ].filter(
              (control, index, all) =>
                all.findIndex(
                  (candidate) =>
                    candidate.kind === control.kind &&
                    candidate.path === control.path &&
                    candidate.line === control.line,
                ) === index,
            );
            records.push({
              path: sinkSummary.file.path,
              line: sinkSummary.sink.line,
              categories: [
                `framework-dataflow:${summary.model.id}`,
                "framework-cross-file-multi-hop-wrapper",
                `modeled-source:${source.kind}`,
                `modeled-sink:${sinkSummary.sink.kind}`,
                ...candidateControls.map(
                  (control) => `candidate-control:${control.kind}`,
                ),
              ],
              priority: 123,
              startLine: sinkStart,
              endLine: sinkEnd,
              excerpt: sourceExcerpt(
                sinkSummary.file.lines,
                sinkStart,
                sinkEnd,
              ),
              sourceExcerpt: sourceExcerpt(
                caller.lines,
                sourceStart,
                sourceEnd,
              ),
              frameworkModel: {
                schemaVersion: "1.2",
                id: summary.model.id,
                language: summary.model.language,
                scope: "cross-file-multi-hop-wrapper",
                source: {
                  kind: source.kind,
                  path: caller.path,
                  line: source.line,
                },
                sink: {
                  kind: sinkSummary.sink.kind,
                  path: sinkSummary.file.path,
                  line: sinkSummary.sink.line,
                  cweIds: sinkSummary.sink.cweIds,
                },
                propagators: [
                  {
                    kind: "java-type-binding",
                    path: caller.path,
                    line: binding.line || call.line,
                    symbol: `${binding.receiver}:${ownerType}`,
                  },
                  {
                    kind: "wrapper-call-argument",
                    path: caller.path,
                    line: call.line,
                    symbol: `${binding.receiver}.${method}[${summary.parameterIndex}]`,
                  },
                  ...chain.relays.flatMap((relay) => [
                    {
                      kind: "wrapper-parameter",
                      path: relay.file.path,
                      line: relay.declarationLine,
                      symbol: relay.parameter,
                    },
                    {
                      kind: "java-type-binding",
                      path: relay.file.path,
                      line:
                        relay.downstreamBinding.line ||
                        relay.downstreamCallLine,
                      symbol: `${relay.downstreamBinding.receiver}:${relay.downstreamBinding.ownerType}`,
                    },
                    {
                      kind: "wrapper-call-argument",
                      path: relay.file.path,
                      line: relay.downstreamCallLine,
                      symbol: `${relay.downstreamBinding.receiver}.${relay.downstream.symbol}[${relay.downstream.parameterIndex}]`,
                    },
                  ]),
                  {
                    kind: "wrapper-parameter",
                    path: sinkSummary.file.path,
                    line: sinkSummary.declarationLine,
                    symbol: sinkSummary.parameter,
                  },
                ],
                candidateControls,
              },
            });
            if (records.length >= MAX_FRAMEWORK_MULTI_HOP_RECORDS) {
              return records;
            }
          }
        }
      }
    }
  }
  return records;
}

function frameworkDotnetMultiHopDataflowRecords(
  files: readonly SourceFileSnapshot[],
): ResidualRiskRecord[] {
  const sinkSummaries = dotnetFrameworkWrapperSummaries(files);
  const ownerPaths = dotnetOwnerPaths(files);
  const relaySummaries: DotnetFrameworkRelaySummary[] = [];
  let downstreamSummaries: readonly (
    | FrameworkWrapperSummary
    | DotnetFrameworkRelaySummary
  )[] = sinkSummaries;
  for (let layer = 0; layer < MAX_TYPED_SERVICE_RELAY_LAYERS; layer += 1) {
    const next = dotnetFrameworkRelaySummaries(
      files,
      downstreamSummaries,
      ownerPaths,
    );
    relaySummaries.push(...next);
    downstreamSummaries = next;
  }
  const summariesByOwnerAndMethod = new Map<
    string,
    DotnetFrameworkRelaySummary[]
  >();
  for (const summary of relaySummaries) {
    const key = `${summary.ownerType}\0${summary.symbol}`;
    const existing = summariesByOwnerAndMethod.get(key) ?? [];
    existing.push(summary);
    summariesByOwnerAndMethod.set(key, existing);
  }

  const records: ResidualRiskRecord[] = [];
  const emitted = new Set<string>();
  for (const caller of files) {
    if (caller.extension !== ".cs") continue;
    const callerMethods = exportedDotnetMethods(caller.lines);
    if (callerMethods.length === 0) continue;
    const receiverBindings = javaReceiverBindings(caller.lines);
    for (const [key, matchingSummaries] of summariesByOwnerAndMethod) {
      const [ownerType, method] = key.split("\0") as [string, string];
      if (ownerPaths.get(ownerType)?.size !== 1) continue;
      const bindings = [
        ...receiverBindings.filter(
          (binding) => binding.ownerType === ownerType,
        ),
        { receiver: ownerType, ownerType, line: 0 },
      ];
      for (const binding of bindings) {
        for (const call of javaMethodCallLines(
          caller.lines,
          binding.receiver,
          method,
        )) {
          const callerMethod = callerMethods.find(
            (candidate) =>
              call.line >= candidate.startLine &&
              call.line <= candidate.endLine,
          );
          if (callerMethod === undefined) continue;
          for (const summary of matchingSummaries) {
            if (summary.file.path === caller.path) continue;
            const chain = typedFrameworkRelayChain(summary);
            if (chain === undefined || chain.relays.length === 0) continue;
            if (call.arguments.length !== summary.parameterCount) continue;
            const argument = call.arguments[summary.parameterIndex];
            if (argument === undefined) continue;
            const source = modeledDotnetCallSource(
              caller.lines,
              callerMethod,
              call.line,
              argument,
              summary.model.sources,
              summary.model.id === "aspnet-http-object-authorization",
              files,
              caller.path,
            );
            if (source === undefined) continue;
            const sinkSummary = chain.sink;
            const recordKey = [
              summary.model.id,
              caller.path,
              call.line,
              ...chain.relays.flatMap((relay) => [
                relay.file.path,
                relay.downstreamCallLine,
                relay.parameterIndex,
              ]),
              sinkSummary.file.path,
              sinkSummary.sink.line,
              sinkSummary.parameterIndex,
            ].join("\0");
            if (emitted.has(recordKey)) continue;
            emitted.add(recordKey);

            const sinkStart = Math.max(
              1,
              sinkSummary.sink.line - CONTEXT_LINES_BEFORE,
            );
            const sinkEnd = Math.min(
              sinkSummary.file.lines.length,
              sinkSummary.sink.line + CONTEXT_LINES_AFTER,
            );
            const sourceStart = Math.max(
              1,
              Math.min(source.line, call.line) - 2,
            );
            const sourceEnd = Math.min(
              caller.lines.length,
              Math.max(source.line, call.line) + 2,
            );
            const candidateControls = [
              ...chain.relays.flatMap((relay) =>
                relay.controls.map((control) => ({
                  ...control,
                  path: relay.file.path,
                })),
              ),
              ...sinkSummary.controls.map((control) => ({
                ...control,
                path: sinkSummary.file.path,
              })),
            ].filter(
              (control, index, all) =>
                all.findIndex(
                  (candidate) =>
                    candidate.kind === control.kind &&
                    candidate.path === control.path &&
                    candidate.line === control.line,
                ) === index,
            );
            records.push({
              path: sinkSummary.file.path,
              line: sinkSummary.sink.line,
              categories: [
                `framework-dataflow:${summary.model.id}`,
                "framework-cross-file-multi-hop-wrapper",
                `modeled-source:${source.kind}`,
                `modeled-sink:${sinkSummary.sink.kind}`,
                ...candidateControls.map(
                  (control) => `candidate-control:${control.kind}`,
                ),
              ],
              priority: 123,
              startLine: sinkStart,
              endLine: sinkEnd,
              excerpt: sourceExcerpt(
                sinkSummary.file.lines,
                sinkStart,
                sinkEnd,
              ),
              sourceExcerpt: sourceExcerpt(
                caller.lines,
                sourceStart,
                sourceEnd,
              ),
              frameworkModel: {
                schemaVersion: "1.2",
                id: summary.model.id,
                language: summary.model.language,
                scope: "cross-file-multi-hop-wrapper",
                source: {
                  kind: source.kind,
                  path: caller.path,
                  line: source.line,
                },
                sink: {
                  kind: sinkSummary.sink.kind,
                  path: sinkSummary.file.path,
                  line: sinkSummary.sink.line,
                  cweIds: sinkSummary.sink.cweIds,
                },
                propagators: [
                  {
                    kind: "dotnet-type-binding",
                    path: caller.path,
                    line: binding.line || call.line,
                    symbol: `${binding.receiver}:${ownerType}`,
                  },
                  {
                    kind: "wrapper-call-argument",
                    path: caller.path,
                    line: call.line,
                    symbol: `${binding.receiver}.${method}[${summary.parameterIndex}]`,
                  },
                  ...chain.relays.flatMap((relay) => [
                    {
                      kind: "wrapper-parameter",
                      path: relay.file.path,
                      line: relay.declarationLine,
                      symbol: relay.parameter,
                    },
                    {
                      kind: "dotnet-type-binding",
                      path: relay.file.path,
                      line:
                        relay.downstreamBinding.line ||
                        relay.downstreamCallLine,
                      symbol: `${relay.downstreamBinding.receiver}:${relay.downstreamBinding.ownerType}`,
                    },
                    {
                      kind: "wrapper-call-argument",
                      path: relay.file.path,
                      line: relay.downstreamCallLine,
                      symbol: `${relay.downstreamBinding.receiver}.${relay.downstream.symbol}[${relay.downstream.parameterIndex}]`,
                    },
                  ]),
                  {
                    kind: "wrapper-parameter",
                    path: sinkSummary.file.path,
                    line: sinkSummary.declarationLine,
                    symbol: sinkSummary.parameter,
                  },
                ],
                candidateControls,
              },
            });
            if (records.length >= MAX_FRAMEWORK_MULTI_HOP_RECORDS) {
              return records;
            }
          }
        }
      }
    }
  }
  return records;
}

function javaFrameworkRelaySummaries(
  files: readonly SourceFileSnapshot[],
  sinkSummaries: readonly (
    | FrameworkWrapperSummary
    | JavaFrameworkRelaySummary
  )[],
  ownerPaths: ReadonlyMap<string, ReadonlySet<string>>,
): JavaFrameworkRelaySummary[] {
  const summariesByOwnerAndMethod = new Map<
    string,
    Array<FrameworkWrapperSummary | JavaFrameworkRelaySummary>
  >();
  for (const summary of sinkSummaries) {
    if (summary.ownerType === undefined) continue;
    const key = `${summary.ownerType}\0${summary.symbol}`;
    const existing = summariesByOwnerAndMethod.get(key) ?? [];
    existing.push(summary);
    summariesByOwnerAndMethod.set(key, existing);
  }

  const summaries: JavaFrameworkRelaySummary[] = [];
  for (const file of files) {
    if (file.extension !== ".java") continue;
    const methods = exportedJavaMethods(file.lines);
    if (methods.length === 0) continue;
    const receiverBindings = javaReceiverBindings(file.lines);
    for (const [key, downstreamSummaries] of summariesByOwnerAndMethod) {
      const [downstreamOwnerType, downstreamMethod] = key.split("\0") as [
        string,
        string,
      ];
      if (ownerPaths.get(downstreamOwnerType)?.size !== 1) continue;
      const bindings = [
        ...receiverBindings.filter(
          (binding) => binding.ownerType === downstreamOwnerType,
        ),
        {
          receiver: downstreamOwnerType,
          ownerType: downstreamOwnerType,
          line: 0,
        },
      ];
      for (const binding of bindings) {
        const calls = javaMethodCallLines(
          file.lines,
          binding.receiver,
          downstreamMethod,
        );
        for (const method of methods) {
          const methodCalls = calls.filter(
            (call) =>
              call.line >= method.startLine && call.line <= method.endLine,
          );
          for (const downstream of downstreamSummaries) {
            const downstreamPaths = typedFrameworkSummaryPaths(downstream);
            if (
              downstreamPaths === undefined ||
              downstreamPaths.has(file.path)
            ) {
              continue;
            }
            const sink =
              "downstream" in downstream
                ? typedFrameworkRelayChain(downstream)?.sink
                : downstream;
            if (sink === undefined) continue;
            const controls =
              downstream.model.id === "spring-mvc-jpa-mass-assignment"
                ? []
                : matchingJavaModelLines(
                    file.lines,
                    downstream.model.controls,
                    64,
                  ).filter(
                    (control) =>
                      control.line >= method.startLine &&
                      control.line <= method.endLine,
                  );
            for (const call of methodCalls) {
              if (
                downstream.parameterCount !== undefined &&
                call.arguments.length !== downstream.parameterCount
              ) {
                continue;
              }
              const argument = call.arguments[downstream.parameterIndex];
              if (argument === undefined) continue;
              for (
                let parameterIndex = 0;
                parameterIndex < method.parameters.length;
                parameterIndex += 1
              ) {
                const parameter = method.parameters[parameterIndex]!;
                if (argument !== parameter.name) continue;
                if (
                  downstream.model.id === "spring-mvc-jpa-mass-assignment" &&
                  (sink.valueType === undefined ||
                    javaParameterSimpleType(parameter) !== sink.valueType)
                ) {
                  continue;
                }
                if (
                  javaIdentifierReassignedBetween(
                    file.lines,
                    parameter.name,
                    method.startLine,
                    call.line,
                  )
                ) {
                  continue;
                }
                summaries.push({
                  model: downstream.model,
                  file,
                  ownerType: method.ownerType,
                  symbol: method.symbol,
                  parameter: parameter.name,
                  parameterIndex,
                  parameterCount: method.parameters.length,
                  declarationLine: method.startLine,
                  downstreamBinding: binding,
                  downstreamCallLine: call.line,
                  downstream,
                  controls: controls.slice(0, 8),
                });
              }
            }
          }
        }
      }
    }
  }
  return summaries;
}

function javaOwnerPaths(
  files: readonly SourceFileSnapshot[],
): Map<string, Set<string>> {
  const ownerPaths = new Map<string, Set<string>>();
  for (const file of files) {
    if (file.extension !== ".java") continue;
    const ownerType = javaOwnerType(file.lines);
    if (ownerType === undefined) continue;
    const paths = ownerPaths.get(ownerType) ?? new Set<string>();
    paths.add(file.path);
    ownerPaths.set(ownerType, paths);
  }
  return ownerPaths;
}

function dotnetFrameworkRelaySummaries(
  files: readonly SourceFileSnapshot[],
  sinkSummaries: readonly (
    | FrameworkWrapperSummary
    | DotnetFrameworkRelaySummary
  )[],
  ownerPaths: ReadonlyMap<string, ReadonlySet<string>>,
): DotnetFrameworkRelaySummary[] {
  const summariesByOwnerAndMethod = new Map<
    string,
    Array<FrameworkWrapperSummary | DotnetFrameworkRelaySummary>
  >();
  for (const summary of sinkSummaries) {
    if (summary.ownerType === undefined) continue;
    const key = `${summary.ownerType}\0${summary.symbol}`;
    const existing = summariesByOwnerAndMethod.get(key) ?? [];
    existing.push(summary);
    summariesByOwnerAndMethod.set(key, existing);
  }

  const summaries: DotnetFrameworkRelaySummary[] = [];
  for (const file of files) {
    if (file.extension !== ".cs") continue;
    const methods = exportedDotnetMethods(file.lines);
    if (methods.length === 0) continue;
    const receiverBindings = javaReceiverBindings(file.lines);
    for (const [key, downstreamSummaries] of summariesByOwnerAndMethod) {
      const [downstreamOwnerType, downstreamMethod] = key.split("\0") as [
        string,
        string,
      ];
      if (ownerPaths.get(downstreamOwnerType)?.size !== 1) continue;
      const bindings = [
        ...receiverBindings.filter(
          (binding) => binding.ownerType === downstreamOwnerType,
        ),
        {
          receiver: downstreamOwnerType,
          ownerType: downstreamOwnerType,
          line: 0,
        },
      ];
      for (const binding of bindings) {
        const calls = javaMethodCallLines(
          file.lines,
          binding.receiver,
          downstreamMethod,
        );
        for (const method of methods) {
          const methodCalls = calls.filter(
            (call) =>
              call.line >= method.startLine && call.line <= method.endLine,
          );
          for (const downstream of downstreamSummaries) {
            const downstreamPaths = typedFrameworkSummaryPaths(downstream);
            if (
              downstreamPaths === undefined ||
              downstreamPaths.has(file.path)
            ) {
              continue;
            }
            const controls = matchingJavaModelLines(
              file.lines,
              downstream.model.controls,
              64,
            ).filter(
              (control) =>
                control.line >= method.startLine &&
                control.line <= method.endLine,
            );
            for (const call of methodCalls) {
              if (
                downstream.parameterCount !== undefined &&
                call.arguments.length !== downstream.parameterCount
              ) {
                continue;
              }
              const argument = call.arguments[downstream.parameterIndex];
              if (argument === undefined) continue;
              for (
                let parameterIndex = 0;
                parameterIndex < method.parameters.length;
                parameterIndex += 1
              ) {
                const parameter = method.parameters[parameterIndex]!;
                if (argument !== parameter.name) continue;
                if (
                  javaIdentifierReassignedBetween(
                    file.lines,
                    parameter.name,
                    method.startLine,
                    call.line,
                  )
                ) {
                  continue;
                }
                summaries.push({
                  model: downstream.model,
                  file,
                  ownerType: method.ownerType,
                  symbol: method.symbol,
                  parameter: parameter.name,
                  parameterIndex,
                  parameterCount: method.parameters.length,
                  declarationLine: method.startLine,
                  downstreamBinding: binding,
                  downstreamCallLine: call.line,
                  downstream,
                  controls: controls.slice(0, 8),
                });
              }
            }
          }
        }
      }
    }
  }
  return summaries;
}

function dotnetOwnerPaths(
  files: readonly SourceFileSnapshot[],
): Map<string, Set<string>> {
  const ownerPaths = new Map<string, Set<string>>();
  for (const file of files) {
    if (file.extension !== ".cs") continue;
    const ownerType = dotnetOwnerType(file.lines);
    if (ownerType === undefined) continue;
    const paths = ownerPaths.get(ownerType) ?? new Set<string>();
    paths.add(file.path);
    ownerPaths.set(ownerType, paths);
  }
  return ownerPaths;
}

function javascriptFrameworkRelaySummaries(
  files: readonly SourceFileSnapshot[],
  sinkSummaries: readonly (FrameworkWrapperSummary | FrameworkRelaySummary)[],
  knownPaths: ReadonlyMap<string, string>,
): FrameworkRelaySummary[] {
  const summariesByFileAndSymbol = new Map<
    string,
    Array<FrameworkWrapperSummary | FrameworkRelaySummary>
  >();
  for (const summary of sinkSummaries) {
    const key = `${summary.file.path}\0${summary.symbol}`;
    const existing = summariesByFileAndSymbol.get(key) ?? [];
    existing.push(summary);
    summariesByFileAndSymbol.set(key, existing);
  }

  const summaries: FrameworkRelaySummary[] = [];
  for (const file of files) {
    if (!JAVASCRIPT_EXTENSIONS.has(file.extension)) continue;
    const exportedFunctions = exportedJavascriptFunctions(file.lines);
    if (exportedFunctions.length === 0) continue;
    for (const imported of importedJavascriptSymbols(file.lines)) {
      const importedPath = resolveRelativeModelImport(
        file.path,
        imported.moduleSpecifier,
        knownPaths,
      );
      if (importedPath === undefined || importedPath === file.path) continue;
      const downstreamSummaries =
        summariesByFileAndSymbol.get(`${importedPath}\0${imported.imported}`) ??
        [];
      if (downstreamSummaries.length === 0) continue;
      const calls = javascriptCallLines(file.lines, imported.local);
      for (const wrapper of exportedFunctions) {
        const wrapperCalls = calls.filter(
          (call) =>
            call.line > wrapper.startLine && call.line <= wrapper.endLine,
        );
        for (const downstream of downstreamSummaries) {
          const downstreamPaths = importedFrameworkSummaryPaths(downstream);
          if (downstreamPaths === undefined || downstreamPaths.has(file.path)) {
            continue;
          }
          const controls = matchingModelLines(
            file.lines,
            downstream.model.controls,
            64,
          )
            .filter(
              (control) =>
                control.line >= wrapper.startLine &&
                control.line <= wrapper.endLine,
            )
            .slice(0, 8);
          for (const call of wrapperCalls) {
            const argument = call.arguments[downstream.parameterIndex];
            if (argument === undefined) continue;
            for (
              let parameterIndex = 0;
              parameterIndex < wrapper.parameters.length;
              parameterIndex += 1
            ) {
              const parameter = wrapper.parameters[parameterIndex]!;
              if (argument !== parameter) continue;
              if (
                javascriptIdentifierReassignedBetween(
                  file.lines,
                  parameter,
                  wrapper.startLine,
                  call.line,
                )
              ) {
                continue;
              }
              summaries.push({
                model: downstream.model,
                file,
                symbol: wrapper.symbol,
                parameter,
                parameterIndex,
                declarationLine: wrapper.startLine,
                downstreamImport: imported,
                downstreamCallLine: call.line,
                downstream,
                controls,
              });
            }
          }
        }
      }
    }
  }
  return summaries;
}

function pythonFrameworkRelaySummaries(
  files: readonly SourceFileSnapshot[],
  sinkSummaries: readonly (FrameworkWrapperSummary | FrameworkRelaySummary)[],
  knownPaths: ReadonlyMap<string, string>,
): FrameworkRelaySummary[] {
  const summariesByFileAndSymbol = new Map<
    string,
    Array<FrameworkWrapperSummary | FrameworkRelaySummary>
  >();
  for (const summary of sinkSummaries) {
    const key = `${summary.file.path}\0${summary.symbol}`;
    const existing = summariesByFileAndSymbol.get(key) ?? [];
    existing.push(summary);
    summariesByFileAndSymbol.set(key, existing);
  }

  const summaries: FrameworkRelaySummary[] = [];
  for (const file of files) {
    if (!PYTHON_EXTENSIONS.has(file.extension)) continue;
    const exportedFunctions = exportedPythonFunctions(file.lines);
    if (exportedFunctions.length === 0) continue;
    for (const imported of importedPythonSymbols(file.lines)) {
      const importedPath = resolveRelativePythonImport(
        file.path,
        imported.moduleSpecifier,
        knownPaths,
      );
      if (importedPath === undefined || importedPath === file.path) continue;
      const downstreamSummaries =
        summariesByFileAndSymbol.get(`${importedPath}\0${imported.imported}`) ??
        [];
      if (downstreamSummaries.length === 0) continue;
      const calls = pythonCallLines(file.lines, imported.local);
      for (const wrapper of exportedFunctions) {
        const wrapperCalls = calls.filter(
          (call) =>
            call.line > wrapper.startLine && call.line <= wrapper.endLine,
        );
        for (const downstream of downstreamSummaries) {
          const downstreamPaths = importedFrameworkSummaryPaths(downstream);
          if (downstreamPaths === undefined || downstreamPaths.has(file.path)) {
            continue;
          }
          const controls = matchingPythonModelLines(
            file.lines,
            downstream.model.controls,
            64,
          )
            .filter(
              (control) =>
                control.line >= wrapper.startLine &&
                control.line <= wrapper.endLine,
            )
            .slice(0, 8);
          for (const call of wrapperCalls) {
            const argument = call.arguments[downstream.parameterIndex];
            if (argument === undefined) continue;
            for (
              let parameterIndex = 0;
              parameterIndex < wrapper.parameters.length;
              parameterIndex += 1
            ) {
              const parameter = wrapper.parameters[parameterIndex]!;
              if (argument !== parameter) continue;
              if (
                pythonIdentifierReassignedBetween(
                  file.lines,
                  parameter,
                  wrapper.startLine,
                  call.line,
                )
              ) {
                continue;
              }
              summaries.push({
                model: downstream.model,
                file,
                symbol: wrapper.symbol,
                parameter,
                parameterIndex,
                declarationLine: wrapper.startLine,
                downstreamImport: imported,
                downstreamCallLine: call.line,
                downstream,
                controls,
              });
            }
          }
        }
      }
    }
  }
  return summaries;
}

function javascriptFrameworkWrapperSummaries(
  files: readonly SourceFileSnapshot[],
): FrameworkWrapperSummary[] {
  const summaries: FrameworkWrapperSummary[] = [];
  for (const file of files) {
    if (!JAVASCRIPT_EXTENSIONS.has(file.extension)) continue;
    const exportedFunctions = exportedJavascriptFunctions(file.lines);
    if (exportedFunctions.length === 0) continue;
    for (const model of FRAMEWORK_DATAFLOW_MODELS) {
      if (
        !model.extensions.has(file.extension) ||
        !model.activation.some((expression) => expression.test(file.text))
      ) {
        continue;
      }
      if (
        (model.id === "node-http-mongoose-nosql" ||
          model.id === "node-http-mongoose-update" ||
          model.id === "node-http-mongoose-bulk-write") &&
        !nodeMongooseHasOfficialFactoryBinding(file.lines)
      ) {
        continue;
      }
      const sinks =
        model.id === "node-http-path"
          ? exactFilesystemPathSinkLines(file.lines, model.id, 32)
          : matchingJavascriptModelLines(file.lines, model.sinks, 32);
      const controls =
        model.id === "node-http-object-authorization" ||
        model.id === "node-http-mongoose-nosql" ||
        model.id === "node-http-mongoose-update" ||
        model.id === "node-http-mongoose-bulk-write"
          ? []
          : model.id === "node-http-ssrf" || model.id === "node-http-path"
            ? matchingJavascriptControlLines(file.lines, model.controls, 64)
            : matchingModelLines(file.lines, model.controls, 64);
      for (const wrapper of exportedFunctions) {
        for (const sink of sinks) {
          if (sink.line < wrapper.startLine || sink.line > wrapper.endLine) {
            continue;
          }
          const sinkLine = javascriptCodeBeforeComment(
            file.lines[sink.line - 1] ?? "",
          );
          const nodeHttpSink =
            model.id === "node-http-ssrf"
              ? nodeHttpUrlSink(file.lines, sink.line)
              : undefined;
          const nodeObjectSink =
            model.id === "node-http-object-authorization"
              ? nodeObjectAuthorizationSink(file.lines, sink.line)
              : undefined;
          const nodeCopilotSink =
            model.id === "node-copilot-system-prompt-injection"
              ? nodeCopilotPromptSink(file.lines, sink.line)
              : undefined;
          const nodePathSink =
            model.id === "node-http-path"
              ? nodeFilesystemPathSink(file.lines, sink.line)
              : undefined;
          const nodeMongooseSink =
            model.id === "node-http-mongoose-nosql"
              ? nodeMongooseNoSqlSink(file.lines, sink.line)
              : undefined;
          const nodeMongooseUpdate =
            model.id === "node-http-mongoose-update"
              ? nodeMongooseUpdateSink(file.lines, sink.line)
              : undefined;
          const nodeMongooseBulkWrite =
            model.id === "node-http-mongoose-bulk-write"
              ? nodeMongooseBulkWriteSink(file.lines, sink.line)
              : undefined;
          if (model.id === "node-http-ssrf" && nodeHttpSink === undefined) {
            continue;
          }
          if (
            model.id === "node-http-object-authorization" &&
            nodeObjectSink === undefined
          ) {
            continue;
          }
          if (
            model.id === "node-copilot-system-prompt-injection" &&
            nodeCopilotSink === undefined
          ) {
            continue;
          }
          if (model.id === "node-http-path" && nodePathSink === undefined) {
            continue;
          }
          if (
            model.id === "node-http-mongoose-nosql" &&
            nodeMongooseSink === undefined
          ) {
            continue;
          }
          if (
            model.id === "node-http-mongoose-update" &&
            nodeMongooseUpdate === undefined
          ) {
            continue;
          }
          if (
            model.id === "node-http-mongoose-bulk-write" &&
            nodeMongooseBulkWrite === undefined
          ) {
            continue;
          }
          if (
            nodeHttpSink?.axiosReceiver !== undefined &&
            wrapper.parameters.includes(nodeHttpSink.axiosReceiver)
          ) {
            continue;
          }
          const sinkValue =
            (nodeMongooseBulkWrite === undefined
              ? undefined
              : nodeMongooseBulkWrite.positions
                  .map(({ expression }) => expression)
                  .join("\n")) ??
            (nodeMongooseUpdate === undefined
              ? undefined
              : resolveJavascriptExpression(
                  file.lines,
                  nodeMongooseUpdate.updateExpression,
                  sink.line,
                )?.value ?? nodeMongooseUpdate.updateExpression) ??
            (nodeMongooseSink === undefined
              ? undefined
              : resolveJavascriptExpression(
                  file.lines,
                  nodeMongooseSink.filterExpression,
                  sink.line,
                )?.value ?? nodeMongooseSink.filterExpression) ??
            nodePathSink?.expressions
              .map(
                (expression) =>
                  resolveJavascriptExpression(file.lines, expression, sink.line)
                    ?.value ?? expression,
              )
              .join("\n") ??
            nodeHttpSink?.urlExpression ??
            nodeObjectSink?.argument ??
            nodeCopilotSink?.inputs
              .map(({ expression }) => expression)
              .join("\n") ??
            sinkLine;
          const parameterIndexes = wrapper.parameters.flatMap(
            (parameter, parameterIndex) =>
              lineReferencesIdentifier(sinkValue, parameter)
                ? [parameterIndex]
                : [],
          );
          if (parameterIndexes.length === 0) continue;
          const sinkPattern = model.sinks.find(
            (pattern) => pattern.kind === sink.kind,
          );
          if (sinkPattern === undefined) continue;
          const wrapperControls = [
            ...controls.filter(
              (control) =>
                nodeHttpGeneralControlApplies(nodeHttpSink, control.kind) &&
                filesystemPathWrapperControlApplies(
                  model.id,
                  control,
                  controls,
                  wrapper.startLine,
                  wrapper.endLine,
                ),
            ),
            ...(model.id === "node-http-ssrf" && nodeHttpSink !== undefined
              ? nodeAxiosConfigurationControls(
                  file.lines,
                  nodeHttpSink,
                  model.controls,
                )
              : []),
            ...(model.id === "node-http-object-authorization" &&
            nodeObjectSink !== undefined
              ? nodeObjectAuthorizationControls(
                  file.lines,
                  nodeObjectSink,
                  wrapper.endLine,
                )
              : []),
            ...(model.id === "node-http-mongoose-nosql" &&
            nodeMongooseSink !== undefined
              ? nodeMongooseNoSqlControls(
                  file.lines,
                  nodeMongooseSink,
                  sink.line,
                )
              : []),
            ...(model.id === "node-http-mongoose-update" &&
            nodeMongooseUpdate !== undefined
              ? nodeMongooseUpdateControls(
                  file.lines,
                  nodeMongooseUpdate,
                  sink.line,
                )
              : []),
            ...(model.id === "node-http-mongoose-bulk-write" &&
            nodeMongooseBulkWrite !== undefined
              ? nodeMongooseBulkWriteControls(
                  file.lines,
                  nodeMongooseBulkWrite,
                  sink.line,
                )
              : []),
          ].filter(
            (control, index, all) =>
              all.findIndex(
                (candidate) =>
                  candidate.kind === control.kind &&
                  candidate.line === control.line,
              ) === index,
          );
          for (const parameterIndex of parameterIndexes) {
            const copilotInput = nodeCopilotSink?.inputs.find(
              ({ expression }) =>
                lineReferencesIdentifier(
                  expression,
                  wrapper.parameters[parameterIndex]!,
                ),
            );
            summaries.push({
              model,
              file,
              symbol: wrapper.symbol,
              parameter: wrapper.parameters[parameterIndex]!,
              parameterIndex,
              declarationLine: wrapper.startLine,
              sink: {
                ...sink,
                ...(copilotInput === undefined
                  ? {}
                  : { kind: copilotInput.kind, line: copilotInput.line }),
                cweIds: sinkPattern.cweIds,
              },
              controls: wrapperControls.slice(0, 8),
            });
          }
        }
      }
    }
  }
  return summaries;
}

function pythonFrameworkWrapperSummaries(
  files: readonly SourceFileSnapshot[],
): FrameworkWrapperSummary[] {
  const summaries: FrameworkWrapperSummary[] = [];
  for (const file of files) {
    if (!PYTHON_EXTENSIONS.has(file.extension)) continue;
    const exportedFunctions = exportedPythonFunctions(file.lines);
    if (exportedFunctions.length === 0) continue;
    const structuralText = pythonStructuralLines(file.lines).join("\n");
    for (const model of FRAMEWORK_DATAFLOW_MODELS) {
      if (
        !model.extensions.has(file.extension) ||
        !model.activation.some((expression) => expression.test(structuralText))
      ) {
        continue;
      }
      const sinks =
        model.id === "python-web-path"
          ? exactFilesystemPathSinkLines(file.lines, model.id, 32)
          : matchingPythonModelLines(file.lines, model.sinks, 32);
      const controls = matchingPythonModelLines(file.lines, model.controls, 64);
      for (const wrapper of exportedFunctions) {
        for (const sink of sinks) {
          if (sink.line < wrapper.startLine || sink.line > wrapper.endLine) {
            continue;
          }
          const sinkExpression = pythonCallExpression(
            file.lines,
            sink.line,
            wrapper.endLine,
          );
          const pythonPathSink =
            model.id === "python-web-path"
              ? pythonFilesystemPathSink(file.lines, sink.line)
              : undefined;
          if (model.id === "python-web-path" && pythonPathSink === undefined) {
            continue;
          }
          const tracedSinkExpression =
            pythonPathSink?.expressions
              .map(
                (expression) =>
                  resolvePythonExpression(file.lines, expression, sink.line) ??
                  expression,
              )
              .join("\n") ?? sinkExpression;
          const parameterIndexes = wrapper.parameters.flatMap(
            (parameter, parameterIndex) =>
              pythonLineReferencesIdentifier(tracedSinkExpression, parameter)
                ? [parameterIndex]
                : [],
          );
          if (parameterIndexes.length === 0) continue;
          const sinkPattern = model.sinks.find(
            (pattern) => pattern.kind === sink.kind,
          );
          if (sinkPattern === undefined) continue;
          const sinkControls = model.controls
            .filter((control) => control.expression.test(sinkExpression))
            .map((control) => ({ kind: control.kind, line: sink.line }));
          const wrapperControls = [
            ...sinkControls,
            ...controls.filter((control) =>
              filesystemPathWrapperControlApplies(
                model.id,
                control,
                controls,
                wrapper.startLine,
                wrapper.endLine,
              ),
            ),
          ].filter(
            (control, index, all) =>
              all.findIndex(
                (candidate) =>
                  candidate.kind === control.kind &&
                  candidate.line === control.line,
              ) === index,
          );
          for (const parameterIndex of parameterIndexes) {
            summaries.push({
              model,
              file,
              symbol: wrapper.symbol,
              parameter: wrapper.parameters[parameterIndex]!,
              parameterIndex,
              declarationLine: wrapper.startLine,
              sink: { ...sink, cweIds: sinkPattern.cweIds },
              controls: wrapperControls.slice(0, 8),
            });
          }
        }
      }
    }
  }
  return summaries;
}

function javaFrameworkWrapperSummaries(
  files: readonly SourceFileSnapshot[],
): FrameworkWrapperSummary[] {
  const summaries: FrameworkWrapperSummary[] = [];
  for (const file of files) {
    if (file.extension !== ".java") continue;
    const methods = exportedJavaMethods(file.lines);
    if (methods.length === 0) continue;
    const structuralText = cFamilyStructuralLines(file.lines).join("\n");
    for (const model of FRAMEWORK_DATAFLOW_MODELS) {
      if (
        !model.extensions.has(file.extension) ||
        !model.activation.some((expression) => expression.test(structuralText))
      ) {
        continue;
      }
      const sinks = matchingJavaModelLines(file.lines, model.sinks, 32);
      const controls =
        model.id === "spring-http-object-authorization" ||
        model.id === "spring-mvc-jpa-mass-assignment"
          ? []
          : matchingJavaModelLines(file.lines, model.controls, 64);
      for (const method of methods) {
        for (const sink of sinks) {
          if (sink.line < method.startLine || sink.line > method.endLine) {
            continue;
          }
          const sinkExpression = javaCallExpression(
            file.lines,
            sink.line,
            method.endLine,
          );
          const parameterSinkExpression =
            model.id === "spring-http-ssrf"
              ? javaOutboundDestinationArgument(
                  javaOutboundCallExpression(
                    file.lines,
                    sink.line,
                    method.endLine,
                  ),
                )
              : sinkExpression;
          if (
            model.id === "spring-http-ssrf" &&
            !javaOutboundHttpSinkHasTypedReceiver(file.lines, sink.line)
          ) {
            continue;
          }
          if (
            model.id === "spring-http-path" &&
            !javaFilesystemSinkHasTypedReceiver(file.lines, sink.line)
          ) {
            continue;
          }
          const objectAuthorizationSink =
            model.id === "spring-http-object-authorization"
              ? javaObjectAuthorizationSink(
                  file.lines,
                  sink.line,
                  method.endLine,
                )
              : undefined;
          const massAssignmentSink =
            model.id === "spring-mvc-jpa-mass-assignment"
              ? javaJpaPersistenceSink(file.lines, sink.line, method.endLine)
              : undefined;
          const persistedDomainType =
            massAssignmentSink === undefined
              ? undefined
              : javaSpringDataRepositoryDomainType(
                  files,
                  file.path,
                  file.lines,
                  massAssignmentSink.receiver,
                );
          if (
            model.id === "spring-http-object-authorization" &&
            (objectAuthorizationSink === undefined ||
              !javaSpringDataLookupHasTypedReceiver(
                files,
                file.path,
                file.lines,
                objectAuthorizationSink,
              ))
          ) {
            continue;
          }
          if (
            model.id === "spring-mvc-jpa-mass-assignment" &&
            (massAssignmentSink === undefined ||
              persistedDomainType === undefined ||
              !javaJpaEntityTypeExists(files, file.path, persistedDomainType))
          ) {
            continue;
          }
          const parameterIndexes =
            model.id === "spring-http-object-authorization"
              ? javaMethodParameterIndexesReachingSink(
                  file.lines,
                  method,
                  sink.line,
                  objectAuthorizationSink!.argument,
                )
              : model.id === "spring-mvc-jpa-mass-assignment"
                ? javaMethodParameterIndexesReachingSink(
                    file.lines,
                    method,
                    sink.line,
                    massAssignmentSink!.argument,
                  ).filter(
                    (parameterIndex) =>
                      javaParameterSimpleType(
                        method.parameters[parameterIndex]!,
                      ) === persistedDomainType,
                  )
                : model.id === "spring-http-path" ||
                    model.id === "spring-http-ssrf"
                  ? javaMethodParameterIndexesReachingSink(
                      file.lines,
                      method,
                      sink.line,
                      parameterSinkExpression,
                    )
                  : method.parameters.flatMap((parameter, parameterIndex) =>
                      cFamilyLineReferencesIdentifier(
                        sinkExpression,
                        parameter.name,
                      )
                        ? [parameterIndex]
                        : [],
                    );
          if (parameterIndexes.length === 0) continue;
          const sinkPattern = model.sinks.find(
            (pattern) => pattern.kind === sink.kind,
          );
          if (sinkPattern === undefined) continue;
          const sinkControls =
            model.id === "spring-http-object-authorization" ||
            model.id === "spring-mvc-jpa-mass-assignment"
              ? []
              : model.controls
                  .filter((control) => control.expression.test(sinkExpression))
                  .map((control) => ({ kind: control.kind, line: sink.line }));
          const methodControls = [
            ...sinkControls,
            ...(model.id === "spring-http-object-authorization" &&
            objectAuthorizationSink !== undefined
              ? javaObjectAuthorizationControls(
                  files,
                  file.path,
                  file.lines,
                  objectAuthorizationSink,
                  method,
                )
              : []),
            ...controls.filter(
              (control) =>
                control.line >= method.startLine &&
                control.line <= method.endLine,
            ),
          ].filter(
            (control, index, all) =>
              all.findIndex(
                (candidate) =>
                  candidate.kind === control.kind &&
                  candidate.line === control.line,
              ) === index,
          );
          for (const parameterIndex of parameterIndexes) {
            summaries.push({
              model,
              file,
              ownerType: method.ownerType,
              symbol: method.symbol,
              parameter: method.parameters[parameterIndex]!.name,
              parameterIndex,
              parameterCount: method.parameters.length,
              ...(persistedDomainType === undefined
                ? {}
                : { valueType: persistedDomainType }),
              declarationLine: method.startLine,
              sink: { ...sink, cweIds: sinkPattern.cweIds },
              controls: methodControls.slice(0, 8),
            });
          }
        }
      }
    }
  }
  return summaries;
}

function dotnetFrameworkWrapperSummaries(
  files: readonly SourceFileSnapshot[],
): FrameworkWrapperSummary[] {
  const summaries: FrameworkWrapperSummary[] = [];
  for (const file of files) {
    if (file.extension !== ".cs") continue;
    const methods = exportedDotnetMethods(file.lines);
    if (methods.length === 0) continue;
    const structuralText = cFamilyStructuralLines(file.lines).join("\n");
    for (const model of FRAMEWORK_DATAFLOW_MODELS) {
      if (
        !model.extensions.has(file.extension) ||
        !model.activation.some((expression) => expression.test(structuralText))
      ) {
        continue;
      }
      const sinks = matchingJavaModelLines(file.lines, model.sinks, 32);
      const controls =
        model.id === "aspnet-http-object-authorization"
          ? []
          : matchingJavaModelLines(file.lines, model.controls, 64);
      for (const method of methods) {
        for (const sink of sinks) {
          if (sink.line < method.startLine || sink.line > method.endLine) {
            continue;
          }
          const sinkExpression = javaCallExpression(
            file.lines,
            sink.line,
            method.endLine,
          );
          if (
            model.id === "aspnet-http-ssrf" &&
            !dotnetHttpClientSinkHasTypedReceiver(file.lines, sink.line)
          ) {
            continue;
          }
          if (
            model.id === "aspnet-http-path" &&
            !dotnetFilesystemSinkHasTypedReceiver(
              file.lines,
              sink.line,
              dotnetProjectProvidesSystemIo(files, file.path),
            )
          ) {
            continue;
          }
          const objectAuthorizationSink =
            model.id === "aspnet-http-object-authorization"
              ? dotnetObjectAuthorizationSink(
                  file.lines,
                  sink.line,
                  method.endLine,
                )
              : undefined;
          if (
            model.id === "aspnet-http-object-authorization" &&
            (objectAuthorizationSink === undefined ||
              !dotnetEfObjectLookupHasTypedReceiver(
                file.lines,
                objectAuthorizationSink,
              ))
          ) {
            continue;
          }
          const templateSourceArgument =
            model.id === "aspnet-http-template-injection"
              ? dotnetTemplateSourceArgument(
                  file.lines,
                  sink.line,
                  method.endLine,
                )
              : undefined;
          if (
            model.id === "aspnet-http-template-injection" &&
            templateSourceArgument === undefined
          ) {
            continue;
          }
          const parameterIndexes =
            model.id === "aspnet-http-template-injection"
              ? dotnetMethodParameterIndexesReachingExpression(
                  file.lines,
                  method,
                  sink.line,
                  templateSourceArgument!,
                )
              : model.id === "aspnet-http-object-authorization"
                ? dotnetMethodParameterIndexesReachingExpression(
                    file.lines,
                    method,
                    sink.line,
                    objectAuthorizationSink!.argument,
                  )
                : method.parameters.flatMap((parameter, parameterIndex) =>
                    cFamilyLineReferencesIdentifier(
                      sinkExpression,
                      parameter.name,
                    )
                      ? [parameterIndex]
                      : [],
                  );
          if (parameterIndexes.length === 0) continue;
          const sinkPattern = model.sinks.find(
            (pattern) => pattern.kind === sink.kind,
          );
          if (sinkPattern === undefined) continue;
          const sinkControls =
            model.id === "aspnet-http-object-authorization"
              ? []
              : model.controls
                  .filter((control) => control.expression.test(sinkExpression))
                  .map((control) => ({ kind: control.kind, line: sink.line }));
          const methodControls = [
            ...sinkControls,
            ...(model.id === "aspnet-http-object-authorization" &&
            objectAuthorizationSink !== undefined
              ? dotnetObjectAuthorizationControls(
                  file.lines,
                  objectAuthorizationSink,
                  method.endLine,
                )
              : []),
            ...controls.filter(
              (control) =>
                control.line >= method.startLine &&
                control.line <= method.endLine,
            ),
          ].filter(
            (control, index, all) =>
              all.findIndex(
                (candidate) =>
                  candidate.kind === control.kind &&
                  candidate.line === control.line,
              ) === index,
          );
          for (const parameterIndex of parameterIndexes) {
            summaries.push({
              model,
              file,
              ownerType: method.ownerType,
              symbol: method.symbol,
              parameter: method.parameters[parameterIndex]!.name,
              parameterIndex,
              parameterCount: method.parameters.length,
              declarationLine: method.startLine,
              sink: { ...sink, cweIds: sinkPattern.cweIds },
              controls: methodControls.slice(0, 8),
            });
          }
        }
      }
    }
  }
  return summaries;
}

function pythonCallExpression(
  lines: readonly string[],
  startLine: number,
  functionEndLine: number,
): string {
  const endLine = Math.min(functionEndLine, startLine + 12);
  const firstLine = lines[startLine - 1] ?? "";
  const structuralFirstLine = pythonStructuralCode(firstLine);
  const open = structuralFirstLine.indexOf("(");
  if (open < 0) return firstLine;
  const joined = lines.slice(startLine - 1, endLine).join("\n");
  const close = matchingCallParenthesis(joined, open);
  return (close < 0 ? joined : joined.slice(0, close + 1)).replace(
    /\s+/gu,
    " ",
  );
}

function javaCallExpression(
  lines: readonly string[],
  startLine: number,
  methodEndLine: number,
): string {
  const endLine = Math.min(methodEndLine, startLine + 12);
  const callLines = lines.slice(startLine - 1, endLine);
  const original = callLines.join("\n");
  const structural = cFamilyStructuralLines(callLines).join("\n");
  let open = structural.indexOf("(");
  const bodyStart = structural.indexOf("{");
  const startsWithMethodDeclaration =
    /^\s*(?:(?:\[[^\]]+\]|@[A-Za-z_$][\w$.]*(?:\([^)]*\))?)\s*)*(?:public|protected|private|internal)\b/u.test(
      structural,
    );
  if (
    startsWithMethodDeclaration &&
    bodyStart >= 0 &&
    open >= 0 &&
    open < bodyStart
  ) {
    const bodyCall = structural.indexOf("(", bodyStart + 1);
    if (bodyCall >= 0) open = bodyCall;
  }
  if (open < 0) return original;
  const close = matchingCallParenthesis(structural, open);
  return (close < 0 ? original : original.slice(0, close + 1)).replace(
    /\s+/gu,
    " ",
  );
}

function javaOutboundCallExpression(
  lines: readonly string[],
  startLine: number,
  methodEndLine: number,
): string {
  const endLine = Math.min(methodEndLine, startLine + 12);
  const callLines = lines.slice(startLine - 1, endLine);
  const original = callLines.join("\n");
  const structural = cFamilyStructuralLines(callLines).join("\n");
  const call =
    /\.\s*(?:send|sendAsync|uri|url|delete|exchange|execute|getForEntity|getForObject|headForHeaders|optionsForAllow|patchForObject|postForEntity|postForLocation|postForObject|put)\s*\(/u.exec(
      structural,
    );
  if (call === null) return javaCallExpression(lines, startLine, methodEndLine);
  const open = structural.indexOf("(", call.index);
  const close = matchingCallParenthesis(structural, open);
  return (
    close < 0
      ? original.slice(call.index)
      : original.slice(call.index, close + 1)
  ).replace(/\s+/gu, " ");
}

function javaOutboundDestinationArgument(callExpression: string): string {
  const structural = cFamilyStructuralLines(
    callExpression.split(/\r?\n/u),
  ).join("\n");
  const open = structural.indexOf("(");
  const close = matchingCallParenthesis(structural, open);
  if (open < 0 || close < 0) return callExpression;
  return (
    splitJavascriptArguments(callExpression.slice(open + 1, close))[0] ?? ""
  );
}

function javaOwnerType(lines: readonly string[]): string | undefined {
  const structuralLines = cFamilyStructuralLines(lines);
  for (const line of structuralLines) {
    const match = /\b(?:class|record)\s+([A-Z][A-Za-z0-9_$]*)\b/u.exec(line);
    if (match !== null) return match[1]!;
  }
  return undefined;
}

function javaMethodDeclarations(
  lines: readonly string[],
): JavaMethodDeclaration[] {
  const ownerType = javaOwnerType(lines);
  if (ownerType === undefined) return [];
  const methods: JavaMethodDeclaration[] = [];
  const structuralLines = cFamilyStructuralLines(lines);
  const blockContext = javaLexicalBlockContext(structuralLines);
  const expression =
    /^\s*(?:(?:@[A-Za-z_$][\w$.]*(?:\([^)]*\))?)\s*)*(?:(public|protected|private)\s+)?(?:(?:default|final|native|static|strictfp|synchronized)\s+)*(?:<[^>]+>\s+)?([A-Za-z_$][\w$.[\]<>?,]*(?:\s*\[\s*\])?)\s+([A-Za-z_$][\w$]*)\s*\(([\s\S]*?)\)\s*(?:throws\s+[^{}]+)?\s*\{/u;
  for (let index = 0; index < lines.length; index += 1) {
    const depth = (blockContext.paths[index] ?? "")
      .split(".")
      .filter(Boolean).length;
    if (depth !== 1) continue;
    const declarationLines = lines.slice(
      index,
      Math.min(lines.length, index + 9),
    );
    const structuralDeclaration =
      cFamilyStructuralLines(declarationLines).join(" ");
    const match = expression.exec(structuralDeclaration);
    if (match === null || match[3] === ownerType) continue;
    const originalDeclaration = declarationLines.join(" ");
    const methodCall = new RegExp(
      `\\b${escapeRegularExpression(match[3]!)}\\s*\\(`,
      "u",
    ).exec(cFamilyStructuralLines([originalDeclaration])[0] ?? "");
    const originalOpen =
      methodCall === null
        ? -1
        : originalDeclaration.indexOf("(", methodCall.index);
    const originalClose = matchingCallParenthesis(
      originalDeclaration,
      originalOpen,
    );
    if (originalOpen < 0 || originalClose < 0) continue;
    const parameters = splitJavascriptArguments(
      originalDeclaration.slice(originalOpen + 1, originalClose),
    ).flatMap((declaration) => {
      const name = /([A-Za-z_$][\w$]*)\s*(?:\[\s*\])?\s*$/u.exec(
        declaration.trim(),
      )?.[1];
      return name === undefined
        ? []
        : [{ name, declaration: declaration.trim() }];
    });
    const declaration: JavaMethodDeclaration = {
      ownerType,
      symbol: match[3]!,
      access:
        match[1] === "public" ||
        match[1] === "protected" ||
        match[1] === "private"
          ? match[1]
          : "package",
      isStatic: /\bstatic\b/u.test(structuralDeclaration),
      returnType: match[2]!.replace(/\s*\.\s*/gu, ".").trim(),
      parameters,
      startLine: index + 1,
      endLine: cFamilyFunctionEndLine(structuralLines, index),
    };
    const duplicateIndex = methods.findIndex(
      (candidate) =>
        candidate.symbol === declaration.symbol &&
        candidate.returnType === declaration.returnType &&
        candidate.endLine === declaration.endLine &&
        candidate.parameters.length === declaration.parameters.length &&
        candidate.parameters.every(
          (parameter, parameterIndex) =>
            parameter.declaration ===
            declaration.parameters[parameterIndex]?.declaration,
        ),
    );
    if (duplicateIndex < 0) methods.push(declaration);
    else methods[duplicateIndex] = declaration;
  }
  return methods;
}

function exportedJavaMethods(lines: readonly string[]): ExportedJavaMethod[] {
  const ownerType = javaOwnerType(lines);
  if (ownerType === undefined) return [];
  const methods: ExportedJavaMethod[] = [];
  const structuralLines = cFamilyStructuralLines(lines);
  const expression =
    /^\s*(?:(?:@[A-Za-z_$][\w$.]*(?:\([^)]*\))?)\s*)*(?:public|protected)\s+(?:(?:default|final|native|static|synchronized)\s+)*(?:<[^>]+>\s+)?(?:[A-Za-z_$][\w$.[\]<>?,]*\s+)+([A-Za-z_$][\w$]*)\s*\(([\s\S]*?)\)\s*(?:throws\s+[^{}]+)?\s*\{/u;
  for (let index = 0; index < lines.length; index += 1) {
    const firstLine = structuralLines[index] ?? "";
    if (!/\b(?:public|protected)\b/u.test(firstLine)) continue;
    const declarationLines = lines.slice(
      index,
      Math.min(lines.length, index + 9),
    );
    const structuralDeclaration =
      cFamilyStructuralLines(declarationLines).join(" ");
    const match = expression.exec(structuralDeclaration);
    if (match === null || match[1] === ownerType) continue;
    const originalDeclaration = declarationLines.join(" ");
    const methodCall = new RegExp(
      `\\b${escapeRegularExpression(match[1]!)}\\s*\\(`,
      "u",
    ).exec(cFamilyStructuralLines([originalDeclaration])[0] ?? "");
    const originalOpen =
      methodCall === null
        ? -1
        : originalDeclaration.indexOf("(", methodCall.index);
    const originalClose = matchingCallParenthesis(
      originalDeclaration,
      originalOpen,
    );
    if (originalOpen < 0 || originalClose < 0) continue;
    const parameters = splitJavascriptArguments(
      originalDeclaration.slice(originalOpen + 1, originalClose),
    ).flatMap((declaration) => {
      const name = /([A-Za-z_$][\w$]*)\s*(?:\[\s*\])?\s*$/u.exec(
        declaration.trim(),
      )?.[1];
      return name === undefined
        ? []
        : [{ name, declaration: declaration.trim() }];
    });
    if (parameters.length === 0) continue;
    methods.push({
      ownerType,
      symbol: match[1]!,
      parameters,
      startLine: index + 1,
      endLine: cFamilyFunctionEndLine(structuralLines, index),
    });
  }
  return methods;
}

function dotnetOwnerType(lines: readonly string[]): string | undefined {
  const structuralLines = cFamilyStructuralLines(lines);
  for (const line of structuralLines) {
    const match = /\b(?:class|record|struct)\s+([A-Z_][A-Za-z0-9_]*)\b/u.exec(
      line,
    );
    if (match !== null) return match[1]!;
  }
  return undefined;
}

function exportedDotnetMethods(
  lines: readonly string[],
): ExportedDotnetMethod[] {
  const ownerType = dotnetOwnerType(lines);
  if (ownerType === undefined) return [];
  const methods: ExportedDotnetMethod[] = [];
  const structuralLines = cFamilyStructuralLines(lines);
  const expression =
    /^\s*(?:(?:\[[^\]]+\])\s*)*(?:public|protected|internal)\s+(?:(?:abstract|async|extern|new|override|sealed|static|unsafe|virtual)\s+)*(?:[A-Za-z_][\w.[\]<>?,]*\s+)+([A-Za-z_]\w*)\s*\(([\s\S]*?)\)\s*(?:where\s+[^{}]+)?\s*\{/u;
  for (let index = 0; index < lines.length; index += 1) {
    const firstLine = structuralLines[index] ?? "";
    if (!/\b(?:public|protected|internal)\b/u.test(firstLine)) continue;
    const declarationLines = lines.slice(
      index,
      Math.min(lines.length, index + 9),
    );
    const structuralDeclaration =
      cFamilyStructuralLines(declarationLines).join(" ");
    const match = expression.exec(structuralDeclaration);
    if (match === null || match[1] === ownerType) continue;
    const access = /\b(public|protected|internal)\b/u.exec(
      structuralDeclaration,
    )?.[1] as ExportedDotnetMethod["access"] | undefined;
    if (access === undefined) continue;
    const originalDeclaration = declarationLines.join(" ");
    const methodCall = new RegExp(
      `\\b${escapeRegularExpression(match[1]!)}\\s*\\(`,
      "u",
    ).exec(cFamilyStructuralLines([originalDeclaration])[0] ?? "");
    const originalOpen =
      methodCall === null
        ? -1
        : originalDeclaration.indexOf("(", methodCall.index);
    const originalClose = matchingCallParenthesis(
      originalDeclaration,
      originalOpen,
    );
    if (originalOpen < 0 || originalClose < 0) continue;
    const parameters = splitJavascriptArguments(
      originalDeclaration.slice(originalOpen + 1, originalClose),
    ).flatMap((declaration) => {
      const name = /([A-Za-z_]\w*)\s*$/u.exec(declaration.trim())?.[1];
      return name === undefined
        ? []
        : [{ name, declaration: declaration.trim() }];
    });
    methods.push({
      ownerType,
      symbol: match[1]!,
      access,
      isStatic: /\bstatic\b/u.test(structuralDeclaration),
      parameters,
      startLine: index + 1,
      endLine: cFamilyFunctionEndLine(structuralLines, index),
    });
  }
  return methods;
}

function cFamilyFunctionEndLine(
  structuralLines: readonly string[],
  startIndex: number,
): number {
  let depth = 0;
  let opened = false;
  const maximum = Math.min(
    structuralLines.length,
    startIndex + MAX_WRAPPER_FUNCTION_LINES,
  );
  for (let index = startIndex; index < maximum; index += 1) {
    for (const character of structuralLines[index] ?? "") {
      if (character === "{") {
        depth += 1;
        opened = true;
      } else if (character === "}" && opened) {
        depth -= 1;
      }
    }
    if (opened && depth <= 0) return index + 1;
  }
  return Math.min(structuralLines.length, startIndex + 1);
}

const EXPORTED_PYTHON_FUNCTIONS_CACHE = new WeakMap<
  readonly string[],
  ExportedPythonFunction[]
>();

function exportedPythonFunctions(
  lines: readonly string[],
): ExportedPythonFunction[] {
  const cached = EXPORTED_PYTHON_FUNCTIONS_CACHE.get(lines);
  if (cached !== undefined) return cached;
  const functions: ExportedPythonFunction[] = [];
  const structuralLines = pythonStructuralLines(lines);
  const expression =
    /^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:->\s*[^:]+)?\s*:/u;
  for (let index = 0; index < lines.length; index += 1) {
    const line = structuralLines[index] ?? "";
    if (/^\s/u.test(line)) continue;
    const match = expression.exec(line);
    if (match === null || match[1]!.startsWith("_")) continue;
    const parameters = splitPythonArguments(match[2] ?? "")
      .map((parameter) =>
        parameter
          .trim()
          .replace(/^\*{1,2}/u, "")
          .replace(/\s*=.*$/u, "")
          .replace(/\s*:\s*.*$/u, "")
          .trim(),
      )
      .filter((parameter) => /^[A-Za-z_]\w*$/u.test(parameter));
    if (parameters.length === 0) continue;
    functions.push({
      symbol: match[1]!,
      parameters,
      startLine: index + 1,
      endLine: pythonFunctionEndLine(lines, index),
    });
  }
  EXPORTED_PYTHON_FUNCTIONS_CACHE.set(lines, functions);
  return functions;
}

function pythonFunctionEndLine(
  lines: readonly string[],
  startIndex: number,
): number {
  const maximum = Math.min(
    lines.length,
    startIndex + MAX_WRAPPER_FUNCTION_LINES,
  );
  let lastBodyLine = startIndex + 1;
  for (let index = startIndex + 1; index < maximum; index += 1) {
    const line = lines[index] ?? "";
    const code = pythonCodeBeforeComment(line);
    if (code.trim() === "") continue;
    if (!/^\s/u.test(code)) return Math.max(startIndex + 1, lastBodyLine);
    lastBodyLine = index + 1;
  }
  return Math.min(lines.length, Math.max(startIndex + 1, lastBodyLine));
}

const EXPORTED_JAVASCRIPT_FUNCTIONS_CACHE = new WeakMap<
  readonly string[],
  ExportedJavascriptFunction[]
>();

function exportedJavascriptFunctions(
  lines: readonly string[],
): ExportedJavascriptFunction[] {
  const cached = EXPORTED_JAVASCRIPT_FUNCTIONS_CACHE.get(lines);
  if (cached !== undefined) return cached;
  const functions: ExportedJavascriptFunction[] = [];
  const structuralLines = javascriptStructuralLines(lines);
  const patterns = [
    /^\s*export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{/u,
    /^\s*export\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/u,
    /^\s*(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function(?:\s+[A-Za-z_$][\w$]*)?\s*\(([^)]*)\)\s*\{/u,
    /^\s*export\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?([A-Za-z_$][\w$]*)\s*=>/u,
  ];
  for (let index = 0; index < lines.length; index += 1) {
    const firstLine = structuralLines[index] ?? "";
    if (firstLine.trim() === "") continue;
    const declaration = structuralLines
      .slice(index, Math.min(lines.length, index + 13))
      .join("\n");
    const match = patterns
      .map((pattern) => pattern.exec(declaration))
      .find((candidate) => candidate !== null);
    if (match === undefined || match === null) continue;
    const parameters = (match[2] ?? "")
      .split(",")
      .map((parameter) =>
        parameter
          .trim()
          .replace(/\s*=.*$/u, "")
          .replace(/\??\s*:\s*.*$/u, "")
          .trim(),
      )
      .filter((parameter) => /^[A-Za-z_$][\w$]*$/u.test(parameter));
    if (parameters.length === 0) continue;
    functions.push({
      symbol: match[1]!,
      parameters,
      startLine: index + 1,
      endLine: javascriptFunctionEndLine(lines, index),
    });
  }
  EXPORTED_JAVASCRIPT_FUNCTIONS_CACHE.set(lines, functions);
  return functions;
}

function javascriptFunctionEndLine(
  lines: readonly string[],
  startIndex: number,
): number {
  let depth = 0;
  let opened = false;
  const maximum = Math.min(
    lines.length,
    startIndex + MAX_WRAPPER_FUNCTION_LINES,
  );
  for (let index = startIndex; index < maximum; index += 1) {
    const line = stripJavascriptStringsAndComments(lines[index] ?? "");
    for (const character of line) {
      if (character === "{") {
        depth += 1;
        opened = true;
      } else if (character === "}" && opened) {
        depth -= 1;
      }
    }
    if (opened && depth <= 0) return index + 1;
  }
  return Math.min(lines.length, startIndex + 1);
}

function stripJavascriptStringsAndComments(line: string): string {
  return line
    .replace(/\/\/.*$/u, "")
    .replace(/'(?:\\.|[^'\\])*'/gu, "''")
    .replace(/"(?:\\.|[^"\\])*"/gu, '""')
    .replace(/`(?:\\.|[^`\\])*`/gu, "``");
}

function javascriptCodeBeforeComment(line: string): string {
  let quote = "";
  let escaped = false;
  for (let index = 0; index < line.length - 1; index += 1) {
    const character = line[index]!;
    if (quote !== "") {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      continue;
    }
    if (character === '"' || character === "'" || character === "`") {
      quote = character;
    } else if (character === "/" && line[index + 1] === "/") {
      return line.slice(0, index);
    }
  }
  return line;
}

const JAVASCRIPT_CODE_LINES_CACHE = new WeakMap<readonly string[], string[]>();

function javascriptCodeLinesWithoutComments(
  lines: readonly string[],
): string[] {
  const cached = JAVASCRIPT_CODE_LINES_CACHE.get(lines);
  if (cached !== undefined) return cached;
  const result: string[] = [];
  let blockComment = false;
  for (const line of lines) {
    const output = [...line];
    let quote = "";
    let escaped = false;
    for (let index = 0; index < output.length; index += 1) {
      const character = line[index]!;
      const next = line[index + 1] ?? "";
      if (blockComment) {
        output[index] = " ";
        if (character === "*" && next === "/") {
          if (index + 1 < output.length) output[index + 1] = " ";
          index += 1;
          blockComment = false;
        }
        continue;
      }
      if (quote !== "") {
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === quote) quote = "";
        continue;
      }
      if (character === "/" && next === "*") {
        output[index] = " ";
        if (index + 1 < output.length) output[index + 1] = " ";
        index += 1;
        blockComment = true;
      } else if (character === "/" && next === "/") {
        output.fill(" ", index);
        break;
      } else if (character === '"' || character === "'" || character === "`") {
        quote = character;
      }
    }
    result.push(output.join(""));
  }
  JAVASCRIPT_CODE_LINES_CACHE.set(lines, result);
  return result;
}

const JAVASCRIPT_STRUCTURAL_LINES_CACHE = new WeakMap<
  readonly string[],
  string[]
>();

function javascriptStructuralLines(lines: readonly string[]): string[] {
  const cached = JAVASCRIPT_STRUCTURAL_LINES_CACHE.get(lines);
  if (cached !== undefined) return cached;
  const structural = javascriptCodeLinesWithoutComments(lines).map((line) =>
    javascriptStructuralCode(line),
  );
  JAVASCRIPT_STRUCTURAL_LINES_CACHE.set(lines, structural);
  return structural;
}

function javascriptStructuralCode(line: string): string {
  const output = [...line];
  let quote = "";
  let escaped = false;
  for (let index = 0; index < output.length; index += 1) {
    const character = line[index]!;
    if (quote !== "") {
      output[index] = " ";
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      continue;
    }
    if (character === '"' || character === "'" || character === "`") {
      quote = character;
      output[index] = " ";
    } else if (character === "/" && line[index + 1] === "/") {
      output.fill(" ", index);
      break;
    }
  }
  return output.join("");
}

function javascriptTemplateExpressionCode(line: string): string {
  const expressions: string[] = [];
  const code = javascriptCodeBeforeComment(line);
  for (const template of code.matchAll(/`(?:\\.|[^`\\])*`/gu)) {
    for (const expression of template[0].matchAll(/\$\{([^{}]*)\}/gu)) {
      expressions.push(expression[1] ?? "");
    }
  }
  return expressions.join("\n");
}

function cFamilyStructuralLines(lines: readonly string[]): string[] {
  const structural: string[] = [];
  let blockComment = false;
  for (const line of lines) {
    const output = [...line];
    let quote = "";
    let escaped = false;
    for (let index = 0; index < output.length; index += 1) {
      const character = line[index]!;
      const next = line[index + 1] ?? "";
      if (blockComment) {
        output[index] = " ";
        if (character === "*" && next === "/") {
          if (index + 1 < output.length) output[index + 1] = " ";
          index += 1;
          blockComment = false;
        }
        continue;
      }
      if (quote !== "") {
        output[index] = " ";
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === quote) quote = "";
        continue;
      }
      if (character === "/" && next === "*") {
        output[index] = " ";
        if (index + 1 < output.length) output[index + 1] = " ";
        index += 1;
        blockComment = true;
      } else if (character === "/" && next === "/") {
        output.fill(" ", index);
        break;
      } else if (character === '"' || character === "'") {
        quote = character;
        output[index] = " ";
      }
    }
    structural.push(output.join(""));
  }
  return structural;
}

function cFamilyLineReferencesIdentifier(
  value: string,
  identifier: string,
): boolean {
  const expression = new RegExp(
    `\\b${escapeRegularExpression(identifier)}\\b`,
    "u",
  );
  return expression.test(
    cFamilyStructuralLines(value.split(/\r?\n/u)).join("\n"),
  );
}

function pythonCodeBeforeComment(line: string): string {
  let quote = "";
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index]!;
    if (quote !== "") {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
    } else if (character === "#") {
      return line.slice(0, index);
    }
  }
  return line;
}

function pythonStructuralCode(line: string): string {
  return pythonStructuralLines([line])[0] ?? "";
}

const PYTHON_STRUCTURAL_LINES_CACHE = new WeakMap<
  readonly string[],
  string[]
>();

function pythonStructuralLines(lines: readonly string[]): string[] {
  const cached = PYTHON_STRUCTURAL_LINES_CACHE.get(lines);
  if (cached !== undefined) return cached;
  const structural: string[] = [];
  let tripleQuote = "";
  for (const line of lines) {
    const output = [...line];
    let quote = "";
    let escaped = false;
    for (let index = 0; index < output.length; index += 1) {
      const character = line[index]!;
      if (tripleQuote !== "") {
        output[index] = " ";
        if (line.startsWith(tripleQuote, index)) {
          for (let offset = 1; offset < tripleQuote.length; offset += 1) {
            if (index + offset < output.length) output[index + offset] = " ";
          }
          index += tripleQuote.length - 1;
          tripleQuote = "";
        }
        continue;
      }
      if (quote !== "") {
        output[index] = " ";
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === quote) quote = "";
        continue;
      }
      const possibleTriple = line.slice(index, index + 3);
      if (possibleTriple === '"""' || possibleTriple === "'''") {
        for (let offset = 0; offset < possibleTriple.length; offset += 1) {
          output[index + offset] = " ";
        }
        index += possibleTriple.length - 1;
        tripleQuote = possibleTriple;
      } else if (character === '"' || character === "'") {
        quote = character;
        output[index] = " ";
      } else if (character === "#") {
        output.fill(" ", index);
        break;
      }
    }
    structural.push(output.join(""));
  }
  PYTHON_STRUCTURAL_LINES_CACHE.set(lines, structural);
  return structural;
}

function pythonFormattedExpressionCode(line: string): string {
  const expressions: string[] = [];
  const code = pythonCodeBeforeComment(line);
  for (const formatted of code.matchAll(
    /(?:^|[^A-Za-z0-9_])(?:f|fr|rf)(["'])(.*?)\1/giu,
  )) {
    for (const expression of (formatted[2] ?? "").matchAll(/\{([^{}]*)\}/gu)) {
      expressions.push(expression[1] ?? "");
    }
  }
  return expressions.join("\n");
}

function pythonLineReferencesIdentifier(
  line: string,
  identifier: string,
): boolean {
  const expression = new RegExp(
    `\\b${escapeRegularExpression(identifier)}\\b`,
    "u",
  );
  return (
    expression.test(pythonStructuralCode(line)) ||
    expression.test(pythonFormattedExpressionCode(line))
  );
}

function importedJavascriptSymbols(
  lines: readonly string[],
): ImportedJavascriptSymbol[] {
  const imports: ImportedJavascriptSymbol[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const esm = /^\s*import\s*\{([^}]+)\}\s*from\s*["']([^"']+)["']/u.exec(
      line,
    );
    const commonjs =
      /^\s*(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*["']([^"']+)["']\s*\)/u.exec(
        line,
      );
    const match = esm ?? commonjs;
    if (match === null) continue;
    for (const rawBinding of (match[1] ?? "").split(",")) {
      const binding = rawBinding.trim();
      const parsed =
        /^([A-Za-z_$][\w$]*)(?:\s+as\s+|\s*:\s*)([A-Za-z_$][\w$]*)$/u.exec(
          binding,
        );
      const imported = parsed?.[1] ?? binding;
      const local = parsed?.[2] ?? binding;
      if (
        !/^[A-Za-z_$][\w$]*$/u.test(imported) ||
        !/^[A-Za-z_$][\w$]*$/u.test(local)
      ) {
        continue;
      }
      imports.push({
        imported,
        local,
        moduleSpecifier: match[2]!,
        line: index + 1,
      });
    }
  }
  return imports;
}

function importedPythonSymbols(
  lines: readonly string[],
): ImportedPythonSymbol[] {
  const imports: ImportedPythonSymbol[] = [];
  const structuralLines = pythonStructuralLines(lines);
  const expression =
    /^\s*from\s+(\.+[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s+import\s+([^#]+?)(?:\s+#.*)?$/u;
  for (let index = 0; index < lines.length; index += 1) {
    const match = expression.exec(structuralLines[index] ?? "");
    if (match === null) continue;
    for (const rawBinding of splitPythonArguments(match[2] ?? "")) {
      const binding = rawBinding.trim();
      const parsed = /^([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?$/u.exec(
        binding,
      );
      if (parsed === null) continue;
      imports.push({
        imported: parsed[1]!,
        local: parsed[2] ?? parsed[1]!,
        moduleSpecifier: match[1]!,
        line: index + 1,
      });
    }
  }
  return imports;
}

function pythonFastApiParameterSourceHasOfficialBinding(
  lines: readonly string[],
): boolean {
  return pythonStructuralLines(lines).some((line) =>
    /^\s*from\s+fastapi(?:\.params)?\s+import\s+[^#]*(?:\bBody\b|\bCookie\b|\bForm\b|\bHeader\b|\bPath\b|\bQuery\b)/u.test(
      line,
    ),
  );
}

function javascriptCallArgumentsAtLine(
  lines: readonly string[],
  line: number,
  callee: RegExp,
): string[] | undefined {
  const callLines = lines.slice(line - 1, Math.min(lines.length, line + 12));
  const original = javascriptCodeLinesWithoutComments(callLines).join("\n");
  const structural = javascriptStructuralLines(callLines).join("\n");
  const match = callee.exec(structural.split("\n", 1)[0] ?? "");
  if (match === null) return undefined;
  const open = structural.indexOf("(", match.index);
  const close = matchingCallParenthesis(structural, open);
  if (open < 0 || close < 0) return undefined;
  return splitJavascriptArguments(original.slice(open + 1, close));
}

interface NodeFilesystemBindingContext {
  wrappers: readonly ExportedJavascriptFunction[];
  namedBindings: readonly ImportedJavascriptSymbol[];
  receiverBindings: ReadonlyArray<{ local: string; line: number }>;
}

const NODE_FILESYSTEM_BINDING_CACHE = new WeakMap<
  readonly string[],
  NodeFilesystemBindingContext
>();

function nodeFilesystemBindingContext(
  lines: readonly string[],
): NodeFilesystemBindingContext {
  const cached = NODE_FILESYSTEM_BINDING_CACHE.get(lines);
  if (cached !== undefined) return cached;
  const fsModule = /^(?:node:)?fs(?:\/promises)?$/u;
  const namedBindings = importedJavascriptSymbols(lines).filter(
    (binding) =>
      fsModule.test(binding.moduleSpecifier) &&
      NODE_FILESYSTEM_PATH_ARGUMENTS.has(binding.imported),
  );
  const receiverBindings: Array<{ local: string; line: number }> = [];
  for (let index = 0; index < lines.length; index += 1) {
    const structural = javascriptCodeBeforeComment(lines[index] ?? "");
    const namespace =
      /^\s*import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+["']((?:node:)?fs(?:\/promises)?)["']/u.exec(
        structural,
      );
    const defaultImport =
      /^\s*import\s+([A-Za-z_$][\w$]*)\s+from\s+["']((?:node:)?fs(?:\/promises)?)["']/u.exec(
        structural,
      );
    const requireBinding =
      /^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["']((?:node:)?fs(?:\/promises)?)["']\s*\)(?:\s*\.\s*promises)?/u.exec(
        structural,
      );
    const promisesBinding =
      /^\s*import\s*\{\s*promises(?:\s+as\s+([A-Za-z_$][\w$]*))?\s*\}\s*from\s*["']((?:node:)?fs)["']/u.exec(
        structural,
      );
    const local =
      namespace?.[1] ??
      defaultImport?.[1] ??
      requireBinding?.[1] ??
      promisesBinding?.[1] ??
      (promisesBinding === null ? undefined : "promises");
    const moduleSpecifier =
      namespace?.[2] ??
      defaultImport?.[2] ??
      requireBinding?.[2] ??
      promisesBinding?.[2];
    if (local !== undefined && moduleSpecifier !== undefined) {
      receiverBindings.push({ local, line: index + 1 });
    }
  }
  const context = {
    wrappers: exportedJavascriptFunctions(lines),
    namedBindings,
    receiverBindings,
  } satisfies NodeFilesystemBindingContext;
  NODE_FILESYSTEM_BINDING_CACHE.set(lines, context);
  return context;
}

function nodeFilesystemPathSink(
  lines: readonly string[],
  line: number,
): FrameworkFilesystemPathSink | undefined {
  const context = nodeFilesystemBindingContext(lines);
  const wrapper = context.wrappers.find(
    (candidate) => line >= candidate.startLine && line <= candidate.endLine,
  );
  for (const binding of context.namedBindings) {
    if (
      binding.line >= line ||
      wrapper?.parameters.includes(binding.local) === true ||
      javascriptIdentifierReassignedBetween(
        lines,
        binding.local,
        binding.line,
        line,
      )
    ) {
      continue;
    }
    const arguments_ = javascriptCallArgumentsAtLine(
      lines,
      line,
      new RegExp(`\\b${escapeRegularExpression(binding.local)}\\s*\\(`, "u"),
    );
    if (arguments_ === undefined) continue;
    const positions = NODE_FILESYSTEM_PATH_ARGUMENTS.get(binding.imported)!;
    const expressions = positions.flatMap((position) =>
      arguments_[position]?.trim() ? [arguments_[position]!.trim()] : [],
    );
    if (expressions.length !== positions.length) continue;
    return { expressions, operation: binding.imported };
  }

  for (const binding of context.receiverBindings) {
    if (
      binding.line >= line ||
      wrapper?.parameters.includes(binding.local) === true ||
      javascriptIdentifierReassignedBetween(
        lines,
        binding.local,
        binding.line,
        line,
      )
    ) {
      continue;
    }
    for (const [operation, positions] of NODE_FILESYSTEM_PATH_ARGUMENTS) {
      const arguments_ = javascriptCallArgumentsAtLine(
        lines,
        line,
        new RegExp(
          `\\b${escapeRegularExpression(binding.local)}\\s*\\.\\s*(?:promises\\s*\\.\\s*)?${escapeRegularExpression(operation)}\\s*\\(`,
          "u",
        ),
      );
      if (arguments_ === undefined) continue;
      const expressions = positions.flatMap((position) =>
        arguments_[position]?.trim() ? [arguments_[position]!.trim()] : [],
      );
      if (expressions.length !== positions.length) continue;
      return { expressions, operation };
    }
  }

  for (const [operation, positions] of NODE_FILESYSTEM_PATH_ARGUMENTS) {
    const arguments_ = javascriptCallArgumentsAtLine(
      lines,
      line,
      new RegExp(
        `\\brequire\\s*\\(\\s*["'](?:node:)?fs(?:/promises)?["']\\s*\\)\\s*\\.\\s*(?:promises\\s*\\.\\s*)?${escapeRegularExpression(operation)}\\s*\\(`,
        "u",
      ),
    );
    if (arguments_ === undefined) continue;
    const expressions = positions.flatMap((position) =>
      arguments_[position]?.trim() ? [arguments_[position]!.trim()] : [],
    );
    if (expressions.length === positions.length) {
      return { expressions, operation };
    }
  }
  return undefined;
}

function exactFilesystemPathSinkLines(
  lines: readonly string[],
  modelId: string,
  limit: number,
): Array<{ kind: string; line: number }> {
  const sinks: Array<{ kind: string; line: number }> = [];
  const structuralLines =
    modelId === "node-http-path"
      ? javascriptStructuralLines(lines)
      : pythonStructuralLines(lines);
  const operations =
    modelId === "node-http-path"
      ? [...NODE_FILESYSTEM_PATH_ARGUMENTS.keys()]
      : [...PYTHON_FILESYSTEM_PATH_ARGUMENTS.keys()].map(
          (qualified) => qualified.split(".").at(-1)!,
        );
  const aliases = new Set<string>();
  if (modelId === "node-http-path") {
    for (const binding of importedJavascriptSymbols(lines)) {
      if (
        /^(?:node:)?fs(?:\/promises)?$/u.test(binding.moduleSpecifier) &&
        NODE_FILESYSTEM_PATH_ARGUMENTS.has(binding.imported)
      ) {
        aliases.add(binding.local);
      }
    }
  } else {
    for (const structural of structuralLines) {
      const fromImport =
        /^\s*from\s+(builtins|os|shutil)\s+import\s+(.+)$/u.exec(structural);
      if (fromImport === null) continue;
      for (const rawBinding of splitPythonArguments(fromImport[2] ?? "")) {
        const parsed = /^([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?$/u.exec(
          rawBinding.trim(),
        );
        if (
          parsed !== null &&
          PYTHON_FILESYSTEM_PATH_ARGUMENTS.has(`${fromImport[1]}.${parsed[1]}`)
        ) {
          aliases.add(parsed[2] ?? parsed[1]!);
        }
      }
    }
  }
  const candidateNames = [...new Set([...operations, ...aliases])]
    .map(escapeRegularExpression)
    .join("|");
  if (candidateNames === "") return sinks;
  const candidateCall = new RegExp(`\\b(?:${candidateNames})\\s*\\(`, "u");
  for (
    let index = 0;
    index < structuralLines.length && sinks.length < limit;
    index += 1
  ) {
    if (!candidateCall.test(structuralLines[index] ?? "")) continue;
    const line = index + 1;
    const sink =
      modelId === "node-http-path"
        ? nodeFilesystemPathSink(lines, line)
        : pythonFilesystemPathSink(lines, line);
    if (sink !== undefined) sinks.push({ kind: "filesystem-path", line });
  }
  return sinks;
}

function filesystemPathControlApplies(
  modelId: string,
  kind: string,
  controls: readonly { kind: string; line: number }[],
): boolean {
  if (modelId !== "node-http-path" && modelId !== "python-web-path") {
    return true;
  }
  if (
    kind !== "canonical-or-normalized-path" &&
    kind !== "absolute-path-rejection"
  ) {
    return true;
  }
  return controls.some(
    (control) => control.kind === "component-aware-root-containment",
  );
}

function filesystemPathWrapperControlApplies(
  modelId: string,
  control: { kind: string; line: number },
  controls: readonly { kind: string; line: number }[],
  wrapperStartLine: number,
  wrapperEndLine: number,
): boolean {
  if (!filesystemPathControlApplies(modelId, control.kind, controls)) {
    return false;
  }
  if (
    (modelId === "node-http-path" || modelId === "python-web-path") &&
    control.kind === "fixed-path-allowlist"
  ) {
    return (
      control.line >= Math.max(1, wrapperStartLine - 64) &&
      control.line <= wrapperEndLine &&
      controls.findIndex(
        (candidate) => candidate.kind === "fixed-path-allowlist",
      ) === controls.indexOf(control)
    );
  }
  return control.line >= wrapperStartLine && control.line <= wrapperEndLine;
}

interface NodeMongooseNoSqlSink {
  filterExpression: string;
  operation: string;
}

interface NodeMongooseUpdateSink {
  updateExpression: string;
  operation: string;
}

type NodeMongooseBulkWritePositionKind =
  | "filter"
  | "update"
  | "document"
  | "operation-array";

interface NodeMongooseBulkWritePosition {
  expression: string;
  kind: NodeMongooseBulkWritePositionKind;
  line: number;
  operation: string;
}

interface NodeMongooseBulkWriteSink {
  operationsExpression: string;
  positions: NodeMongooseBulkWritePosition[];
}

interface NodeMongooseBindingContext {
  mongooseReceivers: ReadonlyArray<{ local: string; line: number }>;
  modelFunctions: ReadonlyArray<{ local: string; line: number }>;
  models: ReadonlyArray<{ local: string; line: number }>;
  wrappers: readonly ExportedJavascriptFunction[];
}

const NODE_MONGOOSE_BINDING_CACHE = new WeakMap<
  readonly string[],
  NodeMongooseBindingContext
>();

const NODE_MONGOOSE_FILTER_OPERATIONS = new Set([
  "countDocuments",
  "deleteMany",
  "deleteOne",
  "exists",
  "find",
  "findOne",
  "findOneAndDelete",
  "findOneAndReplace",
  "findOneAndUpdate",
  "replaceOne",
  "updateMany",
  "updateOne",
]);

const NODE_MONGOOSE_UPDATE_OPERATIONS = new Set([
  "findByIdAndUpdate",
  "findOneAndUpdate",
  "updateMany",
  "updateOne",
]);

function nodeMongooseHasOfficialFactoryBinding(
  lines: readonly string[],
): boolean {
  for (const line of lines) {
    const code = javascriptCodeBeforeComment(line);
    if (
      /^\s*import\s+\*\s+as\s+[A-Za-z_$][\w$]*\s+from\s+["']mongoose["']/u.test(
        code,
      ) ||
      /^\s*import\s+[A-Za-z_$][\w$]*\s+from\s+["']mongoose["']/u.test(code) ||
      /^\s*(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*require\s*\(\s*["']mongoose["']\s*\)/u.test(
        code,
      )
    ) {
      return true;
    }
  }
  return importedJavascriptSymbols(lines).some(
    (binding) =>
      binding.moduleSpecifier === "mongoose" && binding.imported === "model",
  );
}

function nodeMongooseBindingContext(
  lines: readonly string[],
): NodeMongooseBindingContext {
  const cached = NODE_MONGOOSE_BINDING_CACHE.get(lines);
  if (cached !== undefined) return cached;
  const mongooseReceivers: Array<{ local: string; line: number }> = [];
  for (let index = 0; index < lines.length; index += 1) {
    const code = javascriptCodeBeforeComment(lines[index] ?? "");
    const namespace =
      /^\s*import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+["']mongoose["']/u.exec(
        code,
      );
    const defaultImport =
      /^\s*import\s+([A-Za-z_$][\w$]*)\s+from\s+["']mongoose["']/u.exec(code);
    const requireBinding =
      /^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["']mongoose["']\s*\)/u.exec(
        code,
      );
    const local = namespace?.[1] ?? defaultImport?.[1] ?? requireBinding?.[1];
    if (local !== undefined) mongooseReceivers.push({ local, line: index + 1 });
  }
  const modelFunctions = importedJavascriptSymbols(lines)
    .filter(
      (binding) =>
        binding.moduleSpecifier === "mongoose" && binding.imported === "model",
    )
    .map((binding) => ({ local: binding.local, line: binding.line }));
  const candidateModels: Array<{ local: string; line: number }> = [];
  const structuralLines = javascriptStructuralLines(lines);
  for (let index = 0; index < structuralLines.length; index += 1) {
    const structural = structuralLines[index] ?? "";
    const declaration =
      /^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)(?:\s*\.\s*(model))?\s*\(/u.exec(
        structural,
      );
    if (declaration === null) continue;
    const factory = declaration[2]!;
    const member = declaration[3];
    const exactReceiver = mongooseReceivers.some(
      (binding) =>
        binding.local === factory &&
        binding.line < index + 1 &&
        member === "model" &&
        !javascriptIdentifierReassignedBetween(
          lines,
          factory,
          binding.line,
          index + 1,
        ),
    );
    const exactFunction = modelFunctions.some(
      (binding) =>
        binding.local === factory &&
        binding.line < index + 1 &&
        member === undefined &&
        !javascriptIdentifierReassignedBetween(
          lines,
          factory,
          binding.line,
          index + 1,
        ),
    );
    if (exactReceiver || exactFunction) {
      candidateModels.push({ local: declaration[1]!, line: index + 1 });
    }
  }
  const models = candidateModels.filter(
    (candidate) =>
      candidateModels.filter((other) => other.local === candidate.local)
        .length === 1,
  );
  const context = {
    mongooseReceivers,
    modelFunctions,
    models,
    wrappers: exportedJavascriptFunctions(lines),
  } satisfies NodeMongooseBindingContext;
  NODE_MONGOOSE_BINDING_CACHE.set(lines, context);
  return context;
}

function nodeMongooseNoSqlSink(
  lines: readonly string[],
  line: number,
): NodeMongooseNoSqlSink | undefined {
  const context = nodeMongooseBindingContext(lines);
  const wrapper = context.wrappers.find(
    (candidate) => line >= candidate.startLine && line <= candidate.endLine,
  );
  const structuralLine =
    javascriptStructuralLines([lines[line - 1] ?? ""])[0] ?? "";
  for (const model of context.models) {
    if (
      model.line >= line ||
      wrapper?.parameters.includes(model.local) === true ||
      javascriptIdentifierReassignedBetween(
        lines,
        model.local,
        model.line,
        line,
      )
    ) {
      continue;
    }
    for (const operation of NODE_MONGOOSE_FILTER_OPERATIONS) {
      const call = new RegExp(
        `\\b${escapeRegularExpression(model.local)}\\s*\\.\\s*${escapeRegularExpression(operation)}\\s*\\(`,
        "u",
      );
      if (!call.test(structuralLine)) continue;
      const explicitlyConsumed =
        /\bawait\b/u.test(structuralLine) ||
        /\.\s*(?:exec|then|catch)\s*\(/u.test(structuralLine);
      const returnedFromAsyncWrapper =
        /\breturn\b/u.test(structuralLine) &&
        wrapper !== undefined &&
        /\basync\b/u.test(lines[wrapper.startLine - 1] ?? "");
      if (!explicitlyConsumed && !returnedFromAsyncWrapper) {
        continue;
      }
      const arguments_ = javascriptCallArgumentsAtLine(lines, line, call);
      const filterExpression = arguments_?.[0]?.trim();
      if (filterExpression) return { filterExpression, operation };
    }
  }
  return undefined;
}

function nodeMongooseUpdateSink(
  lines: readonly string[],
  line: number,
): NodeMongooseUpdateSink | undefined {
  const context = nodeMongooseBindingContext(lines);
  const wrapper = context.wrappers.find(
    (candidate) => line >= candidate.startLine && line <= candidate.endLine,
  );
  const structuralLine =
    javascriptStructuralLines([lines[line - 1] ?? ""])[0] ?? "";
  for (const model of context.models) {
    if (
      model.line >= line ||
      wrapper?.parameters.includes(model.local) === true ||
      javascriptIdentifierReassignedBetween(
        lines,
        model.local,
        model.line,
        line,
      )
    ) {
      continue;
    }
    for (const operation of NODE_MONGOOSE_UPDATE_OPERATIONS) {
      const call = new RegExp(
        `\\b${escapeRegularExpression(model.local)}\\s*\\.\\s*${escapeRegularExpression(operation)}\\s*\\(`,
        "u",
      );
      if (!call.test(structuralLine)) continue;
      const explicitlyConsumed =
        /\bawait\b/u.test(structuralLine) ||
        /\.\s*(?:exec|then|catch)\s*\(/u.test(structuralLine);
      const returnedFromAsyncWrapper =
        /\breturn\b/u.test(structuralLine) &&
        wrapper !== undefined &&
        /\basync\b/u.test(lines[wrapper.startLine - 1] ?? "");
      if (!explicitlyConsumed && !returnedFromAsyncWrapper) continue;
      const arguments_ = javascriptCallArgumentsAtLine(lines, line, call);
      const updateExpression = arguments_?.[1]?.trim();
      if (updateExpression) return { updateExpression, operation };
    }
  }
  return undefined;
}

function resolvedJavascriptExpression(
  lines: readonly string[],
  expression: string,
  line: number,
): JavascriptResolvedExpression {
  return (
    resolveJavascriptExpression(lines, expression, line) ?? {
      line,
      value: expression.trim(),
    }
  );
}

function nodeMongooseBulkWritePositions(
  lines: readonly string[],
  operationsExpression: string,
  sinkLine: number,
): NodeMongooseBulkWritePosition[] {
  const operations = resolvedJavascriptExpression(
    lines,
    operationsExpression,
    sinkLine,
  );
  const elements = javascriptArrayEntries(operations);
  if (elements.length === 0) {
    return [
      {
        expression: operations.value,
        kind: "operation-array",
        line: operations.line,
        operation: "dynamic",
      },
    ];
  }
  const positions: NodeMongooseBulkWritePosition[] = [];
  const addPosition = (
    expression: string,
    line: number,
    kind: NodeMongooseBulkWritePositionKind,
    operation: string,
  ): void => {
    const resolved = resolvedJavascriptExpression(lines, expression, line);
    positions.push({
      expression: resolved.value,
      kind,
      line: resolved.line,
      operation,
    });
  };
  for (const element of elements) {
    const operationObject = resolvedJavascriptExpression(
      lines,
      element.value,
      element.line,
    );
    const operationEntries = javascriptObjectEntries(operationObject);
    if (operationEntries.length === 0) {
      addPosition(
        operationObject.value.replace(/^\s*\.\.\./u, ""),
        operationObject.line,
        "operation-array",
        "dynamic",
      );
      continue;
    }
    if (/\.\.\.|\[/u.test(operationObject.value)) {
      addPosition(
        operationObject.value,
        operationObject.line,
        "operation-array",
        "dynamic",
      );
    }
    for (const operationEntry of operationEntries) {
      const operation = operationEntry.key;
      const fields: ReadonlyArray<
        readonly [string, NodeMongooseBulkWritePositionKind]
      > =
        operation === "insertOne"
          ? [["document", "document"]]
          : operation === "updateOne" || operation === "updateMany"
            ? [
                ["filter", "filter"],
                ["update", "update"],
              ]
            : operation === "deleteOne" || operation === "deleteMany"
              ? [["filter", "filter"]]
              : operation === "replaceOne"
                ? [
                    ["filter", "filter"],
                    ["replacement", "document"],
                  ]
                : [];
      if (fields.length === 0) continue;
      const specification = resolvedJavascriptExpression(
        lines,
        operationEntry.value,
        operationEntry.line,
      );
      const specificationEntries = javascriptObjectEntries(specification);
      if (specificationEntries.length === 0) {
        addPosition(
          specification.value,
          specification.line,
          "operation-array",
          operation,
        );
        continue;
      }
      if (/\.\.\.|\[/u.test(specification.value)) {
        addPosition(
          specification.value,
          specification.line,
          "operation-array",
          operation,
        );
      }
      for (const [field, kind] of fields) {
        const property = specificationEntries.find(
          (candidate) => candidate.key === field,
        );
        if (property !== undefined) {
          addPosition(property.value, property.line, kind, operation);
        }
      }
    }
  }
  return positions.filter(
    (position, index, all) =>
      all.findIndex(
        (candidate) =>
          candidate.expression === position.expression &&
          candidate.kind === position.kind &&
          candidate.operation === position.operation,
      ) === index,
  );
}

function nodeMongooseBulkWriteSink(
  lines: readonly string[],
  line: number,
): NodeMongooseBulkWriteSink | undefined {
  const context = nodeMongooseBindingContext(lines);
  const wrapper = context.wrappers.find(
    (candidate) => line >= candidate.startLine && line <= candidate.endLine,
  );
  const structuralLine =
    javascriptStructuralLines([lines[line - 1] ?? ""])[0] ?? "";
  for (const model of context.models) {
    if (
      model.line >= line ||
      wrapper?.parameters.includes(model.local) === true ||
      javascriptIdentifierReassignedBetween(
        lines,
        model.local,
        model.line,
        line,
      )
    ) {
      continue;
    }
    const call = new RegExp(
      `\\b${escapeRegularExpression(model.local)}\\s*\\.\\s*bulkWrite\\s*\\(`,
      "u",
    );
    if (!call.test(structuralLine)) continue;
    const arguments_ = javascriptCallArgumentsAtLine(lines, line, call);
    const operationsExpression = arguments_?.[0]?.trim();
    if (!operationsExpression) continue;
    const positions = nodeMongooseBulkWritePositions(
      lines,
      operationsExpression,
      line,
    );
    if (positions.length > 0) return { operationsExpression, positions };
  }
  return undefined;
}

function fixedMongooseUpdateFieldCoversParameter(
  updateExpression: string,
  parameter: string,
): boolean {
  const code = javascriptCodeLinesWithoutComments(
    updateExpression.split(/\r?\n/u),
  ).join("\n");
  const set = /\$set\s*:\s*\{([^{}]*)\}/u.exec(code);
  if (set === null || set.index === undefined) return false;
  const setBody = set[1] ?? "";
  if (/\.\.\.|\[/u.test(setBody)) return false;
  const before = code.slice(0, set.index);
  const after = code.slice(set.index + set[0].length);
  const outsideSet = `${before}\n${after}`;
  const identifier = new RegExp(
    `\\b${escapeRegularExpression(parameter)}\\b`,
    "u",
  );
  if (identifier.test(outsideSet)) return false;
  const fixedAssignment = new RegExp(
    `(?:^|,)\\s*(?:[A-Za-z_][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*|["'][A-Za-z_][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*["'])\\s*:\\s*${escapeRegularExpression(parameter)}(?:\\s*\\.\\s*[A-Za-z_$][\\w$]*)*\\b`,
    "gu",
  );
  const assignments = [...setBody.matchAll(fixedAssignment)];
  if (assignments.length === 0) return false;
  return !identifier.test(setBody.replace(fixedAssignment, ""));
}

function nodeMongooseUpdateControls(
  lines: readonly string[],
  sink: NodeMongooseUpdateSink,
  sinkLine: number,
): Array<{ kind: string; line: number }> {
  const resolved =
    resolveJavascriptExpression(lines, sink.updateExpression, sinkLine) ??
    ({
      line: sinkLine,
      value: sink.updateExpression,
    } satisfies JavascriptResolvedExpression);
  const context = nodeMongooseBindingContext(lines);
  const wrapper = context.wrappers.find(
    (candidate) =>
      sinkLine >= candidate.startLine && sinkLine <= candidate.endLine,
  );
  const taintedParameters = (wrapper?.parameters ?? []).filter((parameter) =>
    lineReferencesIdentifier(resolved.value, parameter),
  );
  if (
    taintedParameters.length > 0 &&
    taintedParameters.every((parameter) =>
      fixedMongooseUpdateFieldCoversParameter(resolved.value, parameter),
    )
  ) {
    return [{ kind: "fixed-update-field-value-boundary", line: sinkLine }];
  }
  return [];
}

function fixedMongooseDocumentFieldCoversParameter(
  documentExpression: string,
  parameter: string,
): boolean {
  const code = javascriptCodeLinesWithoutComments(
    documentExpression.split(/\r?\n/u),
  ).join("\n");
  if (/\.\.\.|\[/u.test(code)) return false;
  const properties = javascriptObjectEntries({ line: 1, value: code });
  if (properties.length === 0) return false;
  const identifier = new RegExp(
    `\\b${escapeRegularExpression(parameter)}\\b`,
    "u",
  );
  const taintedProperties = properties.filter(({ value }) =>
    identifier.test(value),
  );
  if (taintedProperties.length === 0) return false;
  return taintedProperties.every(({ value }) =>
    new RegExp(
      `^\\s*${escapeRegularExpression(parameter)}(?:\\s*\\.\\s*[A-Za-z_$][\\w$]*)+\\s*$`,
      "u",
    ).test(value),
  );
}

function nodeMongooseBulkWriteControls(
  lines: readonly string[],
  sink: NodeMongooseBulkWriteSink,
  sinkLine: number,
): Array<{ kind: string; line: number }> {
  const context = nodeMongooseBindingContext(lines);
  const wrapper = context.wrappers.find(
    (candidate) =>
      sinkLine >= candidate.startLine && sinkLine <= candidate.endLine,
  );
  const controls: Array<{ kind: string; line: number }> = [];
  for (const position of sink.positions) {
    const taintedParameters = (wrapper?.parameters ?? []).filter((parameter) =>
      lineReferencesIdentifier(position.expression, parameter),
    );
    if (taintedParameters.length === 0) continue;
    if (position.kind === "filter") {
      controls.push(
        ...nodeMongooseNoSqlControls(
          lines,
          {
            filterExpression: position.expression,
            operation: position.operation,
          },
          sinkLine,
        ),
      );
    } else if (
      position.kind === "update" &&
      taintedParameters.every((parameter) =>
        fixedMongooseUpdateFieldCoversParameter(position.expression, parameter),
      )
    ) {
      controls.push({
        kind: "fixed-update-field-value-boundary",
        line: sinkLine,
      });
    } else if (
      position.kind === "document" &&
      taintedParameters.every((parameter) =>
        fixedMongooseDocumentFieldCoversParameter(
          position.expression,
          parameter,
        ),
      )
    ) {
      controls.push({
        kind: "fixed-document-field-projection",
        line: sinkLine,
      });
    }
  }
  return controls.filter(
    (control, index, all) =>
      all.findIndex(
        (candidate) =>
          candidate.kind === control.kind && candidate.line === control.line,
      ) === index,
  );
}

function nodeMongooseNoSqlControls(
  lines: readonly string[],
  sink: NodeMongooseNoSqlSink,
  sinkLine: number,
): Array<{ kind: string; line: number }> {
  const resolved =
    resolveJavascriptExpression(lines, sink.filterExpression, sinkLine) ??
    ({
      line: sinkLine,
      value: sink.filterExpression,
    } satisfies JavascriptResolvedExpression);
  const controls: Array<{ kind: string; line: number }> = [];
  const context = nodeMongooseBindingContext(lines);
  const wrapper = context.wrappers.find(
    (candidate) =>
      sinkLine >= candidate.startLine && sinkLine <= candidate.endLine,
  );
  const taintedParameters = (wrapper?.parameters ?? []).filter((parameter) =>
    lineReferencesIdentifier(resolved.value, parameter),
  );
  if (
    taintedParameters.length > 0 &&
    taintedParameters.every((parameter) =>
      new RegExp(
        `\\$eq\\s*:\\s*${escapeRegularExpression(parameter)}\\b`,
        "u",
      ).test(resolved.value),
    )
  ) {
    controls.push({ kind: "literal-query-value-equality", line: sinkLine });
  }
  if (
    context.mongooseReceivers.some(
      (binding) =>
        binding.line < resolved.line &&
        !javascriptIdentifierReassignedBetween(
          lines,
          binding.local,
          binding.line,
          resolved.line,
        ) &&
        new RegExp(
          `\\b${escapeRegularExpression(binding.local)}\\s*\\.\\s*sanitizeFilter\\s*\\(`,
          "u",
        ).test(resolved.value),
    )
  ) {
    controls.push({
      kind: "mongoose-filter-sanitization",
      line: resolved.line,
    });
  }
  return controls;
}

function pythonCallArgumentsAtLine(
  lines: readonly string[],
  line: number,
  callee: RegExp,
): string[] | undefined {
  const callLines = lines.slice(line - 1, Math.min(lines.length, line + 12));
  const original = callLines.join("\n");
  const structural = pythonStructuralLines(callLines).join("\n");
  const match = callee.exec(structural.split("\n", 1)[0] ?? "");
  if (match === null) return undefined;
  const open = structural.indexOf("(", match.index);
  const close = matchingCallParenthesis(structural, open);
  if (open < 0 || close < 0) return undefined;
  return splitPythonArguments(original.slice(open + 1, close));
}

function pythonFilesystemPathSink(
  lines: readonly string[],
  line: number,
): FrameworkFilesystemPathSink | undefined {
  const structuralLines = pythonStructuralLines(lines);
  const wrapper = exportedPythonFunctions(lines).find(
    (candidate) => line >= candidate.startLine && line <= candidate.endLine,
  );
  const namedBindings: Array<{
    local: string;
    qualified: string;
    line: number;
  }> = [];
  const moduleBindings: Array<{ local: string; module: string; line: number }> =
    [];
  const importedLocals = new Set<string>();
  for (let index = 0; index < structuralLines.length; index += 1) {
    const structural = structuralLines[index] ?? "";
    const moduleImport =
      /^\s*import\s+(builtins|os|shutil)(?:\s+as\s+([A-Za-z_]\w*))?\s*$/u.exec(
        structural,
      );
    if (moduleImport !== null) {
      moduleBindings.push({
        module: moduleImport[1]!,
        local: moduleImport[2] ?? moduleImport[1]!,
        line: index + 1,
      });
      continue;
    }
    const fromImport =
      /^\s*from\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s+import\s+(.+)$/u.exec(
        structural,
      );
    if (fromImport === null) continue;
    for (const rawBinding of splitPythonArguments(fromImport[2] ?? "")) {
      const parsed = /^([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?$/u.exec(
        rawBinding.trim(),
      );
      if (parsed === null) continue;
      const local = parsed[2] ?? parsed[1]!;
      importedLocals.add(local);
      const qualified = `${fromImport[1]}.${parsed[1]}`;
      if (PYTHON_FILESYSTEM_PATH_ARGUMENTS.has(qualified)) {
        namedBindings.push({ local, qualified, line: index + 1 });
      }
    }
  }

  for (const binding of namedBindings) {
    if (
      binding.line >= line ||
      wrapper?.parameters.includes(binding.local) === true ||
      pythonIdentifierReassignedBetween(
        lines,
        binding.local,
        binding.line,
        line,
      )
    ) {
      continue;
    }
    const arguments_ = pythonCallArgumentsAtLine(
      lines,
      line,
      new RegExp(`\\b${escapeRegularExpression(binding.local)}\\s*\\(`, "u"),
    );
    if (arguments_ === undefined) continue;
    const positions = PYTHON_FILESYSTEM_PATH_ARGUMENTS.get(binding.qualified)!;
    const expressions = positions.flatMap((position) =>
      arguments_[position]?.trim() ? [arguments_[position]!.trim()] : [],
    );
    if (expressions.length === positions.length) {
      return {
        expressions,
        operation: binding.qualified.split(".").at(-1)!,
      };
    }
  }

  for (const binding of moduleBindings) {
    if (
      binding.line >= line ||
      wrapper?.parameters.includes(binding.local) === true ||
      pythonIdentifierReassignedBetween(
        lines,
        binding.local,
        binding.line,
        line,
      )
    ) {
      continue;
    }
    for (const [qualified, positions] of PYTHON_FILESYSTEM_PATH_ARGUMENTS) {
      const [module, operation] = qualified.split(".");
      if (module !== binding.module) continue;
      const arguments_ = pythonCallArgumentsAtLine(
        lines,
        line,
        new RegExp(
          `\\b${escapeRegularExpression(binding.local)}\\s*\\.\\s*${escapeRegularExpression(operation!)}\\s*\\(`,
          "u",
        ),
      );
      if (arguments_ === undefined) continue;
      const expressions = positions.flatMap((position) =>
        arguments_[position]?.trim() ? [arguments_[position]!.trim()] : [],
      );
      if (expressions.length === positions.length) {
        return { expressions, operation: operation! };
      }
    }
  }

  const builtinShadowed =
    importedLocals.has("open") ||
    wrapper?.parameters.includes("open") === true ||
    structuralLines.some((candidate, index) =>
      index + 1 < line
        ? /^\s*(?:async\s+)?def\s+open\s*\(|^\s*class\s+open\b|^\s*open\s*(?::[^=]+)?=/u.test(
            candidate,
          )
        : false,
    );
  if (!builtinShadowed) {
    const arguments_ = pythonCallArgumentsAtLine(
      lines,
      line,
      /(?<![.\w])open\s*\(/u,
    );
    const expression = arguments_?.[0]?.trim();
    if (expression) return { expressions: [expression], operation: "open" };
  }
  return undefined;
}

function resolveRelativeModelImport(
  callerPath: string,
  moduleSpecifier: string,
  knownPaths: ReadonlyMap<string, string>,
): string | undefined {
  if (!moduleSpecifier.startsWith("./") && !moduleSpecifier.startsWith("../")) {
    return undefined;
  }
  const joined = posix.normalize(
    posix.join(posix.dirname(callerPath), moduleSpecifier),
  );
  if (joined === ".." || joined.startsWith("../") || posix.isAbsolute(joined)) {
    return undefined;
  }
  const extension = posix.extname(joined);
  const stem = extension === "" ? joined : joined.slice(0, -extension.length);
  const candidates = [
    joined,
    ...[".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"].map(
      (candidateExtension) => `${stem}${candidateExtension}`,
    ),
    ...[".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"].map(
      (candidateExtension) => `${joined}/index${candidateExtension}`,
    ),
  ];
  for (const candidate of candidates) {
    const resolved = knownPaths.get(modelPathComparisonKey(candidate));
    if (resolved !== undefined) return resolved;
  }
  return undefined;
}

function resolveRelativePythonImport(
  callerPath: string,
  moduleSpecifier: string,
  knownPaths: ReadonlyMap<string, string>,
): string | undefined {
  const match = /^(\.+)([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)$/u.exec(
    moduleSpecifier,
  );
  if (match === null) return undefined;
  let base = posix.dirname(callerPath);
  for (let level = 1; level < match[1]!.length; level += 1) {
    base = posix.dirname(base);
  }
  const joined = posix.normalize(
    posix.join(base, match[2]!.replaceAll(".", "/")),
  );
  if (joined === ".." || joined.startsWith("../") || posix.isAbsolute(joined)) {
    return undefined;
  }
  for (const candidate of [`${joined}.py`, `${joined}/__init__.py`]) {
    const resolved = knownPaths.get(modelPathComparisonKey(candidate));
    if (resolved !== undefined) return resolved;
  }
  return undefined;
}

function modelPathComparisonKey(path: string): string {
  return process.platform === "win32" ? path.toLowerCase() : path;
}

function javascriptCallLines(
  lines: readonly string[],
  symbol: string,
): Array<{ line: number; arguments: string[] }> {
  const calls: Array<{ line: number; arguments: string[] }> = [];
  const expression = new RegExp(
    `\\b${escapeRegularExpression(symbol)}\\s*\\(`,
    "u",
  );
  for (let index = 0; index < lines.length; index += 1) {
    const firstLine = javascriptStructuralLines([lines[index] ?? ""])[0] ?? "";
    const match = expression.exec(firstLine);
    if (match === null) continue;
    const callLines = lines.slice(index, Math.min(lines.length, index + 13));
    const originalCallText =
      javascriptCodeLinesWithoutComments(callLines).join("\n");
    const structuralCallText = javascriptStructuralLines(callLines).join("\n");
    const open = structuralCallText.indexOf("(", match.index);
    const close = matchingCallParenthesis(structuralCallText, open);
    if (open < 0 || close < 0) continue;
    calls.push({
      line: index + 1,
      arguments: splitJavascriptArguments(
        originalCallText.slice(open + 1, close),
      ),
    });
  }
  return calls;
}

function pythonCallLines(
  lines: readonly string[],
  symbol: string,
): Array<{ line: number; arguments: string[] }> {
  const calls: Array<{ line: number; arguments: string[] }> = [];
  const structuralLines = pythonStructuralLines(lines);
  const expression = new RegExp(
    `\\b${escapeRegularExpression(symbol)}\\s*\\(`,
    "u",
  );
  for (let index = 0; index < lines.length; index += 1) {
    const structuralLine = structuralLines[index] ?? "";
    const match = expression.exec(structuralLine);
    if (match === null) continue;
    const callLines = lines.slice(index, Math.min(lines.length, index + 13));
    const callText = callLines.join("\n");
    const structuralCallText = pythonStructuralLines(callLines).join("\n");
    const open = structuralCallText.indexOf("(", match.index);
    const close = matchingCallParenthesis(structuralCallText, open);
    if (open < 0 || close < 0) continue;
    calls.push({
      line: index + 1,
      arguments: splitPythonArguments(callText.slice(open + 1, close)),
    });
  }
  return calls;
}

function javaReceiverBindings(lines: readonly string[]): JavaReceiverBinding[] {
  const structuralLines = cFamilyStructuralLines(lines);
  const candidates: JavaReceiverBinding[] = [];
  const declaration =
    /^\s*(?:(?:final|internal|private|protected|public|readonly|static|transient|volatile)\s+)*([A-Z][A-Za-z0-9_$]*)\s+([A-Za-z_$][\w$]*)\s*(?:[;=,)])/u;
  for (let index = 0; index < structuralLines.length; index += 1) {
    const match = declaration.exec(structuralLines[index] ?? "");
    if (match === null) continue;
    candidates.push({
      receiver: match[2]!,
      ownerType: match[1]!,
      line: index + 1,
    });
  }
  const ownerTypesByReceiver = new Map<string, Set<string>>();
  for (const candidate of candidates) {
    const types = ownerTypesByReceiver.get(candidate.receiver) ?? new Set();
    types.add(candidate.ownerType);
    ownerTypesByReceiver.set(candidate.receiver, types);
  }
  return candidates.filter(
    (candidate, index, all) =>
      ownerTypesByReceiver.get(candidate.receiver)?.size === 1 &&
      all.findIndex(
        (existing) =>
          existing.receiver === candidate.receiver &&
          existing.ownerType === candidate.ownerType,
      ) === index,
  );
}

function javaMethodCallLines(
  lines: readonly string[],
  receiver: string,
  method: string,
): Array<{ line: number; arguments: string[] }> {
  const calls: Array<{ line: number; arguments: string[] }> = [];
  const expression = new RegExp(
    `\\b(?:this\\s*\\.\\s*)?${escapeRegularExpression(receiver)}\\s*\\.\\s*${escapeRegularExpression(method)}\\s*\\(`,
    "u",
  );
  const structuralLines = cFamilyStructuralLines(lines);
  for (let index = 0; index < structuralLines.length; index += 1) {
    const firstLine = structuralLines[index] ?? "";
    const match = expression.exec(firstLine);
    if (match === null) continue;
    const callLines = lines.slice(index, Math.min(lines.length, index + 13));
    const callText = callLines.join("\n");
    const structuralCallText = cFamilyStructuralLines(callLines).join("\n");
    const open = structuralCallText.indexOf("(", match.index);
    const close = matchingCallParenthesis(structuralCallText, open);
    if (open < 0 || close < 0) continue;
    calls.push({
      line: index + 1,
      arguments: splitJavascriptArguments(callText.slice(open + 1, close)),
    });
  }
  return calls;
}

function matchingCallParenthesis(line: string, open: number): number {
  if (open < 0) return -1;
  let depth = 0;
  let quote = "";
  let escaped = false;
  for (let index = open; index < line.length; index += 1) {
    const character = line[index]!;
    if (quote !== "") {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      continue;
    }
    if (character === '"' || character === "'" || character === "`") {
      quote = character;
    } else if (character === "(") {
      depth += 1;
    } else if (character === ")") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function splitJavascriptArguments(value: string): string[] {
  const arguments_: string[] = [];
  let start = 0;
  let depth = 0;
  let quote = "";
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]!;
    if (quote !== "") {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      continue;
    }
    if (character === '"' || character === "'" || character === "`") {
      quote = character;
    } else if (["(", "[", "{"].includes(character)) {
      depth += 1;
    } else if ([")", "]", "}"].includes(character)) {
      depth -= 1;
    } else if (character === "," && depth === 0) {
      arguments_.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  arguments_.push(value.slice(start).trim());
  return arguments_;
}

function splitPythonArguments(value: string): string[] {
  return splitJavascriptArguments(value);
}

function modeledCallSource(
  lines: readonly string[],
  sources: readonly { kind: string; line: number }[],
  callLine: number,
  argument: string,
  sourcePatterns: readonly FrameworkModelPattern[],
): { kind: string; line: number } | undefined {
  const direct = sourcePatterns.find((pattern) =>
    pattern.expression.test(argument),
  );
  if (direct !== undefined) return { kind: direct.kind, line: callLine };
  if (!/^[A-Za-z_$][\w$]*$/u.test(argument)) return undefined;
  const earliest = Math.max(1, callLine - MAX_WRAPPER_CALL_DISTANCE);
  for (let line = callLine - 1; line >= earliest; line -= 1) {
    const source = sources.find((candidate) => candidate.line === line);
    if (source === undefined) continue;
    const assignment = new RegExp(
      `\\b(?:const|let|var)\\s+${escapeRegularExpression(argument)}\\s*=`,
      "u",
    );
    if (!assignment.test(lines[line - 1] ?? "")) continue;
    if (
      !javascriptIdentifierReassignedBetween(lines, argument, line, callLine)
    ) {
      return source;
    }
  }
  return undefined;
}

function modeledObjectLookupSource(
  lines: readonly string[],
  sources: readonly { kind: string; line: number }[],
  callLine: number,
  argument: string,
  sourcePatterns: readonly FrameworkModelPattern[],
): { kind: string; line: number } | undefined {
  const direct = sourcePatterns.find((pattern) =>
    pattern.expression.test(argument),
  );
  if (direct !== undefined) return { kind: direct.kind, line: callLine };
  const earliest = Math.max(1, callLine - MAX_WRAPPER_CALL_DISTANCE);
  for (let line = callLine - 1; line >= earliest; line -= 1) {
    const source = sources.find((candidate) => candidate.line === line);
    if (source === undefined) continue;
    const assignment = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/u.exec(
      javascriptStructuralCode(lines[line - 1] ?? ""),
    );
    const identifier = assignment?.[1];
    if (
      identifier === undefined ||
      !lineReferencesIdentifier(argument, identifier) ||
      javascriptIdentifierReassignedBetween(lines, identifier, line, callLine)
    ) {
      continue;
    }
    return source;
  }
  return undefined;
}

function modeledPythonCallSource(
  lines: readonly string[],
  sources: readonly { kind: string; line: number }[],
  callLine: number,
  argument: string,
  sourcePatterns: readonly FrameworkModelPattern[],
): { kind: string; line: number } | undefined {
  const structuralLines = pythonStructuralLines(lines);
  const direct = sourcePatterns.find((pattern) =>
    pattern.expression.test(argument),
  );
  if (direct !== undefined) return { kind: direct.kind, line: callLine };
  if (!/^[A-Za-z_]\w*$/u.test(argument)) return undefined;
  const earliest = Math.max(1, callLine - MAX_WRAPPER_CALL_DISTANCE);
  const assignment = new RegExp(
    `^\\s*${escapeRegularExpression(argument)}\\s*(?::[^=]+)?=`,
    "u",
  );
  for (let line = callLine - 1; line >= earliest; line -= 1) {
    const source = sources.find((candidate) => candidate.line === line);
    if (source === undefined) continue;
    if (!assignment.test(structuralLines[line - 1] ?? "")) {
      continue;
    }
    if (!pythonIdentifierReassignedBetween(lines, argument, line, callLine)) {
      return source;
    }
  }
  return undefined;
}

function modeledPythonObjectSource(
  lines: readonly string[],
  sources: readonly { kind: string; line: number }[],
  callLine: number,
  argument: string,
  sourcePatterns: readonly FrameworkModelPattern[],
): { kind: string; line: number } | undefined {
  const direct = sourcePatterns.find((pattern) =>
    pattern.expression.test(argument),
  );
  if (direct !== undefined) return { kind: direct.kind, line: callLine };
  const structuralLines = pythonStructuralLines(lines);
  const earliest = Math.max(1, callLine - MAX_WRAPPER_CALL_DISTANCE);
  for (let line = callLine - 1; line >= earliest; line -= 1) {
    const source = sources.find((candidate) => candidate.line === line);
    if (source === undefined) continue;
    const assignment = /^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=/u.exec(
      structuralLines[line - 1] ?? "",
    );
    const identifier = assignment?.[1];
    if (
      identifier === undefined ||
      !pythonLineReferencesIdentifier(argument, identifier) ||
      pythonIdentifierReassignedBetween(lines, identifier, line, callLine)
    ) {
      continue;
    }
    return source;
  }
  return undefined;
}

function resolvePythonExpression(
  lines: readonly string[],
  expression: string,
  beforeLine: number,
  depth = 0,
  seen: ReadonlySet<string> = new Set(),
): string | undefined {
  const value = expression.trim();
  if (value === "" || depth > 8) return undefined;
  if (!/^[A-Za-z_]\w*$/u.test(value)) return value;
  if (seen.has(value)) return undefined;
  const earliest = Math.max(1, beforeLine - 64);
  const structuralLines = pythonStructuralLines(lines);
  const assignment = new RegExp(
    `^\\s*${escapeRegularExpression(value)}\\s*(?::[^=]+)?=\\s*(.+)$`,
    "u",
  );
  for (let line = beforeLine - 1; line >= earliest; line -= 1) {
    const structural = structuralLines[line - 1] ?? "";
    const match = assignment.exec(structural);
    if (match === null) continue;
    if (pythonIdentifierReassignedBetween(lines, value, line, beforeLine)) {
      return undefined;
    }
    const original = pythonCodeBeforeComment(lines[line - 1] ?? "");
    const equals = original.indexOf("=");
    if (equals < 0) return undefined;
    return resolvePythonExpression(
      lines,
      original.slice(equals + 1),
      line,
      depth + 1,
      new Set([...seen, value]),
    );
  }
  return value;
}

function modeledJavaCallSource(
  lines: readonly string[],
  method: ExportedJavaMethod,
  callLine: number,
  argument: string,
  sourcePatterns: readonly FrameworkModelPattern[],
): { kind: string; line: number } | undefined {
  const direct = sourcePatterns.find((pattern) =>
    pattern.expression.test(argument),
  );
  if (direct !== undefined) return { kind: direct.kind, line: callLine };
  if (!/^[A-Za-z_$][\w$]*$/u.test(argument)) return undefined;
  for (const parameter of method.parameters) {
    if (parameter.name !== argument) continue;
    const source = sourcePatterns.find((pattern) =>
      pattern.expression.test(parameter.declaration),
    );
    if (
      source !== undefined &&
      !javaMethodParameterReassignedBeforeCall(
        lines,
        argument,
        method.startLine,
        callLine,
      )
    ) {
      return { kind: source.kind, line: method.startLine };
    }
  }

  const sources = matchingJavaModelLines(lines, sourcePatterns, 32);
  const structuralLines = cFamilyStructuralLines(lines);
  const assignment = new RegExp(
    `\\b(?:[A-Za-z_$][\\w$.[\\]<>?,]*\\s+)?${escapeRegularExpression(argument)}\\s*=`,
    "u",
  );
  const earliest = Math.max(
    method.startLine,
    callLine - MAX_WRAPPER_CALL_DISTANCE,
  );
  for (let line = callLine - 1; line >= earliest; line -= 1) {
    const source = sources.find((candidate) => candidate.line === line);
    if (source === undefined) continue;
    if (!assignment.test(structuralLines[line - 1] ?? "")) continue;
    if (!javaIdentifierReassignedBetween(lines, argument, line, callLine)) {
      return source;
    }
  }
  return undefined;
}

function javaMethodParameterReassignedBeforeCall(
  lines: readonly string[],
  identifier: string,
  methodStartLine: number,
  callLine: number,
): boolean {
  const structural = cFamilyStructuralLines(
    lines.slice(methodStartLine - 1, callLine),
  ).join("\n");
  const bodyStart = structural.indexOf("{");
  if (bodyStart < 0) return false;
  const escapedIdentifier = escapeRegularExpression(identifier);
  const reassignment = new RegExp(
    `(?:\\b${escapedIdentifier}\\s*(?:[+\\-*/%&|^]?=|\\+\\+|--)|(?:\\+\\+|--)\\s*${escapedIdentifier}\\b|\\b(?:final\\s+)?[A-Za-z_$][\\w$.[\\]<>?,]*\\s+${escapedIdentifier}\\b)`,
    "u",
  );
  return reassignment.test(structural.slice(bodyStart + 1));
}

function modeledSameFileJavaSource(
  lines: readonly string[],
  sinkLine: number,
  modelId: string,
  sourcePatterns: readonly FrameworkModelPattern[],
): { kind: string; line: number } | undefined {
  const method = exportedJavaMethods(lines).find(
    (candidate) =>
      sinkLine >= candidate.startLine && sinkLine <= candidate.endLine,
  );
  if (method === undefined) return undefined;
  const sinkExpression =
    modelId === "spring-http-ssrf"
      ? javaOutboundDestinationArgument(
          javaOutboundCallExpression(lines, sinkLine, method.endLine),
        )
      : javaCallExpression(lines, sinkLine, method.endLine);
  const direct = modeledJavaCallSource(
    lines,
    method,
    sinkLine,
    sinkExpression.trim(),
    sourcePatterns,
  );
  if (direct !== undefined) return direct;

  for (const parameterIndex of javaMethodParameterIndexesReachingSink(
    lines,
    method,
    sinkLine,
    sinkExpression,
  )) {
    const parameter = method.parameters[parameterIndex];
    if (parameter === undefined) continue;
    const source = modeledJavaCallSource(
      lines,
      method,
      sinkLine,
      parameter.name,
      sourcePatterns,
    );
    if (source !== undefined) return source;
  }
  return undefined;
}

interface JavaObjectAuthorizationSink {
  argument: string;
  arguments: string[];
  receiver: string;
  method: string;
  callStartLine: number;
  callEndLine: number;
}

interface JavaJpaPersistenceSink {
  argument: string;
  receiver: string;
  callStartLine: number;
  callEndLine: number;
}

function javaJpaPersistenceSink(
  lines: readonly string[],
  sinkLine: number,
  methodEndLine = lines.length,
): JavaJpaPersistenceSink | undefined {
  const baseLine = Math.max(1, sinkLine - 1);
  const callLines = lines.slice(
    baseLine - 1,
    Math.min(methodEndLine, sinkLine + 12),
  );
  const original = callLines.join("\n");
  const structural = cFamilyStructuralLines(callLines).join("\n");
  const call = /\b([A-Za-z_$][\w$]*)\s*\.\s*save\s*\(/u.exec(structural);
  if (call?.index === undefined) return undefined;
  const methodIndex = structural.indexOf("save", call.index);
  const methodLine =
    baseLine + (structural.slice(0, methodIndex).match(/\n/gu)?.length ?? 0);
  if (methodLine !== sinkLine) return undefined;
  const open = structural.indexOf("(", call.index);
  const close = matchingCallParenthesis(structural, open);
  if (open < 0 || close < 0) return undefined;
  const argument = splitJavascriptArguments(
    original.slice(open + 1, close),
  )[0]?.trim();
  if (argument === undefined || argument === "") return undefined;
  return {
    argument,
    receiver: call[1]!,
    callStartLine: sinkLine,
    callEndLine:
      baseLine + (structural.slice(0, close).match(/\n/gu)?.length ?? 0),
  };
}

function javaSpringDataRepositoryDomainType(
  files: readonly SourceFileSnapshot[],
  sourcePath: string,
  lines: readonly string[],
  receiverName: string,
): string | undefined {
  const structuralText = cFamilyStructuralLines(lines).join("\n");
  const receiver = escapeRegularExpression(receiverName);
  const direct = new RegExp(
    `\\b(?:org\\s*\\.\\s*springframework\\s*\\.\\s*data\\s*\\.(?:\\s*jpa\\s*\\.)?\\s*repository\\s*\\.\\s*)?(?:CrudRepository|JpaRepository)\\s*<\\s*([A-Z][A-Za-z0-9_$.]*)\\s*,[^;{}]+>\\s+${receiver}\\b`,
    "u",
  ).exec(structuralText);
  if (direct !== null && javaSourceUsesOfficialSpringDataRepository(lines)) {
    return direct[1]!.split(".").at(-1);
  }

  const bindings = javaReceiverBindings(lines).filter(
    (binding) => binding.receiver === receiverName,
  );
  if (bindings.length !== 1) return undefined;
  const repositoryType = bindings[0]!.ownerType;
  const projectRoot = javaProjectRootForPath(files, sourcePath);
  const declarations = files.filter((file) => {
    if (
      file.extension !== ".java" ||
      !pathWithinDirectory(file.path, projectRoot)
    ) {
      return false;
    }
    const text = cFamilyStructuralLines(file.lines).join("\n");
    return new RegExp(
      `\\binterface\\s+${escapeRegularExpression(repositoryType)}\\b`,
      "u",
    ).test(text);
  });
  if (declarations.length !== 1) return undefined;
  const declaration = declarations[0]!;
  if (!javaSourceUsesOfficialSpringDataRepository(declaration.lines)) {
    return undefined;
  }
  const declarationText = cFamilyStructuralLines(declaration.lines).join("\n");
  const extended = new RegExp(
    `\\binterface\\s+${escapeRegularExpression(repositoryType)}(?:\\s*<[^>{}]+>)?\\s+extends\\s+(?:org\\s*\\.\\s*springframework\\s*\\.\\s*data\\s*\\.(?:\\s*jpa\\s*\\.)?\\s*repository\\s*\\.\\s*)?(?:CrudRepository|JpaRepository)\\s*<\\s*([A-Z][A-Za-z0-9_$.]*)\\s*,`,
    "u",
  ).exec(declarationText);
  return extended?.[1]?.split(".").at(-1);
}

function javaJpaEntityTypeExists(
  files: readonly SourceFileSnapshot[],
  sourcePath: string,
  domainType: string,
): boolean {
  const projectRoot = javaProjectRootForPath(files, sourcePath);
  const declarations = files.filter((file) => {
    if (
      file.extension !== ".java" ||
      !pathWithinDirectory(file.path, projectRoot)
    ) {
      return false;
    }
    const text = cFamilyStructuralLines(file.lines).join("\n");
    return new RegExp(
      `\\b(?:class|record)\\s+${escapeRegularExpression(domainType)}\\b`,
      "u",
    ).test(text);
  });
  if (declarations.length !== 1) return false;
  const text = cFamilyStructuralLines(declarations[0]!.lines).join("\n");
  if (/\b@interface\s+Entity\b/u.test(text)) return false;
  const imported =
    /^\s*import\s+(?:jakarta|javax)\.persistence\.Entity\s*;/mu.test(text);
  const annotated = /@Entity\b/u.test(text);
  const qualified =
    /@(?:jakarta|javax)\s*\.\s*persistence\s*\.\s*Entity\b/u.test(text);
  return (imported && annotated) || qualified;
}

function javaParameterSimpleType(parameter: {
  name: string;
  declaration: string;
}): string | undefined {
  const withoutName = parameter.declaration
    .replace(
      new RegExp(
        `${escapeRegularExpression(parameter.name)}\\s*(?:\\[\\s*\\])?\\s*$`,
        "u",
      ),
      "",
    )
    .replace(/@[A-Za-z_$][\w$.]*(?:\([^)]*\))?/gu, " ")
    .replace(/\b(?:final|volatile|transient)\b/gu, " ")
    .trim();
  return /(?:^|[.\s])([A-Z][A-Za-z0-9_$]*)\s*$/u.exec(withoutName)?.[1];
}

function modeledJavaMassAssignmentSource(
  lines: readonly string[],
  method: ExportedJavaMethod,
  callLine: number,
  argument: string,
  domainType: string,
): { kind: string; line: number } | undefined {
  if (
    !javaSpringWebController(lines) ||
    !javaSpringStateChangingHandler(lines, method)
  ) {
    return undefined;
  }
  const parameter = method.parameters.find(
    (candidate) => candidate.name === argument.trim(),
  );
  if (
    parameter === undefined ||
    javaParameterSimpleType(parameter) !== domainType ||
    !javaOfficialBoundModelParameter(lines, parameter.declaration) ||
    javaMethodParameterReassignedBeforeCall(
      lines,
      parameter.name,
      method.startLine,
      callLine,
    )
  ) {
    return undefined;
  }
  return { kind: "spring-bound-domain-object", line: method.startLine };
}

function javaOfficialBoundModelParameter(
  lines: readonly string[],
  declaration: string,
): boolean {
  const text = cFamilyStructuralLines(lines).join("\n");
  if (/\b@interface\s+ModelAttribute\b/u.test(text)) return false;
  const official =
    /^\s*import\s+org\.springframework\.web\.bind\.annotation\.ModelAttribute\s*;/mu.test(
      text,
    ) ||
    /^\s*import\s+org\.springframework\.web\.bind\.annotation\.\*\s*;/mu.test(
      text,
    ) ||
    /@org\s*\.\s*springframework\s*\.\s*web\s*\.\s*bind\s*\.\s*annotation\s*\.\s*ModelAttribute\b/u.test(
      declaration,
    );
  return (
    official &&
    /@(?:org\.springframework\.web\.bind\.annotation\.)?ModelAttribute\b/u.test(
      declaration,
    ) &&
    !/@(?:org\.springframework\.web\.bind\.annotation\.)?ModelAttribute\s*\([^)]*binding\s*=\s*false/iu.test(
      declaration,
    )
  );
}

function javaSpringWebController(lines: readonly string[]): boolean {
  const text = cFamilyStructuralLines(lines).join("\n");
  if (/\b@interface\s+(?:Controller|RestController)\b/u.test(text)) {
    return false;
  }
  return [
    {
      name: "Controller",
      packageName: "org.springframework.stereotype.Controller",
    },
    {
      name: "RestController",
      packageName: "org.springframework.web.bind.annotation.RestController",
    },
  ].some(({ name, packageName }) => {
    const escapedName = escapeRegularExpression(name);
    const escapedPackage = escapeRegularExpression(packageName);
    return (
      (new RegExp(`@${escapedName}\\b`, "u").test(text) &&
        new RegExp(`^\\s*import\\s+${escapedPackage}\\s*;`, "mu").test(text)) ||
      new RegExp(
        `@${escapedPackage.replaceAll("\\.", "\\s*\\.\\s*")}\\b`,
        "u",
      ).test(text)
    );
  });
}

function javaSpringStateChangingHandler(
  lines: readonly string[],
  method: ExportedJavaMethod,
): boolean {
  const text = cFamilyStructuralLines(lines).join("\n");
  if (
    /\b@interface\s+(?:PatchMapping|PostMapping|PutMapping|RequestMapping)\b/u.test(
      text,
    )
  ) {
    return false;
  }
  const window = lines
    .slice(Math.max(0, method.startLine - 12), method.startLine - 1)
    .join("\n");
  const immediatelyPrecedesMethod = (expression: RegExp): boolean =>
    [...window.matchAll(new RegExp(expression.source, `${expression.flags}g`))]
      .reverse()
      .some((match) => {
        const suffix = window.slice((match.index ?? 0) + match[0].length);
        return !/(?:;|^\s*\}\s*$)/mu.test(suffix);
      });
  const mappingNames = ["PatchMapping", "PostMapping", "PutMapping"];
  for (const name of mappingNames) {
    const official =
      new RegExp(
        `^\\s*import\\s+org\\.springframework\\.web\\.bind\\.annotation\\.${name}\\s*;`,
        "mu",
      ).test(text) ||
      /^\s*import\s+org\.springframework\.web\.bind\.annotation\.\*\s*;/mu.test(
        text,
      );
    if (
      (official && immediatelyPrecedesMethod(new RegExp(`@${name}\\b`, "u"))) ||
      immediatelyPrecedesMethod(
        new RegExp(
          `@org\\.springframework\\.web\\.bind\\.annotation\\.${name}\\b`,
          "u",
        ),
      )
    ) {
      return true;
    }
  }
  const requestMappingOfficial =
    /^\s*import\s+org\.springframework\.web\.bind\.annotation\.RequestMapping\s*;/mu.test(
      text,
    ) ||
    /^\s*import\s+org\.springframework\.web\.bind\.annotation\.\*\s*;/mu.test(
      text,
    ) ||
    /@org\s*\.\s*springframework\s*\.\s*web\s*\.\s*bind\s*\.\s*annotation\s*\.\s*RequestMapping\b/u.test(
      window,
    );
  return (
    requestMappingOfficial &&
    immediatelyPrecedesMethod(
      /@(?:org\.springframework\.web\.bind\.annotation\.)?RequestMapping\s*\([^)]*RequestMethod\s*\.\s*(?:PATCH|POST|PUT)\b/iu,
    )
  );
}

function javaSpringBindingControls(
  lines: readonly string[],
  parameter: { name: string; declaration: string },
): Array<{ kind: string; line: number }> {
  const text = cFamilyStructuralLines(lines).join("\n");
  if (
    /\b@interface\s+InitBinder\b/u.test(text) ||
    /\b(?:class|interface|record)\s+WebDataBinder\b/u.test(text)
  ) {
    return [];
  }
  const officialInitBinder =
    /^\s*import\s+org\.springframework\.web\.bind\.annotation\.InitBinder\s*;/mu.test(
      text,
    ) ||
    /^\s*import\s+org\.springframework\.web\.bind\.annotation\.\*\s*;/mu.test(
      text,
    ) ||
    /@org\s*\.\s*springframework\s*\.\s*web\s*\.\s*bind\s*\.\s*annotation\s*\.\s*InitBinder\b/u.test(
      text,
    );
  const officialBinder =
    /^\s*import\s+org\.springframework\.web\.bind\.WebDataBinder\s*;/mu.test(
      text,
    ) ||
    /org\s*\.\s*springframework\s*\.\s*web\s*\.\s*bind\s*\.\s*WebDataBinder\b/u.test(
      text,
    );
  if (!officialInitBinder || !officialBinder) return [];

  const attributeName =
    /@(?:org\.springframework\.web\.bind\.annotation\.)?ModelAttribute\s*\([^)]*(?:name|value)\s*=\s*["']([^"']+)["']/iu.exec(
      parameter.declaration,
    )?.[1] ??
    /@(?:org\.springframework\.web\.bind\.annotation\.)?ModelAttribute\s*\(\s*["']([^"']+)["']/iu.exec(
      parameter.declaration,
    )?.[1] ??
    (() => {
      const type = javaParameterSimpleType(parameter);
      return type === undefined
        ? parameter.name
        : `${type.slice(0, 1).toLowerCase()}${type.slice(1)}`;
    })();
  const structuralLines = cFamilyStructuralLines(lines);
  const controls: Array<{ kind: string; line: number }> = [];
  for (let index = 0; index < structuralLines.length; index += 1) {
    const annotation = structuralLines[index] ?? "";
    const initBinder =
      /@(?:org\s*\.\s*springframework\s*\.\s*web\s*\.\s*bind\s*\.\s*annotation\s*\.\s*)?InitBinder\b/u;
    if (!initBinder.test(annotation)) continue;
    const annotationText = lines
      .slice(index, Math.min(lines.length, index + 6))
      .join("\n");
    const restricted =
      /@(?:org\s*\.\s*springframework\s*\.\s*web\s*\.\s*bind\s*\.\s*annotation\s*\.\s*)?InitBinder\s*\(([^)]*)\)/u.exec(
        annotationText,
      )?.[1];
    if (/\bInitBinder\s*\(/u.test(annotation) && restricted === undefined) {
      continue;
    }
    if (
      restricted !== undefined &&
      restricted.trim() !== "" &&
      !new RegExp(
        `["']${escapeRegularExpression(attributeName)}["']`,
        "u",
      ).test(restricted)
    ) {
      continue;
    }
    const declarationEnd = Math.min(lines.length, index + 9);
    const declaration = lines.slice(index, declarationEnd).join("\n");
    const binder =
      /(?:org\.springframework\.web\.bind\.)?WebDataBinder\s+([A-Za-z_$][\w$]*)\b/u.exec(
        declaration,
      )?.[1];
    if (binder === undefined) continue;
    const endLine = cFamilyFunctionEndLine(structuralLines, index);
    const escapedBinder = escapeRegularExpression(binder);
    for (let line = index + 1; line < endLine; line += 1) {
      const candidate = structuralLines[line] ?? "";
      if (
        new RegExp(
          `\\b${escapedBinder}\\s*\\.\\s*setAllowedFields\\s*\\(`,
          "u",
        ).test(candidate)
      ) {
        controls.push({ kind: "explicit-binding-allowlist", line: line + 1 });
      }
      if (
        new RegExp(
          `\\b${escapedBinder}\\s*\\.\\s*setDeclarativeBinding\\s*\\(\\s*true\\s*\\)`,
          "u",
        ).test(candidate)
      ) {
        controls.push({ kind: "constructor-only-binding", line: line + 1 });
      }
    }
  }
  return controls.filter(
    (control, index, all) =>
      all.findIndex(
        (candidate) =>
          candidate.kind === control.kind && candidate.line === control.line,
      ) === index,
  );
}

const JAVA_OBJECT_OWNER_FIELD =
  "(?:Account|Customer|Organization|Owner|Principal|Tenant|User|Workspace)Id";

function javaObjectAuthorizationSink(
  lines: readonly string[],
  sinkLine: number,
  methodEndLine = lines.length,
): JavaObjectAuthorizationSink | undefined {
  const baseLine = Math.max(1, sinkLine - 1);
  const callLines = lines.slice(
    baseLine - 1,
    Math.min(methodEndLine, sinkLine + 12),
  );
  const original = callLines.join("\n");
  const structural = cFamilyStructuralLines(callLines).join("\n");
  const call = new RegExp(
    `\\b([A-Za-z_$][\\w$]*)\\s*\\.\\s*(findById(?:And${JAVA_OBJECT_OWNER_FIELD})?)\\s*\\(`,
    "u",
  ).exec(structural);
  if (call?.index === undefined) return undefined;
  const methodIndex = structural.indexOf(call[2]!, call.index);
  const methodLine =
    baseLine + (structural.slice(0, methodIndex).match(/\n/gu)?.length ?? 0);
  if (methodLine !== sinkLine) return undefined;
  const open = structural.indexOf("(", call.index);
  const close = matchingCallParenthesis(structural, open);
  if (open < 0 || close < 0) return undefined;
  const arguments_ = splitJavascriptArguments(
    original.slice(open + 1, close),
  ).map((argument) => argument.trim());
  const argument = arguments_[0];
  if (argument === undefined || argument === "") return undefined;
  return {
    argument,
    arguments: arguments_,
    receiver: call[1]!,
    method: call[2]!,
    callStartLine: sinkLine,
    callEndLine:
      baseLine + (structural.slice(0, close).match(/\n/gu)?.length ?? 0),
  };
}

function javaSpringDataLookupHasTypedReceiver(
  files: readonly SourceFileSnapshot[],
  sourcePath: string,
  lines: readonly string[],
  sink: JavaObjectAuthorizationSink,
): boolean {
  const structuralText = cFamilyStructuralLines(lines).join("\n");
  const receiver = escapeRegularExpression(sink.receiver);
  const directRepository = new RegExp(
    `\\b(?:org\\s*\\.\\s*springframework\\s*\\.\\s*data\\s*\\.(?:\\s*jpa\\s*\\.)?\\s*repository\\s*\\.\\s*)?(?:CrudRepository|JpaRepository|PagingAndSortingRepository|Repository)\\s*<[^;{}]+>\\s+${receiver}\\b`,
    "u",
  );
  if (directRepository.test(structuralText)) {
    return javaSourceUsesOfficialSpringDataRepository(lines);
  }

  const bindings = javaReceiverBindings(lines).filter(
    (binding) => binding.receiver === sink.receiver,
  );
  if (bindings.length !== 1) return false;
  const repositoryType = bindings[0]!.ownerType;
  const declarations = files.filter((file) => {
    if (file.extension !== ".java") return false;
    const text = cFamilyStructuralLines(file.lines).join("\n");
    return new RegExp(
      `\\binterface\\s+${escapeRegularExpression(repositoryType)}\\b`,
      "u",
    ).test(text);
  });
  if (declarations.length !== 1) return false;
  const declaration = declarations[0]!;
  const declarationText = cFamilyStructuralLines(declaration.lines).join("\n");
  const extendsSpringData = new RegExp(
    `\\binterface\\s+${escapeRegularExpression(repositoryType)}(?:\\s*<[^>{}]+>)?\\s+extends\\s+(?:org\\s*\\.\\s*springframework\\s*\\.\\s*data\\s*\\.(?:\\s*jpa\\s*\\.)?\\s*repository\\s*\\.\\s*)?(?:CrudRepository|JpaRepository|PagingAndSortingRepository|Repository)\\s*<`,
    "u",
  ).test(declarationText);
  if (
    !extendsSpringData ||
    !javaSourceUsesOfficialSpringDataRepository(declaration.lines)
  ) {
    return false;
  }
  if (sink.method !== "findById") {
    const declaredMethod = new RegExp(
      `\\b${escapeRegularExpression(sink.method)}\\s*\\([^;{}]*\\)\\s*;`,
      "u",
    );
    if (!declaredMethod.test(declarationText)) return false;
  }
  return pathWithinDirectory(
    declaration.path,
    javaProjectRootForPath(files, sourcePath),
  );
}

function javaSourceUsesOfficialSpringDataRepository(
  lines: readonly string[],
): boolean {
  const text = cFamilyStructuralLines(lines).join("\n");
  if (
    /\b(?:class|interface|record)\s+(?:CrudRepository|JpaRepository|PagingAndSortingRepository|Repository)\b/u.test(
      text,
    )
  ) {
    return false;
  }
  return (
    /^\s*import\s+org\.springframework\.data\.(?:jpa\.)?repository\.(?:CrudRepository|JpaRepository|PagingAndSortingRepository|Repository)\s*;/mu.test(
      text,
    ) ||
    /\borg\s*\.\s*springframework\s*\.\s*data\s*\.(?:\s*jpa\s*\.)?\s*repository\s*\.\s*(?:CrudRepository|JpaRepository|PagingAndSortingRepository|Repository)\b/u.test(
      text,
    )
  );
}

function modeledSameFileJavaObjectSource(
  lines: readonly string[],
  sinkLine: number,
  lookupArgument: string,
  sourcePatterns: readonly FrameworkModelPattern[],
): { kind: string; line: number } | undefined {
  const method = exportedJavaMethods(lines).find(
    (candidate) =>
      sinkLine >= candidate.startLine && sinkLine <= candidate.endLine,
  );
  if (method === undefined) return undefined;
  const direct = modeledJavaCallSource(
    lines,
    method,
    sinkLine,
    lookupArgument.trim(),
    sourcePatterns,
  );
  if (direct !== undefined) return direct;
  for (const parameterIndex of javaMethodParameterIndexesReachingSink(
    lines,
    method,
    sinkLine,
    lookupArgument,
  )) {
    const parameter = method.parameters[parameterIndex];
    if (parameter === undefined) continue;
    const source = modeledJavaCallSource(
      lines,
      method,
      sinkLine,
      parameter.name,
      sourcePatterns,
    );
    if (source !== undefined) return source;
  }
  return undefined;
}

function javaObjectAuthorizationControls(
  files: readonly SourceFileSnapshot[],
  sourcePath: string,
  lines: readonly string[],
  sink: JavaObjectAuthorizationSink,
  enclosingMethod?: ExportedJavaMethod,
): Array<{ kind: string; line: number }> {
  const controls: Array<{ kind: string; line: number }> = [];
  const method =
    enclosingMethod ??
    exportedJavaMethods(lines).find(
      (candidate) =>
        sink.callStartLine >= candidate.startLine &&
        sink.callStartLine <= candidate.endLine,
    );
  if (method === undefined) return controls;
  if (
    sink.method !== "findById" &&
    sink.arguments[1] !== undefined &&
    javaAuthenticatedPrincipalExpression(lines, sink.arguments[1]!)
  ) {
    controls.push({
      kind: "principal-bound-object-query",
      line: sink.callStartLine,
    });
  }

  const postAuthorizeLine = javaEnforcedPostAuthorizeControl(
    files,
    sourcePath,
    lines,
    method,
  );
  if (postAuthorizeLine !== undefined) {
    controls.push({
      kind: "enabled-return-object-authorization",
      line: postAuthorizeLine,
    });
  }
  return controls;
}

function javaAuthenticatedPrincipalExpression(
  lines: readonly string[],
  expression: string,
): boolean {
  const text = cFamilyStructuralLines(lines).join("\n");
  if (
    /\b(?:class|interface|record)\s+(?:Authentication|Principal|SecurityContextHolder)\b/u.test(
      text,
    )
  ) {
    return false;
  }
  if (
    /\bSecurityContextHolder\s*\.\s*getContext\s*\(\s*\)\s*\.\s*getAuthentication\s*\(\s*\)\s*\.\s*getName\s*\(\s*\)/u.test(
      expression,
    )
  ) {
    return (
      /^\s*import\s+org\.springframework\.security\.core\.context\.SecurityContextHolder\s*;/mu.test(
        text,
      ) ||
      /\borg\s*\.\s*springframework\s*\.\s*security\s*\.\s*core\s*\.\s*context\s*\.\s*SecurityContextHolder\b/u.test(
        text,
      )
    );
  }
  const receiver = /\b([A-Za-z_$][\w$]*)\s*\.\s*getName\s*\(\s*\)/u.exec(
    expression,
  )?.[1];
  if (receiver === undefined) return false;
  const escaped = escapeRegularExpression(receiver);
  const authenticationBinding = new RegExp(
    `\\bAuthentication\\s+${escaped}\\b`,
    "u",
  ).test(text);
  const principalBinding = new RegExp(
    `\\bPrincipal\\s+${escaped}\\b`,
    "u",
  ).test(text);
  return (
    (authenticationBinding &&
      /^\s*import\s+org\.springframework\.security\.core\.Authentication\s*;/mu.test(
        text,
      )) ||
    (principalBinding &&
      /^\s*import\s+java\.security\.Principal\s*;/mu.test(text))
  );
}

function javaEnforcedPostAuthorizeControl(
  files: readonly SourceFileSnapshot[],
  sourcePath: string,
  lines: readonly string[],
  method: ExportedJavaMethod,
): number | undefined {
  if (!javaSpringMethodSecurityEnabled(files, sourcePath)) return undefined;
  const text = cFamilyStructuralLines(lines).join("\n");
  if (
    !javaSpringManagedBean(lines) ||
    /\b(?:save|saveAll|delete|deleteAll|deleteById|flush)\s*\(/u.test(
      cFamilyStructuralLines(
        lines.slice(method.startLine - 1, method.endLine),
      ).join("\n"),
    )
  ) {
    return undefined;
  }
  const hasOfficialPostAuthorize =
    /^\s*import\s+org\.springframework\.security\.access\.prepost\.PostAuthorize\s*;/mu.test(
      text,
    ) ||
    /@org\s*\.\s*springframework\s*\.\s*security\s*\.\s*access\s*\.\s*prepost\s*\.\s*PostAuthorize\b/u.test(
      text,
    );
  if (
    !hasOfficialPostAuthorize ||
    /\b@interface\s+PostAuthorize\b/u.test(text)
  ) {
    return undefined;
  }
  const startLine = Math.max(1, method.startLine - 8);
  const annotationLines = lines.slice(startLine - 1, method.startLine);
  const structuralAnnotations = cFamilyStructuralLines(annotationLines);
  const originalAnnotations = annotationLines.join("\n");
  const annotation = structuralAnnotations.findIndex((line) =>
    /@(?:org\.springframework\.security\.access\.prepost\.)?PostAuthorize\s*\(/u.test(
      line,
    ),
  );
  if (annotation < 0) return undefined;
  const ownerCheck = new RegExp(
    `returnObject\\s*\\.\\s*(?:get)?${JAVA_OBJECT_OWNER_FIELD}(?:\\s*\\(\\s*\\))?\\s*==\\s*authentication\\s*\\.\\s*(?:name|getName\\s*\\(\\s*\\))|authentication\\s*\\.\\s*(?:name|getName\\s*\\(\\s*\\))\\s*==\\s*returnObject\\s*\\.\\s*(?:get)?${JAVA_OBJECT_OWNER_FIELD}(?:\\s*\\(\\s*\\))?`,
    "iu",
  );
  if (!ownerCheck.test(originalAnnotations)) return undefined;
  return startLine + annotation;
}

function javaSpringManagedBean(lines: readonly string[]): boolean {
  const text = cFamilyStructuralLines(lines).join("\n");
  if (
    /\b@interface\s+(?:Component|Controller|RestController|Service)\b/u.test(
      text,
    )
  ) {
    return false;
  }
  const officialAnnotations = [
    {
      name: "Component",
      packageName: "org.springframework.stereotype.Component",
    },
    {
      name: "Controller",
      packageName: "org.springframework.stereotype.Controller",
    },
    {
      name: "RestController",
      packageName: "org.springframework.web.bind.annotation.RestController",
    },
    {
      name: "Service",
      packageName: "org.springframework.stereotype.Service",
    },
  ] as const;
  return officialAnnotations.some(({ name, packageName }) => {
    const escapedName = escapeRegularExpression(name);
    const escapedPackage = escapeRegularExpression(packageName);
    return (
      (new RegExp(`@${escapedName}\\b`, "u").test(text) &&
        new RegExp(`^\\s*import\\s+${escapedPackage}\\s*;`, "mu").test(text)) ||
      new RegExp(
        `@${escapedPackage.replaceAll("\\.", "\\s*\\.\\s*")}\\b`,
        "u",
      ).test(text)
    );
  });
}

function javaSpringMethodSecurityEnabled(
  files: readonly SourceFileSnapshot[],
  sourcePath: string,
): boolean {
  const projectRoot = javaProjectRootForPath(files, sourcePath);
  return files.some((file) => {
    if (
      file.extension !== ".java" ||
      !pathWithinDirectory(file.path, projectRoot)
    ) {
      return false;
    }
    const text = cFamilyStructuralLines(file.lines).join("\n");
    if (
      /\b@interface\s+(?:EnableGlobalMethodSecurity|EnableMethodSecurity)\b/u.test(
        text,
      )
    ) {
      return false;
    }
    const modern =
      (/^\s*import\s+org\.springframework\.security\.config\.annotation\.method\.configuration\.EnableMethodSecurity\s*;/mu.test(
        text,
      ) ||
        /@org\s*\.\s*springframework\s*\.\s*security\s*\.\s*config\s*\.\s*annotation\s*\.\s*method\s*\.\s*configuration\s*\.\s*EnableMethodSecurity\b/u.test(
          text,
        )) &&
      /@(?:org\.springframework\.security\.config\.annotation\.method\.configuration\.)?EnableMethodSecurity\b(?!\s*\([^)]*prePostEnabled\s*=\s*false)/u.test(
        text,
      );
    const legacy =
      /^\s*import\s+org\.springframework\.security\.config\.annotation\.method\.configuration\.EnableGlobalMethodSecurity\s*;/mu.test(
        text,
      ) &&
      /@EnableGlobalMethodSecurity\s*\([^)]*prePostEnabled\s*=\s*true/u.test(
        text,
      );
    return modern || legacy;
  });
}

function javaProjectRootForPath(
  files: readonly SourceFileSnapshot[],
  sourcePath: string,
): string {
  return (
    files
      .filter(
        (file) =>
          posix.basename(file.path).toLowerCase() === "pom.xml" &&
          pathWithinDirectory(sourcePath, posix.dirname(file.path)),
      )
      .map((file) => posix.dirname(file.path))
      .sort((left, right) => right.length - left.length)[0] ?? "."
  );
}

function javaBasenameProjectRootForPath(
  files: readonly SourceFileSnapshot[],
  sourcePath: string,
): string {
  return (
    files
      .filter(
        (file) =>
          javaProjectBoundaryFile(file.path) &&
          pathWithinDirectory(sourcePath, posix.dirname(file.path)),
      )
      .map((file) => posix.dirname(file.path))
      .sort((left, right) => right.length - left.length)[0] ?? "."
  );
}

function javaBasenameVisibleProjectRoots(
  graph: JavaBasenameProjectGraph,
  projectRoot: string,
): ReadonlySet<string> {
  return new Set([
    projectRoot,
    ...(graph.directDependencies.get(projectRoot) ?? []),
  ]);
}

function javaBasenameProjectCanRead(
  graph: JavaBasenameProjectGraph,
  callerRoot: string,
  helperRoot: string,
  callerPath: string,
  helperPath: string,
): boolean {
  if (callerRoot === helperRoot) return true;
  return (
    graph.directDependencies.get(callerRoot)?.has(helperRoot) === true &&
    javaConventionalJavaMainSource(callerRoot, callerPath) &&
    javaConventionalJavaMainSource(helperRoot, helperPath)
  );
}

function javaConventionalJavaMainSource(
  projectRoot: string,
  sourcePath: string,
): boolean {
  if (!pathWithinDirectory(sourcePath, projectRoot)) return false;
  const relative =
    projectRoot === "." ? sourcePath : sourcePath.slice(projectRoot.length + 1);
  return /^src\/main\/java\/[^/]+(?:\/[^/]+)*\.java$/u.test(relative);
}

function javaGradleProjectPath(value: string): string | undefined {
  const normalized = value.startsWith(":") ? value : `:${value}`;
  return /^:[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)*$/u.test(normalized)
    ? normalized
    : undefined;
}

function javaLiteralGradleIncludePaths(
  settingsFile: SourceFileSnapshot,
): ReadonlySet<string> | undefined {
  if (/(?:"""|'''|\$\/)/u.test(settingsFile.text)) return undefined;
  const structuralLines = cFamilyStructuralLines(settingsFile.lines);
  const structuralText = structuralLines.join("\n");
  if (/\b(?:buildFileName|includeBuild|projectDir)\b/u.test(structuralText)) {
    return undefined;
  }
  const quotedProject = String.raw`["'](:?[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)*)["']`;
  const parenthesized = new RegExp(
    String.raw`^\s*include\s*\(\s*(${quotedProject}(?:\s*,\s*${quotedProject})*)\s*\)\s*;?\s*$`,
    "u",
  );
  const groovy = new RegExp(
    String.raw`^\s*include\s+(${quotedProject}(?:\s*,\s*${quotedProject})*)\s*;?\s*$`,
    "u",
  );
  const quotedValue = /["']([^"']+)["']/gu;
  const paths = new Set<string>();
  for (let index = 0; index < settingsFile.lines.length; index += 1) {
    const structural = structuralLines[index] ?? "";
    if (!/\binclude\b/u.test(structural)) continue;
    if (!/^\s*include\b/u.test(structural)) return undefined;
    const original = settingsFile.lines[index] ?? "";
    const declaration = parenthesized.exec(original) ?? groovy.exec(original);
    if (declaration === null) return undefined;
    const list = declaration[1] ?? "";
    const declared = [...list.matchAll(quotedValue)].flatMap((match) =>
      match[1] === undefined ? [] : [match[1]],
    );
    if (declared.length === 0) return undefined;
    for (const value of declared) {
      const path = javaGradleProjectPath(value);
      if (path === undefined || paths.has(path)) return undefined;
      paths.add(path);
    }
  }
  return paths;
}

function javaExactGradleBuildFile(
  files: readonly SourceFileSnapshot[],
  projectRoot: string,
): SourceFileSnapshot | undefined {
  const candidates = files.filter(
    (file) =>
      posix.dirname(file.path) === projectRoot &&
      /^(?:build\.gradle|build\.gradle\.kts)$/iu.test(
        posix.basename(file.path),
      ),
  );
  return candidates.length === 1 ? candidates[0] : undefined;
}

function javaStructuralBraceDepthBefore(
  structural: string,
  before: number,
): number {
  let depth = 0;
  for (const character of structural.slice(0, before)) {
    if (character === "{") depth += 1;
    else if (character === "}") depth = Math.max(0, depth - 1);
  }
  return depth;
}

function javaLiteralGradleCompileProjectDependencies(
  buildFile: SourceFileSnapshot,
): ReadonlySet<string> {
  if (/(?:"""|'''|\$\/)/u.test(buildFile.text)) return new Set<string>();
  const original = buildFile.lines.join("\n");
  const structural = cFamilyStructuralLines(buildFile.lines).join("\n");
  const paths = new Set<string>();
  const blockStart = /\bdependencies\s*\{/gu;
  const quotedProject = String.raw`["'](:[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)*)["']`;
  const configuration = String.raw`(?:api|implementation|compileOnly|compileOnlyApi)`;
  const parenthesized = new RegExp(
    String.raw`^\s*${configuration}\s*\(\s*project\s*\(\s*${quotedProject}\s*\)\s*\)\s*;?\s*$`,
    "u",
  );
  const groovy = new RegExp(
    String.raw`^\s*${configuration}\s+project\s*\(\s*${quotedProject}\s*\)\s*;?\s*$`,
    "u",
  );
  for (const match of structural.matchAll(blockStart)) {
    if (
      match.index === undefined ||
      javaStructuralBraceDepthBefore(structural, match.index) !== 0
    ) {
      continue;
    }
    const open = structural.indexOf("{", match.index);
    const close = matchingStructuralBrace(structural, open);
    if (open < 0 || close < 0) continue;
    const originalLines = original.slice(open + 1, close).split("\n");
    const structuralLines = structural.slice(open + 1, close).split("\n");
    let depth = 0;
    for (let index = 0; index < structuralLines.length; index += 1) {
      const structuralLine = structuralLines[index] ?? "";
      if (
        depth === 0 &&
        new RegExp(String.raw`^\s*${configuration}\b`, "u").test(
          structuralLine,
        ) &&
        /\bproject\s*\(/u.test(structuralLine)
      ) {
        const originalLine = originalLines[index] ?? "";
        const declaration =
          parenthesized.exec(originalLine) ?? groovy.exec(originalLine);
        const path = declaration?.[1];
        if (path !== undefined) paths.add(path);
      }
      for (const character of structuralLine) {
        if (character === "{") depth += 1;
        else if (character === "}") depth = Math.max(0, depth - 1);
      }
    }
  }
  return paths;
}

function javaMavenXml(text: string): JavaMavenXmlElement | undefined {
  const token =
    /<!--[\s\S]*?-->|<\?xml(?:\s+[A-Za-z_:][A-Za-z0-9_.:-]*\s*=\s*(?:"[^"<]*"|'[^'<]*'))*\s*\?>|<\/[A-Za-z][A-Za-z0-9.-]*\s*>|<[A-Za-z][A-Za-z0-9.-]*(?:\s+[A-Za-z_:][A-Za-z0-9_.:-]*\s*=\s*(?:"[^"<]*"|'[^'<]*'))*\s*\/?>|[^<]+/gu;
  const opening =
    /^<([A-Za-z][A-Za-z0-9.-]*)(?:\s+[A-Za-z_:][A-Za-z0-9_.:-]*\s*=\s*(?:"[^"<]*"|'[^'<]*'))*\s*(\/?)>$/u;
  const closing = /^<\/([A-Za-z][A-Za-z0-9.-]*)\s*>$/u;
  const stack: JavaMavenXmlElement[] = [];
  let root: JavaMavenXmlElement | undefined;
  let xmlDeclarationSeen = false;
  let cursor = 0;
  for (const match of text.matchAll(token)) {
    if (match.index !== cursor) return undefined;
    const value = match[0];
    cursor += value.length;
    if (value.startsWith("<!--")) continue;
    if (value.includes("&")) return undefined;
    if (value.startsWith("<?xml")) {
      if (xmlDeclarationSeen || root !== undefined) return undefined;
      xmlDeclarationSeen = true;
      continue;
    }
    if (value.startsWith("</")) {
      const name = closing.exec(value)?.[1];
      if (name === undefined || stack.at(-1)?.name !== name) return undefined;
      stack.pop();
      continue;
    }
    if (value.startsWith("<")) {
      const declaration = opening.exec(value);
      const name = declaration?.[1];
      if (name === undefined) return undefined;
      const element: JavaMavenXmlElement = {
        name,
        children: [],
        text: "",
      };
      const parent = stack.at(-1);
      if (parent === undefined) {
        if (root !== undefined) return undefined;
        root = element;
      } else {
        parent.children.push(element);
      }
      if (declaration?.[2] !== "/") {
        if (stack.length >= MAX_JAVA_MAVEN_MODEL_DEPTH) return undefined;
        stack.push(element);
      }
      continue;
    }
    const current = stack.at(-1);
    if (current === undefined) {
      if (value.trim() !== "") return undefined;
    } else {
      current.text += value;
    }
  }
  return cursor === text.length && stack.length === 0 ? root : undefined;
}

function javaMavenUniqueValue(
  element: JavaMavenXmlElement,
  name: string,
): string | null | undefined {
  const matches = element.children.filter((child) => child.name === name);
  if (matches.length > 1) return null;
  const match = matches[0];
  if (match === undefined) return undefined;
  if (match.children.length > 0) return null;
  return match.text.trim();
}

function javaMavenLiteralCoordinate(value: string): boolean {
  return /^[A-Za-z0-9_.+~-]+$/u.test(value);
}

function javaMavenDependency(
  element: JavaMavenXmlElement,
): JavaMavenDependency | undefined {
  const groupId = javaMavenUniqueValue(element, "groupId");
  const artifactId = javaMavenUniqueValue(element, "artifactId");
  const version = javaMavenUniqueValue(element, "version");
  const scope = javaMavenUniqueValue(element, "scope");
  const type = javaMavenUniqueValue(element, "type");
  const classifier = javaMavenUniqueValue(element, "classifier");
  if (
    groupId === undefined ||
    groupId === null ||
    artifactId === undefined ||
    artifactId === null ||
    version === undefined ||
    version === null ||
    scope === null ||
    type === null ||
    classifier === null ||
    !javaMavenLiteralCoordinate(groupId) ||
    !javaMavenLiteralCoordinate(artifactId) ||
    !javaMavenLiteralCoordinate(version) ||
    (scope !== undefined && !/^[A-Za-z]+$/u.test(scope)) ||
    (type !== undefined && !/^[A-Za-z0-9_.-]+$/u.test(type)) ||
    (classifier !== undefined && !javaMavenLiteralCoordinate(classifier))
  ) {
    return undefined;
  }
  return { groupId, artifactId, version, scope, type, classifier };
}

function javaMavenPom(file: SourceFileSnapshot): JavaMavenPom | undefined {
  const project = javaMavenXml(file.text);
  if (project?.name !== "project" || project.text.trim() !== "") {
    return undefined;
  }
  const groupId = javaMavenUniqueValue(project, "groupId");
  const artifactId = javaMavenUniqueValue(project, "artifactId");
  const version = javaMavenUniqueValue(project, "version");
  const packaging = javaMavenUniqueValue(project, "packaging");
  const modelVersion = javaMavenUniqueValue(project, "modelVersion");
  if (
    modelVersion !== "4.0.0" ||
    groupId === null ||
    artifactId === undefined ||
    artifactId === null ||
    version === null ||
    packaging === null ||
    (groupId !== undefined && !javaMavenLiteralCoordinate(groupId)) ||
    !javaMavenLiteralCoordinate(artifactId) ||
    (version !== undefined && !javaMavenLiteralCoordinate(version)) ||
    (packaging !== undefined && !/^[A-Za-z0-9_.-]+$/u.test(packaging))
  ) {
    return undefined;
  }

  const parentElements = project.children.filter(
    (child) => child.name === "parent",
  );
  if (parentElements.length > 1) return undefined;
  let parent: JavaMavenParent | undefined;
  if (parentElements[0] !== undefined) {
    const element = parentElements[0];
    if (element.text.trim() !== "") return undefined;
    const parentGroupId = javaMavenUniqueValue(element, "groupId");
    const parentArtifactId = javaMavenUniqueValue(element, "artifactId");
    const parentVersion = javaMavenUniqueValue(element, "version");
    const relativePath = javaMavenUniqueValue(element, "relativePath");
    if (
      parentGroupId === undefined ||
      parentGroupId === null ||
      parentArtifactId === undefined ||
      parentArtifactId === null ||
      parentVersion === undefined ||
      parentVersion === null ||
      relativePath === null ||
      !javaMavenLiteralCoordinate(parentGroupId) ||
      !javaMavenLiteralCoordinate(parentArtifactId) ||
      !javaMavenLiteralCoordinate(parentVersion)
    ) {
      return undefined;
    }
    parent = {
      groupId: parentGroupId,
      artifactId: parentArtifactId,
      version: parentVersion,
      relativePath: relativePath === "" ? undefined : relativePath,
      localResolutionDisabled: relativePath === "",
    };
  }

  const modulesElements = project.children.filter(
    (child) => child.name === "modules",
  );
  if (modulesElements.length > 1) return undefined;
  const modules: string[] = [];
  if (modulesElements[0] !== undefined) {
    const element = modulesElements[0];
    if (element.text.trim() !== "" || packaging !== "pom") return undefined;
    for (const child of element.children) {
      const value = child.text.trim();
      if (
        child.name !== "module" ||
        child.children.length > 0 ||
        !/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/u.test(value) ||
        value
          .split("/")
          .some((segment) => segment === "." || segment === "..") ||
        modules.includes(value)
      ) {
        return undefined;
      }
      modules.push(value);
    }
  }

  const dependenciesElements = project.children.filter(
    (child) => child.name === "dependencies",
  );
  if (dependenciesElements.length > 1) return undefined;
  const dependencies: JavaMavenDependency[] = [];
  if (dependenciesElements[0] !== undefined) {
    const element = dependenciesElements[0];
    if (element.text.trim() !== "") return undefined;
    for (const child of element.children) {
      const dependency =
        child.name === "dependency" && child.text.trim() === ""
          ? javaMavenDependency(child)
          : undefined;
      if (dependency !== undefined) dependencies.push(dependency);
    }
  }
  return {
    root: posix.dirname(file.path),
    groupId,
    artifactId,
    version,
    packaging,
    parent,
    modules,
    dependencies,
  };
}

function javaMavenRepositoryPath(value: string): string | undefined {
  const normalized = posix.normalize(value);
  return normalized === ".." ||
    normalized.startsWith("../") ||
    normalized.startsWith("/")
    ? undefined
    : normalized;
}

function javaMavenParentRoot(
  pom: JavaMavenPom,
  poms: ReadonlyMap<string, JavaMavenPom>,
): string | undefined {
  if (pom.parent === undefined || pom.parent.localResolutionDisabled) {
    return undefined;
  }
  const relativePath = pom.parent.relativePath ?? "../pom.xml";
  if (
    !/^(?:\.{1,2}|[A-Za-z0-9_.-]+)(?:\/(?:\.{1,2}|[A-Za-z0-9_.-]+))*\/pom\.xml$|^pom\.xml$/u.test(
      relativePath,
    )
  ) {
    return undefined;
  }
  const candidate = javaMavenRepositoryPath(posix.join(pom.root, relativePath));
  if (candidate === undefined || posix.basename(candidate) !== "pom.xml") {
    return undefined;
  }
  const root = posix.dirname(candidate);
  return poms.has(root) ? root : undefined;
}

function javaMavenEffectiveCoordinates(
  root: string,
  poms: ReadonlyMap<string, JavaMavenPom>,
  cache: Map<string, JavaMavenCoordinates | undefined>,
  active = new Set<string>(),
): JavaMavenCoordinates | undefined {
  if (cache.has(root)) return cache.get(root);
  if (active.has(root) || active.size >= MAX_JAVA_MAVEN_MODEL_DEPTH) {
    return undefined;
  }
  const pom = poms.get(root);
  if (pom === undefined) return undefined;
  const nextActive = new Set(active).add(root);
  const parentRoot = javaMavenParentRoot(pom, poms);
  let inherited: JavaMavenCoordinates | undefined;
  if (parentRoot !== undefined) {
    inherited = javaMavenEffectiveCoordinates(
      parentRoot,
      poms,
      cache,
      nextActive,
    );
    if (
      inherited === undefined ||
      pom.parent === undefined ||
      inherited.groupId !== pom.parent.groupId ||
      inherited.artifactId !== pom.parent.artifactId ||
      inherited.version !== pom.parent.version
    ) {
      cache.set(root, undefined);
      return undefined;
    }
  }
  const groupId = pom.groupId ?? inherited?.groupId;
  const version = pom.version ?? inherited?.version;
  const coordinates =
    groupId === undefined || version === undefined
      ? undefined
      : { groupId, artifactId: pom.artifactId, version };
  cache.set(root, coordinates);
  return coordinates;
}

function javaMavenModuleRoot(
  aggregatorRoot: string,
  module: string,
  poms: ReadonlyMap<string, JavaMavenPom>,
): string | undefined {
  const candidate = javaMavenRepositoryPath(posix.join(aggregatorRoot, module));
  return candidate !== undefined && poms.has(candidate) ? candidate : undefined;
}

function javaMavenReactor(
  root: string,
  poms: ReadonlyMap<string, JavaMavenPom>,
  active = new Set<string>(),
): ReadonlySet<string> | undefined {
  if (active.has(root) || active.size >= MAX_JAVA_MAVEN_MODEL_DEPTH) {
    return undefined;
  }
  const pom = poms.get(root);
  if (pom === undefined) return undefined;
  const projects = new Set([root]);
  const nextActive = new Set(active).add(root);
  for (const module of pom.modules) {
    const moduleRoot = javaMavenModuleRoot(root, module, poms);
    if (moduleRoot === undefined) return undefined;
    const nested = javaMavenReactor(moduleRoot, poms, nextActive);
    if (nested === undefined) return undefined;
    for (const project of nested) {
      if (projects.has(project)) return undefined;
      projects.add(project);
    }
  }
  return projects;
}

function javaMavenCompileProjectDependencies(
  files: readonly SourceFileSnapshot[],
): ReadonlyMap<string, ReadonlySet<string>> {
  const poms = new Map<string, JavaMavenPom>();
  for (const file of files) {
    if (posix.basename(file.path).toLowerCase() !== "pom.xml") continue;
    const pom = javaMavenPom(file);
    if (pom !== undefined) poms.set(pom.root, pom);
  }
  const moduleOwners = new Set<string>();
  for (const pom of poms.values()) {
    for (const module of pom.modules) {
      const moduleRoot = javaMavenModuleRoot(pom.root, module, poms);
      if (moduleRoot !== undefined) moduleOwners.add(moduleRoot);
    }
  }
  const reactors: ReadonlySet<string>[] = [];
  for (const pom of poms.values()) {
    if (pom.modules.length === 0 || moduleOwners.has(pom.root)) continue;
    const reactor = javaMavenReactor(pom.root, poms);
    if (reactor !== undefined) reactors.push(reactor);
  }
  const ownerCounts = new Map<string, number>();
  for (const reactor of reactors) {
    for (const root of reactor) {
      ownerCounts.set(root, (ownerCounts.get(root) ?? 0) + 1);
    }
  }
  const coordinateCache = new Map<string, JavaMavenCoordinates | undefined>();
  const dependencies = new Map<string, Set<string>>();
  for (const reactor of reactors) {
    if ([...reactor].some((root) => ownerCounts.get(root) !== 1)) continue;
    const coordinates = new Map<string, JavaMavenCoordinates>();
    for (const root of reactor) {
      const value = javaMavenEffectiveCoordinates(root, poms, coordinateCache);
      if (value !== undefined) coordinates.set(root, value);
    }
    for (const callerRoot of reactor) {
      if (ownerCounts.get(callerRoot) !== 1) continue;
      const caller = poms.get(callerRoot);
      if (caller === undefined) continue;
      for (const dependency of caller.dependencies) {
        if (
          ![undefined, "compile", "provided"].includes(dependency.scope) ||
          ![undefined, "jar"].includes(dependency.type) ||
          dependency.classifier !== undefined
        ) {
          continue;
        }
        const targets = [...coordinates].filter(
          ([targetRoot, target]) =>
            targetRoot !== callerRoot &&
            ownerCounts.get(targetRoot) === 1 &&
            target.groupId === dependency.groupId &&
            target.artifactId === dependency.artifactId &&
            target.version === dependency.version &&
            [undefined, "jar"].includes(poms.get(targetRoot)?.packaging),
        );
        if (targets.length !== 1) continue;
        const direct = dependencies.get(callerRoot) ?? new Set<string>();
        direct.add(targets[0]![0]);
        dependencies.set(callerRoot, direct);
      }
    }
  }
  return dependencies;
}

function javaBasenameProjectGraph(
  files: readonly SourceFileSnapshot[],
): JavaBasenameProjectGraph {
  const settingsGroups = new Map<string, SourceFileSnapshot[]>();
  for (const file of files) {
    if (
      !/^(?:settings\.gradle|settings\.gradle\.kts)$/iu.test(
        posix.basename(file.path),
      )
    ) {
      continue;
    }
    const root = posix.dirname(file.path);
    const group = settingsGroups.get(root) ?? [];
    group.push(file);
    settingsGroups.set(root, group);
  }
  const builds: Array<ReadonlyMap<string, string>> = [];
  for (const [settingsRoot, settingsFiles] of settingsGroups) {
    if (settingsFiles.length !== 1) continue;
    const included = javaLiteralGradleIncludePaths(settingsFiles[0]!);
    if (included === undefined) continue;
    const projects = new Map<string, string>();
    if (javaExactGradleBuildFile(files, settingsRoot) !== undefined) {
      projects.set(":", settingsRoot);
    }
    for (const projectPath of included) {
      const segments = projectPath.slice(1).split(":");
      const projectRoot = posix.join(settingsRoot, ...segments);
      if (
        javaExactGradleBuildFile(files, projectRoot) === undefined ||
        [...projects.values()].includes(projectRoot)
      ) {
        continue;
      }
      projects.set(projectPath, projectRoot);
    }
    if (projects.size > 0) builds.push(projects);
  }
  const ownerCounts = new Map<string, number>();
  for (const projects of builds) {
    for (const root of projects.values()) {
      ownerCounts.set(root, (ownerCounts.get(root) ?? 0) + 1);
    }
  }
  const mutable = new Map<string, Set<string>>();
  for (const projects of builds) {
    for (const callerRoot of projects.values()) {
      if (ownerCounts.get(callerRoot) !== 1) continue;
      const buildFile = javaExactGradleBuildFile(files, callerRoot);
      if (buildFile === undefined) continue;
      for (const dependencyPath of javaLiteralGradleCompileProjectDependencies(
        buildFile,
      )) {
        const dependencyRoot = projects.get(dependencyPath);
        if (
          dependencyRoot === undefined ||
          dependencyRoot === callerRoot ||
          ownerCounts.get(dependencyRoot) !== 1
        ) {
          continue;
        }
        const dependencies = mutable.get(callerRoot) ?? new Set<string>();
        dependencies.add(dependencyRoot);
        mutable.set(callerRoot, dependencies);
      }
    }
  }
  for (const [callerRoot, dependencies] of javaMavenCompileProjectDependencies(
    files,
  )) {
    const direct = mutable.get(callerRoot) ?? new Set<string>();
    for (const dependency of dependencies) direct.add(dependency);
    mutable.set(callerRoot, direct);
  }
  return { directDependencies: mutable };
}

function javaProjectBoundaryFile(path: string): boolean {
  return JAVA_PROJECT_BOUNDARY_FILES.has(posix.basename(path).toLowerCase());
}

interface DotnetRazorBoundProperty {
  name: string;
  line: number;
  supportsGet: boolean;
}

function dotnetProjectDeclaresType(
  files: readonly SourceFileSnapshot[],
  names: readonly string[],
  namespace?: string,
): boolean {
  const alternatives = names.map(escapeRegularExpression).join("|");
  const type = new RegExp(
    `\\b(?:class|interface|record|struct)\\s+(?:${alternatives})\\b`,
    "u",
  );
  return files.some((file) => {
    if (file.extension !== ".cs") return false;
    const structural = cFamilyStructuralLines(file.lines).join("\n");
    if (!type.test(structural)) return false;
    return (
      namespace === undefined ||
      new RegExp(
        `\\bnamespace\\s+${escapeRegularExpression(namespace).replaceAll("\\\\.", "\\\\s*\\\\.\\\\s*")}\\b`,
        "u",
      ).test(structural)
    );
  });
}

function dotnetUsesNamespace(
  lines: readonly string[],
  namespace: string,
): boolean {
  const dotted = escapeRegularExpression(namespace).replaceAll(
    "\\\\.",
    "\\\\s*\\\\.\\\\s*",
  );
  return new RegExp(`^\\s*(?:global\\s+)?using\\s+${dotted}\\s*;`, "mu").test(
    cFamilyStructuralLines(lines).join("\n"),
  );
}

function dotnetHasOfficialAttribute(
  fragment: string,
  shortName: string,
  namespace: string,
  files: readonly SourceFileSnapshot[],
  declaringLines: readonly string[],
): boolean {
  const normalized = fragment.replace(/\s+/gu, "");
  const qualified = `${namespace}.${shortName}`;
  const fullyQualified =
    normalized.includes(`[${qualified}`) ||
    normalized.includes(`[${qualified}Attribute`) ||
    normalized.includes(`[global::${qualified}`) ||
    normalized.includes(`[global::${qualified}Attribute`);
  if (fullyQualified) {
    return !dotnetProjectDeclaresType(
      files,
      [shortName, `${shortName}Attribute`],
      namespace,
    );
  }
  const unqualified = new RegExp(
    `\\[\\s*${escapeRegularExpression(shortName)}(?:Attribute)?\\b`,
    "u",
  ).test(fragment);
  return (
    unqualified &&
    dotnetUsesNamespace(declaringLines, namespace) &&
    !dotnetProjectDeclaresType(files, [shortName, `${shortName}Attribute`])
  );
}

function dotnetDeclaredBaseType(
  lines: readonly string[],
  ownerType: string,
): string | undefined {
  const structural = cFamilyStructuralLines(lines).join("\n");
  const declaration = new RegExp(
    `\\b(?:class|record)\\s+${escapeRegularExpression(ownerType)}(?:\\s*<[^;{}]+>)?\\s*:\\s*([^{}]+)\\{`,
    "u",
  ).exec(structural)?.[1];
  const base =
    declaration === undefined
      ? undefined
      : splitJavascriptArguments(declaration)[0]?.trim();
  if (base === undefined || base === "") return undefined;
  return base.replace(/\s+/gu, "");
}

function dotnetIsRazorPageModel(
  files: readonly SourceFileSnapshot[],
  path: string,
  lines: readonly string[],
  ownerType: string,
  depth = 0,
  visited = new Set<string>(),
): boolean {
  if (depth > 8 || visited.has(ownerType)) return false;
  visited.add(ownerType);
  const base = dotnetDeclaredBaseType(lines, ownerType);
  if (base === undefined) return false;
  const official = "Microsoft.AspNetCore.Mvc.RazorPages.PageModel";
  if (base === official || base === `global::${official}`) {
    return !dotnetProjectDeclaresType(
      files,
      ["PageModel"],
      official.slice(0, -10),
    );
  }
  if (base === "PageModel") {
    return (
      dotnetUsesNamespace(lines, "Microsoft.AspNetCore.Mvc.RazorPages") &&
      !dotnetProjectDeclaresType(files, ["PageModel"])
    );
  }
  if (!/^[A-Za-z_]\w*$/u.test(base)) return false;
  const candidates = files.filter(
    (file) =>
      file.extension === ".cs" &&
      dotnetOwnerType(file.lines) === base &&
      file.path !== path,
  );
  if (candidates.length !== 1) return false;
  const candidate = candidates[0]!;
  return dotnetIsRazorPageModel(
    files,
    candidate.path,
    candidate.lines,
    base,
    depth + 1,
    visited,
  );
}

function dotnetRazorHandlerMethod(
  files: readonly SourceFileSnapshot[],
  lines: readonly string[],
  method: ExportedDotnetMethod,
): boolean {
  if (
    method.access !== "public" ||
    method.isStatic ||
    !/^On(?:Get|Post|Put|Delete|Patch|Head|Options|Trace|Connect)[A-Za-z0-9_]*(?:Async)?$/u.test(
      method.symbol,
    )
  ) {
    return false;
  }
  const structuralLines = cFamilyStructuralLines(lines);
  let attributeStart = method.startLine - 1;
  while (
    attributeStart > 0 &&
    /^\s*\[/u.test(structuralLines[attributeStart - 1] ?? "")
  ) {
    attributeStart -= 1;
  }
  const fragment = lines
    .slice(attributeStart, Math.min(lines.length, method.startLine + 8))
    .join("\n");
  return !dotnetHasOfficialAttribute(
    fragment,
    "NonHandler",
    "Microsoft.AspNetCore.Mvc.RazorPages",
    files,
    lines,
  );
}

function dotnetRazorHandlerParameterAllowed(declaration: string): boolean {
  if (
    /\[\s*(?:FromServices|FromKeyedServices|BindNever)(?:Attribute)?\b/iu.test(
      declaration,
    )
  ) {
    return false;
  }
  return !/\b(?:CancellationToken|IServiceProvider|ILogger(?:\s*<[^;{}]+>)?|PageContext|ViewDataDictionary(?:\s*<[^;{}]+>)?|ModelStateDictionary|IUrlHelper|ClaimsPrincipal|HttpContext|HttpRequest|HttpResponse)\b/u.test(
    declaration,
  );
}

function dotnetRazorBoundProperties(
  files: readonly SourceFileSnapshot[],
  lines: readonly string[],
  ownerType: string,
): DotnetRazorBoundProperty[] {
  const structuralLines = cFamilyStructuralLines(lines);
  const ownerIndex = structuralLines.findIndex((line) =>
    new RegExp(
      `\\b(?:class|record)\\s+${escapeRegularExpression(ownerType)}\\b`,
      "u",
    ).test(line),
  );
  const ownerFragment = lines
    .slice(Math.max(0, ownerIndex - 8), ownerIndex + 1)
    .join("\n");
  const classBound =
    ownerIndex >= 0 &&
    dotnetHasOfficialAttribute(
      ownerFragment,
      "BindProperties",
      "Microsoft.AspNetCore.Mvc",
      files,
      lines,
    );
  const classSupportsGet =
    classBound && /\bSupportsGet\s*=\s*true\b/iu.test(ownerFragment);
  const properties: DotnetRazorBoundProperty[] = [];
  for (
    let index = Math.max(0, ownerIndex + 1);
    index < lines.length;
    index += 1
  ) {
    if (!/\bpublic\b/u.test(structuralLines[index] ?? "")) continue;
    let start = index;
    while (
      start > ownerIndex + 1 &&
      /^\s*\[/u.test(structuralLines[start - 1] ?? "")
    ) {
      start -= 1;
    }
    const fragment = lines
      .slice(start, Math.min(lines.length, index + 6))
      .join(" ");
    const structural = cFamilyStructuralLines(
      lines.slice(start, Math.min(lines.length, index + 6)),
    ).join(" ");
    const property =
      /^(?:\s*\[[^\]]+\]\s*)*\s*public\s+(?!static\b)(?:required\s+)?[A-Za-z_][\w.<>?,\[\]]*\s+([A-Za-z_]\w*)\s*\{\s*(?:get\s*;\s*set\s*;|set\s*;\s*get\s*;)\s*\}/u.exec(
        structural,
      );
    const name = property?.[1];
    if (name === undefined) continue;
    const directlyBound = dotnetHasOfficialAttribute(
      fragment,
      "BindProperty",
      "Microsoft.AspNetCore.Mvc",
      files,
      lines,
    );
    if (!directlyBound && !classBound) continue;
    if (
      dotnetHasOfficialAttribute(
        fragment,
        "BindNever",
        "Microsoft.AspNetCore.Mvc.ModelBinding",
        files,
        lines,
      )
    ) {
      continue;
    }
    properties.push({
      name,
      line: index + 1,
      supportsGet:
        (directlyBound && /\bSupportsGet\s*=\s*true\b/iu.test(fragment)) ||
        classSupportsGet,
    });
  }
  return properties;
}

function dotnetRazorPropertiesForHandler(
  properties: readonly DotnetRazorBoundProperty[],
  method: ExportedDotnetMethod,
): readonly DotnetRazorBoundProperty[] {
  return /^On(?:Get|Head)/u.test(method.symbol)
    ? properties.filter((property) => property.supportsGet)
    : properties;
}

function dotnetRazorPageSources(
  files: readonly SourceFileSnapshot[],
  path: string,
  lines: readonly string[],
): Array<{ kind: string; line: number }> {
  const ownerType = dotnetOwnerType(lines);
  if (
    ownerType === undefined ||
    !dotnetIsRazorPageModel(files, path, lines, ownerType)
  ) {
    return [];
  }
  const properties = dotnetRazorBoundProperties(files, lines, ownerType);
  const sources: Array<{ kind: string; line: number }> = [];
  for (const method of exportedDotnetMethods(lines)) {
    if (!dotnetRazorHandlerMethod(files, lines, method)) continue;
    for (const parameter of method.parameters) {
      if (dotnetRazorHandlerParameterAllowed(parameter.declaration)) {
        sources.push({
          kind: "aspnet-razor-page-handler-parameter",
          line: method.startLine,
        });
      }
    }
    for (const property of dotnetRazorPropertiesForHandler(
      properties,
      method,
    )) {
      sources.push({
        kind: "aspnet-razor-page-bound-property",
        line: property.line,
      });
    }
  }
  return sources;
}

function dotnetRazorBoundPropertySource(
  lines: readonly string[],
  method: ExportedDotnetMethod,
  callLine: number,
  expression: string,
  properties: readonly DotnetRazorBoundProperty[],
): { kind: string; line: number } | undefined {
  const reaching = new Map<string, DotnetRazorBoundProperty>();
  for (const property of properties) {
    const shadowedByParameter = method.parameters.some(
      (parameter) => parameter.name === property.name,
    );
    if (
      !shadowedByParameter ||
      new RegExp(
        `\\bthis\\s*\\.\\s*${escapeRegularExpression(property.name)}\\b`,
        "u",
      ).test(expression)
    ) {
      reaching.set(property.name, property);
    }
  }
  const structuralLines = cFamilyStructuralLines(lines);
  for (let line = method.startLine + 1; line < callLine; line += 1) {
    const structural = structuralLines[line - 1] ?? "";
    const assignment =
      /\b(?:(?:var|[A-Za-z_]\w*(?:\s*<[^;{}]+>)?\??)\s+)?((?:this\s*\.\s*)?[A-Za-z_]\w*)\s*=(?!=|>)([^;]+);/u.exec(
        structural,
      );
    if (assignment !== null) {
      const target = assignment[1]!
        .replace(/\s+/gu, "")
        .replace(/^this\./u, "");
      const value = assignment[2]!;
      const source = [...reaching.entries()].find(([identifier]) =>
        cFamilyLineReferencesIdentifier(value, identifier),
      )?.[1];
      if (source === undefined) reaching.delete(target);
      else reaching.set(target, source);
    }
    for (const [identifier] of reaching) {
      const memberWrite = new RegExp(
        `\\b(?:this\\s*\\.\\s*)?${escapeRegularExpression(identifier)}\\s*\\.\\s*[A-Za-z_]\\w*\\s*=(?!=|>)`,
        "u",
      );
      if (memberWrite.test(structural)) reaching.delete(identifier);
    }
  }
  const reached = [...reaching.entries()].find(([identifier]) =>
    cFamilyLineReferencesIdentifier(expression, identifier),
  )?.[1];
  return reached === undefined
    ? undefined
    : { kind: "aspnet-razor-page-bound-property", line: reached.line };
}

function modeledRazorPageSource(
  lines: readonly string[],
  method: ExportedDotnetMethod,
  callLine: number,
  expression: string,
  rejectParameterReassignment: boolean,
  files: readonly SourceFileSnapshot[],
  path: string,
): { kind: string; line: number } | undefined {
  if (
    !dotnetRazorHandlerMethod(files, lines, method) ||
    !dotnetIsRazorPageModel(files, path, lines, method.ownerType)
  ) {
    return undefined;
  }
  for (const parameterIndex of dotnetMethodParameterIndexesReachingExpression(
    lines,
    method,
    callLine,
    expression,
  )) {
    const parameter = method.parameters[parameterIndex];
    if (
      parameter !== undefined &&
      dotnetRazorHandlerParameterAllowed(parameter.declaration) &&
      (!rejectParameterReassignment ||
        !dotnetMethodParameterReassignedBeforeCall(
          lines,
          parameter.name,
          method.startLine,
          callLine,
        ))
    ) {
      return {
        kind: "aspnet-razor-page-handler-parameter",
        line: method.startLine,
      };
    }
  }
  const properties = dotnetRazorPropertiesForHandler(
    dotnetRazorBoundProperties(files, lines, method.ownerType),
    method,
  );
  return dotnetRazorBoundPropertySource(
    lines,
    method,
    callLine,
    expression,
    properties,
  );
}

function modeledDotnetCallSource(
  lines: readonly string[],
  method: ExportedDotnetMethod,
  callLine: number,
  argument: string,
  sourcePatterns: readonly FrameworkModelPattern[],
  rejectParameterReassignment = false,
  files: readonly SourceFileSnapshot[] = [],
  path = "",
): { kind: string; line: number } | undefined {
  const direct = sourcePatterns.find((pattern) =>
    pattern.expression.test(argument),
  );
  if (direct !== undefined) return { kind: direct.kind, line: callLine };
  const razorSource = modeledRazorPageSource(
    lines,
    method,
    callLine,
    argument,
    rejectParameterReassignment,
    files,
    path,
  );
  if (razorSource !== undefined) return razorSource;
  if (!/^[A-Za-z_]\w*$/u.test(argument)) return undefined;
  for (const parameter of method.parameters) {
    if (parameter.name !== argument) continue;
    const source = sourcePatterns.find((pattern) =>
      pattern.expression.test(parameter.declaration),
    );
    if (
      source !== undefined &&
      (!rejectParameterReassignment ||
        !dotnetMethodParameterReassignedBeforeCall(
          lines,
          argument,
          method.startLine,
          callLine,
        ))
    ) {
      return { kind: source.kind, line: method.startLine };
    }
  }

  const sources = matchingJavaModelLines(lines, sourcePatterns, 32);
  const structuralLines = cFamilyStructuralLines(lines);
  const assignment = new RegExp(
    `\\b(?:[A-Za-z_][\\w.[\\]<>?,]*\\s+)?${escapeRegularExpression(argument)}\\s*=`,
    "u",
  );
  const earliest = Math.max(
    method.startLine,
    callLine - MAX_WRAPPER_CALL_DISTANCE,
  );
  for (let line = callLine - 1; line >= earliest; line -= 1) {
    const source = sources.find((candidate) => candidate.line === line);
    if (source === undefined) continue;
    if (!assignment.test(structuralLines[line - 1] ?? "")) continue;
    if (!javaIdentifierReassignedBetween(lines, argument, line, callLine)) {
      return source;
    }
  }
  return undefined;
}

function dotnetMethodParameterReassignedBeforeCall(
  lines: readonly string[],
  identifier: string,
  methodStartLine: number,
  callLine: number,
): boolean {
  const structural = cFamilyStructuralLines(
    lines.slice(methodStartLine - 1, callLine),
  ).join("\n");
  const bodyStart = structural.indexOf("{");
  if (bodyStart < 0) return false;
  const escapedIdentifier = escapeRegularExpression(identifier);
  const reassignment = new RegExp(
    `(?:\\b${escapedIdentifier}\\s*(?:[+\\-*/%&|^]?=|\\+\\+|--)|(?:\\+\\+|--)\\s*${escapedIdentifier}\\b|\\b(?:var|[A-Za-z_]\\w*(?:\\s*<[^;{}]+>)?\\??)\\s+${escapedIdentifier}\\b)`,
    "u",
  );
  return reassignment.test(structural.slice(bodyStart + 1));
}

function dotnetScribanTemplateSourceArgument(
  lines: readonly string[],
  sinkLine: number,
  methodEndLine = lines.length,
): string | undefined {
  const callLines = lines.slice(
    sinkLine - 1,
    Math.min(methodEndLine, sinkLine + 12),
  );
  const original = callLines.join("\n");
  const structural = cFamilyStructuralLines(callLines).join("\n");
  const parseCall =
    /\b(?:(?:global\s*::\s*)?Scriban\s*\.\s*)?Template\s*\.\s*Parse\s*\(/u.exec(
      structural,
    );
  if (parseCall?.index === undefined) return undefined;

  const structuralFile = cFamilyStructuralLines(lines).join("\n");
  const callPrefix = structural.slice(parseCall.index, parseCall.index + 96);
  const fullyQualified =
    /^(?:global\s*::\s*)?Scriban\s*\.\s*Template\s*\.\s*Parse\s*\(/u.test(
      callPrefix,
    );
  const imported = /^\s*(?:global\s+)?using\s+Scriban\s*;/mu.test(
    structuralFile,
  );
  const shadowsTemplate = /\b(?:class|record|struct)\s+Template\b/u.test(
    structuralFile,
  );
  const shadowsQualifiedTemplate =
    /\bnamespace\s+Scriban\b[\s\S]*\b(?:class|record|struct)\s+Template\b/u.test(
      structuralFile,
    );
  if (
    (fullyQualified && shadowsQualifiedTemplate) ||
    (!fullyQualified && (!imported || shadowsTemplate))
  ) {
    return undefined;
  }

  const open = structural.indexOf("(", parseCall.index);
  const close = matchingCallParenthesis(structural, open);
  if (open < 0 || close < 0) return undefined;
  const source = splitJavascriptArguments(original.slice(open + 1, close))[0];
  if (source === undefined || source.trim() === "") return undefined;

  const afterParse = structural.slice(close + 1);
  if (/^\s*\.\s*Render(?:Async)?\s*\(/u.test(afterParse)) {
    return source.trim();
  }

  const beforeParse = structural.slice(0, parseCall.index);
  const statementBoundary = Math.max(
    beforeParse.lastIndexOf(";"),
    beforeParse.lastIndexOf("{"),
    beforeParse.lastIndexOf("}"),
    beforeParse.lastIndexOf("\n"),
  );
  const assignment =
    /^\s*(?:(?:var|(?:(?:global\s*::\s*)?Scriban\s*\.\s*)?Template)\s+)?([A-Za-z_]\w*)\s*=\s*$/u.exec(
      beforeParse.slice(statementBoundary + 1),
    );
  const parsedTemplate = assignment?.[1];
  if (parsedTemplate === undefined) return undefined;
  const escapedTemplate = escapeRegularExpression(parsedTemplate);
  const render = new RegExp(
    `\\b${escapedTemplate}\\s*\\.\\s*Render(?:Async)?\\s*\\(`,
    "u",
  ).exec(afterParse);
  if (render?.index === undefined) return undefined;
  const beforeRender = afterParse.slice(0, render.index);
  if (new RegExp(`\\b${escapedTemplate}\\s*=(?!=)`, "u").test(beforeRender)) {
    return undefined;
  }
  return source.trim();
}

function dotnetRazorLightTemplateSourceArgument(
  lines: readonly string[],
  sinkLine: number,
  methodEndLine = lines.length,
): string | undefined {
  const callLines = lines.slice(
    sinkLine - 1,
    Math.min(methodEndLine, sinkLine + 16),
  );
  const original = callLines.join("\n");
  const structural = cFamilyStructuralLines(callLines).join("\n");
  const call =
    /\b(?:this\s*\.\s*)?([A-Za-z_]\w*)\s*\.\s*CompileRenderStringAsync(?:\s*<[^;(){}]+>)?\s*\(/u.exec(
      structural,
    );
  const receiver = call?.[1];
  if (call?.index === undefined || receiver === undefined) return undefined;

  const structuralFile = cFamilyStructuralLines(lines).join("\n");
  const imported = /^\s*(?:global\s+)?using\s+RazorLight\s*;/mu.test(
    structuralFile,
  );
  const shadowsUnqualifiedType =
    /\b(?:class|interface|record|struct)\s+(?:IRazorLightEngine|RazorLightEngine|RazorLightEngineBuilder)\b/u.test(
      structuralFile,
    );
  const shadowsQualifiedType =
    /\bnamespace\s+RazorLight\b[\s\S]*\b(?:class|interface|record|struct)\s+(?:IRazorLightEngine|RazorLightEngine|RazorLightEngineBuilder)\b/u.test(
      structuralFile,
    );
  const escapedReceiver = escapeRegularExpression(receiver);
  const fullyQualifiedType = new RegExp(
    String.raw`\b(?:global\s*::\s*)?RazorLight\s*\.\s*(?:IRazorLightEngine|RazorLightEngine)\s+${escapedReceiver}\b`,
    "u",
  ).test(structuralFile);
  const importedType = new RegExp(
    String.raw`\b(?:IRazorLightEngine|RazorLightEngine)\s+${escapedReceiver}\b`,
    "u",
  ).test(structuralFile);
  const fullyQualifiedBuilder = new RegExp(
    String.raw`\bvar\s+${escapedReceiver}\s*=\s*new\s+(?:global\s*::\s*)?RazorLight\s*\.\s*RazorLightEngineBuilder\s*\([^;{}]*\)[^;{}]{0,512}?\.\s*Build\s*\(\s*\)\s*;`,
    "u",
  ).test(structuralFile);
  const importedBuilder = new RegExp(
    String.raw`\bvar\s+${escapedReceiver}\s*=\s*new\s+RazorLightEngineBuilder\s*\([^;{}]*\)[^;{}]{0,512}?\.\s*Build\s*\(\s*\)\s*;`,
    "u",
  ).test(structuralFile);
  const typedReceiver =
    (!shadowsQualifiedType && (fullyQualifiedType || fullyQualifiedBuilder)) ||
    (imported && !shadowsUnqualifiedType && (importedType || importedBuilder));
  if (!typedReceiver) return undefined;

  const open = structural.indexOf("(", call.index);
  const close = matchingCallParenthesis(structural, open);
  if (open < 0 || close < 0) return undefined;
  const arguments_ = splitJavascriptArguments(original.slice(open + 1, close));
  const namedContent = arguments_.find((argument) =>
    /^\s*content\s*:/u.test(argument),
  );
  const source =
    namedContent === undefined
      ? arguments_[1]
      : namedContent.replace(/^\s*content\s*:\s*/u, "");
  if (
    source === undefined ||
    source.trim() === "" ||
    (namedContent === undefined && /^\s*(?:model|viewBag)\s*:/u.test(source))
  ) {
    return undefined;
  }
  return source.replace(/^\s*content\s*:\s*/u, "").trim();
}

function dotnetTemplateSourceArgument(
  lines: readonly string[],
  sinkLine: number,
  methodEndLine = lines.length,
): string | undefined {
  return (
    dotnetScribanTemplateSourceArgument(lines, sinkLine, methodEndLine) ??
    dotnetRazorLightTemplateSourceArgument(lines, sinkLine, methodEndLine)
  );
}

function dotnetMethodParameterIndexesReachingExpression(
  lines: readonly string[],
  method: ExportedDotnetMethod,
  sinkLine: number,
  expression: string,
): number[] {
  const structuralBody = cFamilyStructuralLines(
    lines.slice(method.startLine - 1, sinkLine),
  ).join("\n");
  const assignments = [
    ...structuralBody.matchAll(/\b([A-Za-z_]\w*)\s*=(?!=)\s*([^;]+);/gu),
  ];
  return method.parameters.flatMap((parameter, parameterIndex) => {
    const reachingIdentifiers = new Set([parameter.name]);
    for (const assignment of assignments) {
      const target = assignment[1];
      const value = assignment[2];
      if (target === undefined || value === undefined) continue;
      const valueReaches = [...reachingIdentifiers].some((identifier) =>
        cFamilyLineReferencesIdentifier(value, identifier),
      );
      if (valueReaches) reachingIdentifiers.add(target);
      else reachingIdentifiers.delete(target);
    }
    return [...reachingIdentifiers].some((identifier) =>
      cFamilyLineReferencesIdentifier(expression, identifier),
    )
      ? [parameterIndex]
      : [];
  });
}

function modeledSameFileDotnetTemplateSource(
  lines: readonly string[],
  sinkLine: number,
  sourcePatterns: readonly FrameworkModelPattern[],
  files: readonly SourceFileSnapshot[] = [],
  path = "",
): { kind: string; line: number } | undefined {
  const method = exportedDotnetMethods(lines).find(
    (candidate) =>
      sinkLine >= candidate.startLine && sinkLine <= candidate.endLine,
  );
  if (method === undefined) return undefined;
  const templateSource = dotnetTemplateSourceArgument(
    lines,
    sinkLine,
    method.endLine,
  );
  if (templateSource === undefined) return undefined;

  for (const parameterIndex of dotnetMethodParameterIndexesReachingExpression(
    lines,
    method,
    sinkLine,
    templateSource,
  )) {
    const parameter = method.parameters[parameterIndex];
    if (parameter === undefined) continue;
    const source = modeledDotnetCallSource(
      lines,
      method,
      sinkLine,
      parameter.name,
      sourcePatterns,
      false,
      files,
      path,
    );
    if (source !== undefined) return source;
  }

  if (
    method.parameters.some(
      (parameter) => parameter.name === templateSource.trim(),
    )
  ) {
    return undefined;
  }
  return modeledDotnetCallSource(
    lines,
    method,
    sinkLine,
    templateSource,
    sourcePatterns,
    false,
    files,
    path,
  );
}

function modeledSameFileDotnetSource(
  lines: readonly string[],
  sinkLine: number,
  sourcePatterns: readonly FrameworkModelPattern[],
  files: readonly SourceFileSnapshot[] = [],
  path = "",
): { kind: string; line: number } | undefined {
  const method = exportedDotnetMethods(lines).find(
    (candidate) =>
      sinkLine >= candidate.startLine && sinkLine <= candidate.endLine,
  );
  if (method === undefined) return undefined;
  const expression = javaCallExpression(lines, sinkLine, method.endLine);
  const direct = modeledDotnetCallSource(
    lines,
    method,
    sinkLine,
    expression,
    sourcePatterns,
    false,
    files,
    path,
  );
  if (direct !== undefined) return direct;
  for (const parameterIndex of dotnetMethodParameterIndexesReachingExpression(
    lines,
    method,
    sinkLine,
    expression,
  )) {
    const parameter = method.parameters[parameterIndex];
    if (parameter === undefined) continue;
    const source = modeledDotnetCallSource(
      lines,
      method,
      sinkLine,
      parameter.name,
      sourcePatterns,
      false,
      files,
      path,
    );
    if (source !== undefined) return source;
  }
  return undefined;
}

interface DotnetObjectAuthorizationSink {
  argument: string;
  receiver: string;
  method: string;
  callStartLine: number;
  callEndLine: number;
  resultIdentifier?: string;
}

const DOTNET_OBJECT_OWNER_FIELD =
  "(?:Account|Customer|Organization|Owner|Principal|Tenant|User|Workspace)Id";
const DOTNET_AUTHENTICATED_PRINCIPAL_VALUE =
  "(?:User\\s*\\.\\s*(?:FindFirstValue|FindFirst)\\s*\\([^)]*\\)(?:\\s*\\.\\s*Value)?|HttpContext\\s*\\.\\s*User\\s*\\.\\s*(?:FindFirstValue|FindFirst)\\s*\\([^)]*\\)(?:\\s*\\.\\s*Value)?|(?:actor|authenticated|current|principal|session)[A-Za-z0-9_]*Id)";

function dotnetObjectAuthorizationSink(
  lines: readonly string[],
  sinkLine: number,
  methodEndLine = lines.length,
): DotnetObjectAuthorizationSink | undefined {
  const callLines = lines.slice(
    sinkLine - 1,
    Math.min(methodEndLine, sinkLine + 12),
  );
  const original = callLines.join("\n");
  const structural = cFamilyStructuralLines(callLines).join("\n");
  const call =
    /\b([A-Za-z_]\w*)\s*\.\s*(Find|FindAsync|First|FirstAsync|FirstOrDefault|FirstOrDefaultAsync|Single|SingleAsync|SingleOrDefault|SingleOrDefaultAsync)\s*(?:<[^;(){}]+>)?\s*\(/u.exec(
      structural,
    );
  if (call?.index === undefined) return undefined;
  const open = structural.indexOf("(", call.index);
  const close = matchingCallParenthesis(structural, open);
  if (open < 0 || close < 0) return undefined;
  const argument = splitJavascriptArguments(
    original.slice(open + 1, close),
  )[0]?.trim();
  if (argument === undefined || argument === "") return undefined;
  const resultIdentifier =
    /\b(?:var|[A-Za-z_]\w*(?:\s*<[^;{}]+>)?\??)\s+([A-Za-z_]\w*)\s*=\s*(?:await\s+)?$/u.exec(
      structural.slice(0, call.index),
    )?.[1];
  return {
    argument,
    receiver: call[1]!,
    method: call[2]!,
    callStartLine: sinkLine,
    callEndLine:
      sinkLine + (structural.slice(0, close).match(/\n/gu)?.length ?? 0),
    ...(resultIdentifier === undefined ? {} : { resultIdentifier }),
  };
}

function dotnetEfObjectLookupHasTypedReceiver(
  lines: readonly string[],
  sink: DotnetObjectAuthorizationSink,
): boolean {
  const structuralText = cFamilyStructuralLines(lines).join("\n");
  const imported =
    /^\s*(?:global\s+)?using\s+Microsoft\.EntityFrameworkCore\s*;/mu.test(
      structuralText,
    );
  const fullyQualified =
    /\bMicrosoft\s*\.\s*EntityFrameworkCore\s*\.\s*(?:DbContext|DbSet)\b/u.test(
      structuralText,
    );
  const shadowsEf =
    /\bnamespace\s+Microsoft\.EntityFrameworkCore\b/u.test(structuralText) ||
    /\b(?:class|interface|record|struct)\s+(?:DbContext|DbSet)\b/u.test(
      structuralText,
    );
  if ((!imported && !fullyQualified) || shadowsEf) return false;
  const receiver = escapeRegularExpression(sink.receiver);
  const typedSet = new RegExp(
    `\\b(?:(?:Microsoft\\s*\\.\\s*EntityFrameworkCore\\s*\\.\\s*)?DbSet\\s*<[^;{}]+>)\\s+${receiver}\\b`,
    "u",
  );
  const typedContext = new RegExp(
    `\\b(?:[A-Za-z_]\\w*DbContext|(?:Microsoft\\s*\\.\\s*EntityFrameworkCore\\s*\\.\\s*)?DbContext)\\s+${receiver}\\b`,
    "u",
  );
  return typedSet.test(structuralText) || typedContext.test(structuralText);
}

function modeledSameFileDotnetObjectSource(
  lines: readonly string[],
  sinkLine: number,
  lookupArgument: string,
  sourcePatterns: readonly FrameworkModelPattern[],
  files: readonly SourceFileSnapshot[] = [],
  path = "",
): { kind: string; line: number } | undefined {
  const method = exportedDotnetMethods(lines).find(
    (candidate) =>
      sinkLine >= candidate.startLine && sinkLine <= candidate.endLine,
  );
  if (method === undefined) return undefined;
  const direct = modeledDotnetCallSource(
    lines,
    method,
    sinkLine,
    lookupArgument.trim(),
    sourcePatterns,
    true,
    files,
    path,
  );
  if (direct !== undefined) return direct;
  for (const parameterIndex of dotnetMethodParameterIndexesReachingExpression(
    lines,
    method,
    sinkLine,
    lookupArgument,
  )) {
    const parameter = method.parameters[parameterIndex];
    if (parameter === undefined) continue;
    const source = modeledDotnetCallSource(
      lines,
      method,
      sinkLine,
      parameter.name,
      sourcePatterns,
      true,
      files,
      path,
    );
    if (source !== undefined) return source;
  }
  return undefined;
}

function dotnetObjectAuthorizationControls(
  lines: readonly string[],
  sink: DotnetObjectAuthorizationSink,
  functionEndLine: number,
): Array<{ kind: string; line: number }> {
  const controls: Array<{ kind: string; line: number }> = [];
  const callLines = cFamilyStructuralLines(
    lines.slice(sink.callStartLine - 1, sink.callEndLine),
  );
  const principalFilter = new RegExp(
    `\\b${DOTNET_OBJECT_OWNER_FIELD}\\b\\s*(?:==|equals\\s*\\()\\s*${DOTNET_AUTHENTICATED_PRINCIPAL_VALUE}\\b|\\b${DOTNET_AUTHENTICATED_PRINCIPAL_VALUE}\\s*==\\s*[^;{}]*\\b${DOTNET_OBJECT_OWNER_FIELD}\\b`,
    "iu",
  );
  const filterIndex = callLines.findIndex((line) => principalFilter.test(line));
  if (filterIndex >= 0) {
    controls.push({
      kind: "principal-bound-object-filter",
      line: sink.callStartLine + filterIndex,
    });
  }

  if (sink.resultIdentifier === undefined) return controls;
  const resourceControl = dotnetEnforcedResourceAuthorization(
    lines,
    sink.callEndLine + 1,
    Math.min(lines.length, functionEndLine, sink.callEndLine + 48),
    sink.resultIdentifier,
  );
  if (resourceControl !== undefined) {
    controls.push({
      kind: "resource-based-object-authorization",
      line: resourceControl,
    });
  }
  return controls;
}

function dotnetEnforcedResourceAuthorization(
  lines: readonly string[],
  startLine: number,
  endLine: number,
  resourceIdentifier: string,
): number | undefined {
  const structuralFile = cFamilyStructuralLines(lines).join("\n");
  const escapedResource = escapeRegularExpression(resourceIdentifier);
  const failClosed =
    /\breturn\s+(?:Challenge|Forbid|StatusCode|Unauthorized)\s*\(|\bthrow\b/u;
  for (let line = startLine; line <= endLine; line += 1) {
    const callLines = lines.slice(line - 1, Math.min(endLine, line + 12));
    const original = callLines.join("\n");
    const structural = cFamilyStructuralLines(callLines).join("\n");
    const call = /\b([A-Za-z_]\w*)\s*\.\s*AuthorizeAsync\s*\(/u.exec(
      structural,
    );
    if (call?.index === undefined) continue;
    const receiver = escapeRegularExpression(call[1]!);
    const typedReceiver = new RegExp(
      `\\b(?:Microsoft\\s*\\.\\s*AspNetCore\\s*\\.\\s*Authorization\\s*\\.\\s*)?IAuthorizationService\\s+${receiver}\\b`,
      "u",
    );
    if (!typedReceiver.test(structuralFile)) continue;
    const open = structural.indexOf("(", call.index);
    const close = matchingCallParenthesis(structural, open);
    if (open < 0 || close < 0) continue;
    const arguments_ = splitJavascriptArguments(
      original.slice(open + 1, close),
    ).map((argument) =>
      argument.replace(/^\s*[A-Za-z_]\w*\s*:\s*/u, "").trim(),
    );
    if (
      !/^(?:User|HttpContext\s*\.\s*User)$/u.test(arguments_[0] ?? "") ||
      !new RegExp(`^${escapedResource}$`, "u").test(arguments_[1] ?? "")
    ) {
      continue;
    }

    const beforeCall = structural.slice(0, call.index);
    const afterCall = structural.slice(close + 1);
    if (
      /\bif\s*\([^;{}]*!\s*(?:\(?\s*await\s+)?$/u.test(beforeCall) &&
      /^\s*\)?\s*\.\s*Succeeded\b/u.test(afterCall) &&
      failClosed.test(afterCall)
    ) {
      return line;
    }

    const authorizationResult =
      /\b(?:var|AuthorizationResult)\s+([A-Za-z_]\w*)\s*=\s*(?:await\s+)?$/u.exec(
        beforeCall,
      )?.[1];
    if (authorizationResult === undefined) continue;
    const escapedResult = escapeRegularExpression(authorizationResult);
    const following = cFamilyStructuralLines(
      lines.slice(
        line + (structural.slice(0, close).match(/\n/gu)?.length ?? 0),
        Math.min(endLine, line + 16),
      ),
    ).join("\n");
    const negativeGuard = new RegExp(
      `\\bif\\s*\\(\\s*!\\s*${escapedResult}\\s*\\.\\s*Succeeded\\s*\\)[^;{}]*(?:\\{[^{}]*)?`,
      "u",
    );
    const guard = negativeGuard.exec(following);
    if (
      guard?.index !== undefined &&
      failClosed.test(following.slice(guard.index))
    ) {
      return line;
    }
  }
  return undefined;
}

interface NodeHttpUrlSink {
  urlExpression?: string;
  axiosReceiver?: string;
  axiosConfigurationLine?: number;
  axiosConfigurationEndLine?: number;
  callStartLine?: number;
  callEndLine?: number;
}

interface NodeObjectAuthorizationSink {
  argument: string;
  callStartLine: number;
  callEndLine: number;
  resultIdentifier?: string;
}

const NODE_OBJECT_OWNER_FIELD =
  "(?:account|customer|organization|owner|principal|tenant|user|workspace)(?:Id|_id)";
const NODE_AUTHENTICATED_PRINCIPAL_VALUE =
  "(?:(?:req|request)\\.(?:auth|session|user)(?:\\.[A-Za-z_$][\\w$]*)+|ctx\\.(?:state\\.)?(?:auth|session|user)(?:\\.[A-Za-z_$][\\w$]*)+|(?:actor|authenticated|current|principal|session)[A-Za-z0-9_$]*(?:Id|_id))";

function nodeObjectAuthorizationSink(
  lines: readonly string[],
  sinkLine: number,
): NodeObjectAuthorizationSink | undefined {
  const endLine = Math.min(lines.length, sinkLine + 12);
  const callLines = lines.slice(sinkLine - 1, endLine);
  const original = javascriptCodeLinesWithoutComments(callLines).join("\n");
  const structural = javascriptStructuralLines(callLines).join("\n");
  const call =
    /\.\s*(?:findById|findByPk|findFirst|findOne|findUnique|getById|loadById|selectById)\s*(?:<[^;(){}]+>)?\s*\(/iu.exec(
      structural,
    );
  if (call?.index === undefined) return undefined;
  const open = structural.indexOf("(", call.index);
  const close = matchingCallParenthesis(structural, open);
  if (open < 0 || close < 0) return undefined;
  const argument = splitJavascriptArguments(
    original.slice(open + 1, close),
  )[0]?.trim();
  if (argument === undefined || argument === "") return undefined;
  const resultIdentifier =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?/u.exec(
      structural.slice(0, call.index),
    )?.[1];
  return {
    argument,
    callStartLine: sinkLine,
    callEndLine:
      sinkLine + (structural.slice(0, close).match(/\n/gu)?.length ?? 0),
    ...(resultIdentifier === undefined ? {} : { resultIdentifier }),
  };
}

function nodeObjectAuthorizationControls(
  lines: readonly string[],
  sink: NodeObjectAuthorizationSink,
  functionEndLine: number,
): Array<{ kind: string; line: number }> {
  const controls: Array<{ kind: string; line: number }> = [];
  const callLines = javascriptStructuralLines(
    lines.slice(sink.callStartLine - 1, sink.callEndLine),
  );
  const principalFilter = new RegExp(
    `\\b${NODE_OBJECT_OWNER_FIELD}\\b\\s*:\\s*${NODE_AUTHENTICATED_PRINCIPAL_VALUE}\\b`,
    "iu",
  );
  const filterIndex = callLines.findIndex((line) => principalFilter.test(line));
  if (filterIndex >= 0) {
    controls.push({
      kind: "principal-bound-object-filter",
      line: sink.callStartLine + filterIndex,
    });
  }

  if (sink.resultIdentifier === undefined) return controls;
  const escapedResult = escapeRegularExpression(sink.resultIdentifier);
  const ownerAccess = `${escapedResult}\\s*\\.\\s*${NODE_OBJECT_OWNER_FIELD}`;
  const principalComparison = new RegExp(
    `(?:${ownerAccess}\\s*(?:===|==|!==|!=)\\s*${NODE_AUTHENTICATED_PRINCIPAL_VALUE}|${NODE_AUTHENTICATED_PRINCIPAL_VALUE}\\s*(?:===|==|!==|!=)\\s*${ownerAccess})\\b`,
    "iu",
  );
  const explicitAuthorization = new RegExp(
    `\\b(?:assertCanAccess|authorize|authorizeObject|canAccess|canRead|canWrite|checkAccess|enforceOwnership|owns)\\s*\\([^;{}]*\\b${escapedResult}\\b`,
    "iu",
  );
  const postLookupLines = javascriptStructuralLines(
    lines.slice(
      sink.callEndLine,
      Math.min(lines.length, functionEndLine, sink.callEndLine + 48),
    ),
  );
  for (let index = 0; index < postLookupLines.length; index += 1) {
    const line = postLookupLines[index] ?? "";
    if (principalComparison.test(line) || explicitAuthorization.test(line)) {
      controls.push({
        kind: "post-lookup-object-authorization",
        line: sink.callEndLine + index + 1,
      });
      break;
    }
  }
  return controls;
}

interface JavascriptAxiosBinding {
  declarationLine: number;
  kind: "root" | "instance";
  configurationEndLine?: number;
}

function nodeHttpGeneralControlApplies(
  sink: NodeHttpUrlSink | undefined,
  kind: string,
): boolean {
  return (
    sink?.axiosReceiver === undefined ||
    (kind !== "axios-absolute-url-override-disabled" &&
      kind !== "redirects-disabled")
  );
}

function javascriptAxiosReceiverShadowedInExport(
  lines: readonly string[],
  sinkLine: number,
  receiver: string,
): boolean {
  return exportedJavascriptFunctions(lines).some(
    (wrapper) =>
      sinkLine >= wrapper.startLine &&
      sinkLine <= wrapper.endLine &&
      wrapper.parameters.includes(receiver),
  );
}

function javascriptAxiosBindings(
  lines: readonly string[],
): Map<string, JavascriptAxiosBinding> {
  const codeLines = javascriptCodeLinesWithoutComments(lines);
  const bindings = new Map<string, JavascriptAxiosBinding>();
  for (let index = 0; index < codeLines.length; index += 1) {
    const code = codeLines[index] ?? "";
    const imported =
      /^\s*import\s+([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}]*\})?\s+from\s+["']axios["']\s*;?/u.exec(
        code,
      ) ??
      /^\s*import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+["']axios["']\s*;?/u.exec(
        code,
      ) ??
      /^\s*import\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["']axios["']\s*\)\s*;?/u.exec(
        code,
      ) ??
      /^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["']axios["']\s*\)(?:\s*\.\s*default)?\s*;?/u.exec(
        code,
      );
    if (imported?.[1] !== undefined) {
      bindings.set(imported[1], {
        declarationLine: index + 1,
        kind: "root",
      });
    }
  }

  const structuralLines = javascriptStructuralLines(lines);
  for (let index = 0; index < structuralLines.length; index += 1) {
    const structural = structuralLines
      .slice(index, Math.min(structuralLines.length, index + 64))
      .join("\n");
    for (const [root, rootBinding] of [...bindings]) {
      const instance = new RegExp(
        `^\\s*(?:export\\s+)?(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)(?:\\s*:\\s*[^=;]+)?\\s*=\\s*${escapeRegularExpression(root)}\\s*\\.\\s*create\\s*\\(`,
        "u",
      ).exec(structural);
      if (instance?.[1] !== undefined) {
        if (
          javascriptIdentifierReassignedBetween(
            lines,
            root,
            rootBinding.declarationLine,
            index + 1,
          ) ||
          javascriptAxiosReceiverShadowedInExport(lines, index + 1, root)
        ) {
          continue;
        }
        const open = structural.indexOf("(", instance.index);
        const close = matchingCallParenthesis(structural, open);
        if (open < 0 || close < 0) continue;
        bindings.set(instance[1], {
          declarationLine: index + 1,
          kind: "instance",
          configurationEndLine:
            index + 1 + (structural.slice(0, close).match(/\n/gu)?.length ?? 0),
        });
      }
    }
  }
  return bindings;
}

function javascriptObjectPropertyValue(
  value: string,
  property: string,
): string | undefined {
  const trimmed = value.trim();
  if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) return undefined;
  const entries = splitJavascriptArguments(trimmed.slice(1, -1));
  const escapedProperty = escapeRegularExpression(property);
  for (const entry of entries) {
    if (new RegExp(`^\\s*${escapedProperty}\\s*$`, "u").test(entry)) {
      return property;
    }
    const match = new RegExp(
      `^\\s*(?:${escapedProperty}|["']${escapedProperty}["'])\\s*:\\s*([\\s\\S]+)$`,
      "u",
    ).exec(entry);
    if (match?.[1] !== undefined && match[1].trim() !== "") {
      return match[1].trim();
    }
  }
  return undefined;
}

interface JavascriptPropertyEntry {
  key: string;
  line: number;
  value: string;
}

interface JavascriptResolvedExpression {
  line: number;
  value: string;
}

interface JavascriptCopilotClientBinding {
  declarationLine: number;
  importedClass: string;
}

const COPILOT_SYSTEM_MESSAGE_SECTIONS = [
  "preamble",
  "identity",
  "tone",
  "tool_efficiency",
  "environment_context",
  "code_change_rules",
  "guidelines",
  "safety",
  "tool_instructions",
  "custom_instructions",
  "runtime_instructions",
  "last_instructions",
] as const;

function javascriptDelimitedEntries(
  value: string,
): Array<{ offset: number; value: string }> {
  const entries: Array<{ offset: number; value: string }> = [];
  let start = 0;
  let depth = 0;
  let quote = "";
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]!;
    if (quote !== "") {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      continue;
    }
    if (character === '"' || character === "'" || character === "`") {
      quote = character;
    } else if (["(", "[", "{"].includes(character)) {
      depth += 1;
    } else if ([")", "]", "}"].includes(character)) {
      depth -= 1;
    } else if (character === "," && depth === 0) {
      const raw = value.slice(start, index);
      const leading = raw.length - raw.trimStart().length;
      if (raw.trim() !== "") {
        entries.push({ offset: start + leading, value: raw.trim() });
      }
      start = index + 1;
    }
  }
  const raw = value.slice(start);
  const leading = raw.length - raw.trimStart().length;
  if (raw.trim() !== "") {
    entries.push({ offset: start + leading, value: raw.trim() });
  }
  return entries;
}

function javascriptCompositePrefix(
  value: string,
  opener: "{" | "[",
  closer: "}" | "]",
): string | undefined {
  const leading = value.length - value.trimStart().length;
  if (value[leading] !== opener) return undefined;
  let depth = 0;
  let quote = "";
  let escaped = false;
  for (let index = leading; index < value.length; index += 1) {
    const character = value[index]!;
    if (quote !== "") {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      continue;
    }
    if (character === '"' || character === "'" || character === "`") {
      quote = character;
    } else if (character === opener) {
      depth += 1;
    } else if (character === closer) {
      depth -= 1;
      if (depth === 0) return value.slice(leading, index + 1);
    }
  }
  return undefined;
}

function javascriptExpressionEnd(value: string, start: number): number {
  let depth = 0;
  let quote = "";
  let escaped = false;
  for (let index = start; index < value.length; index += 1) {
    const character = value[index]!;
    if (quote !== "") {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      continue;
    }
    if (character === '"' || character === "'" || character === "`") {
      quote = character;
    } else if (["(", "[", "{"].includes(character)) {
      depth += 1;
    } else if ([")", "]", "}"].includes(character)) {
      depth -= 1;
    } else if ((character === ";" || character === "\n") && depth === 0) {
      return index;
    }
  }
  return value.length;
}

function javascriptVariableInitializer(
  lines: readonly string[],
  identifier: string,
  beforeLine: number,
): JavascriptResolvedExpression | undefined {
  const earliest = Math.max(1, beforeLine - 64);
  const structuralLines = javascriptStructuralLines(lines);
  const declaration = new RegExp(
    `^\\s*(?:export\\s+)?(?:const|let|var)\\s+${escapeRegularExpression(identifier)}(?:\\s*:[^=;]+)?\\s*=\\s*`,
    "u",
  );
  for (let line = beforeLine - 1; line >= earliest; line -= 1) {
    const first = structuralLines[line - 1] ?? "";
    if (!declaration.test(first)) continue;
    if (
      javascriptIdentifierReassignedBetween(lines, identifier, line, beforeLine)
    ) {
      return undefined;
    }
    const original = javascriptCodeLinesWithoutComments(
      lines.slice(line - 1, Math.min(lines.length, line + 31)),
    ).join("\n");
    const structural = javascriptStructuralLines(
      lines.slice(line - 1, Math.min(lines.length, line + 31)),
    ).join("\n");
    const match = declaration.exec(structural);
    if (match === null) return undefined;
    let start = match.index + match[0].lastIndexOf("=") + 1;
    while (/\s/u.test(original[start] ?? "")) start += 1;
    const end = javascriptExpressionEnd(original, start);
    const expression = original.slice(start, end).trim();
    if (expression === "") return undefined;
    return { line, value: expression };
  }
  return undefined;
}

function resolveJavascriptExpression(
  lines: readonly string[],
  expression: string,
  line: number,
  depth = 0,
  seen: ReadonlySet<string> = new Set(),
): JavascriptResolvedExpression | undefined {
  const value = expression.trim();
  if (value === "" || depth > 8) return undefined;
  if (!/^[A-Za-z_$][\w$]*$/u.test(value)) return { line, value };
  if (seen.has(value)) return undefined;
  const initializer = javascriptVariableInitializer(lines, value, line);
  if (initializer === undefined) return { line, value };
  return resolveJavascriptExpression(
    lines,
    initializer.value,
    initializer.line,
    depth + 1,
    new Set([...seen, value]),
  );
}

function javascriptObjectEntries(
  value: JavascriptResolvedExpression,
): JavascriptPropertyEntry[] {
  const object = javascriptCompositePrefix(value.value, "{", "}");
  if (object === undefined) return [];
  return javascriptDelimitedEntries(object.slice(1, -1)).flatMap((entry) => {
    const shorthand = /^([A-Za-z_$][\w$]*)$/u.exec(entry.value);
    if (shorthand !== null) {
      return [
        {
          key: shorthand[1]!,
          line:
            value.line +
            (object.slice(0, entry.offset + 1).match(/\n/gu)?.length ?? 0),
          value: shorthand[1]!,
        },
      ];
    }
    const property =
      /^\s*(?:([A-Za-z_$][\w$]*)|["']([^"']+)["'])\s*:\s*([\s\S]+)$/u.exec(
        entry.value,
      );
    if (property === null) return [];
    return [
      {
        key: property[1] ?? property[2]!,
        line:
          value.line +
          (object.slice(0, entry.offset + 1).match(/\n/gu)?.length ?? 0),
        value: property[3]!.trim(),
      },
    ];
  });
}

function javascriptArrayEntries(
  value: JavascriptResolvedExpression,
): JavascriptResolvedExpression[] {
  const array = javascriptCompositePrefix(value.value, "[", "]");
  if (array === undefined) return [];
  return javascriptDelimitedEntries(array.slice(1, -1)).map((entry) => ({
    line:
      value.line +
      (array.slice(0, entry.offset + 1).match(/\n/gu)?.length ?? 0),
    value: entry.value,
  }));
}

function javascriptCopilotClientBindings(
  lines: readonly string[],
): Map<string, JavascriptCopilotClientBinding> {
  const importedClasses = importedJavascriptSymbols(lines)
    .filter(
      (binding) =>
        binding.moduleSpecifier === "@github/copilot-sdk" &&
        binding.imported === "CopilotClient",
    )
    .map(({ local }) => local);
  if (new Set(importedClasses).size !== importedClasses.length)
    return new Map();
  const bindings = new Map<string, JavascriptCopilotClientBinding>();
  const structuralLines = javascriptStructuralLines(lines);
  for (let index = 0; index < structuralLines.length; index += 1) {
    for (const importedClass of importedClasses) {
      const declaration = new RegExp(
        `^\\s*(?:export\\s+)?(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)(?:\\s*:[^=;]+)?\\s*=\\s*new\\s+${escapeRegularExpression(importedClass)}\\s*\\(`,
        "u",
      ).exec(structuralLines[index] ?? "");
      if (declaration?.[1] === undefined) continue;
      if (bindings.has(declaration[1])) return new Map();
      bindings.set(declaration[1], {
        declarationLine: index + 1,
        importedClass,
      });
    }
  }
  return bindings;
}

function nodeCopilotPromptSink(
  lines: readonly string[],
  sinkLine: number,
): NodeCopilotPromptSink | undefined {
  const bindings = javascriptCopilotClientBindings(lines);
  const endLine = Math.min(lines.length, sinkLine + 63);
  const original = javascriptCodeLinesWithoutComments(
    lines.slice(sinkLine - 1, endLine),
  ).join("\n");
  const structural = javascriptStructuralLines(
    lines.slice(sinkLine - 1, endLine),
  ).join("\n");
  const call =
    /\b([A-Za-z_$][\w$]*)\s*\.\s*(createSession|resumeSession)\s*\(/u.exec(
      structural,
    );
  if (
    call?.index === undefined ||
    call[1] === undefined ||
    call[2] === undefined
  ) {
    return undefined;
  }
  const binding = bindings.get(call[1]);
  if (
    binding === undefined ||
    binding.declarationLine > sinkLine ||
    javascriptIdentifierReassignedBetween(
      lines,
      call[1],
      binding.declarationLine,
      sinkLine,
    ) ||
    exportedJavascriptFunctions(lines).some(
      (wrapper) =>
        sinkLine >= wrapper.startLine &&
        sinkLine <= wrapper.endLine &&
        (wrapper.parameters.includes(call[1]!) ||
          wrapper.parameters.includes(binding.importedClass)),
    )
  ) {
    return undefined;
  }
  const open = structural.indexOf("(", call.index);
  const close = matchingCallParenthesis(structural, open);
  if (open < 0 || close < 0) return undefined;
  const arguments_ = splitJavascriptArguments(original.slice(open + 1, close));
  const configIndex = call[2] === "resumeSession" ? 1 : 0;
  const configExpression = arguments_[configIndex];
  if (configExpression === undefined) return undefined;
  const config = resolveJavascriptExpression(lines, configExpression, sinkLine);
  if (config === undefined) return undefined;
  const inputs = nodeCopilotTrustedInputs(lines, config);
  if (inputs.length === 0) return undefined;
  return {
    callEndLine:
      sinkLine + (structural.slice(0, close).match(/\n/gu)?.length ?? 0),
    callLine: sinkLine,
    inputs,
  };
}

function nodeCopilotTrustedInputs(
  lines: readonly string[],
  config: JavascriptResolvedExpression,
): NodeCopilotTrustedInput[] {
  const inputs: NodeCopilotTrustedInput[] = [];
  const properties = javascriptObjectEntries(config);
  const property = (name: string): JavascriptPropertyEntry | undefined =>
    properties.find((candidate) => candidate.key === name);
  const add = (
    candidate: JavascriptPropertyEntry | undefined,
    kind: NodeCopilotTrustedInput["kind"],
  ): void => {
    if (candidate === undefined || candidate.value.trim() === "") return;
    inputs.push({ expression: candidate.value, kind, line: candidate.line });
  };

  const systemMessageProperty = property("systemMessage");
  if (systemMessageProperty !== undefined) {
    const systemMessage = resolveJavascriptExpression(
      lines,
      systemMessageProperty.value,
      systemMessageProperty.line,
    );
    if (systemMessage !== undefined) {
      const systemProperties = javascriptObjectEntries(systemMessage);
      add(
        systemProperties.find(({ key }) => key === "content"),
        "copilot-system-message-content",
      );
      const sectionsProperty = systemProperties.find(
        ({ key }) => key === "sections",
      );
      if (sectionsProperty !== undefined) {
        const sections = resolveJavascriptExpression(
          lines,
          sectionsProperty.value,
          sectionsProperty.line,
        );
        if (sections !== undefined) {
          for (const section of javascriptObjectEntries(sections)) {
            const knownSection = COPILOT_SYSTEM_MESSAGE_SECTIONS.includes(
              section.key as (typeof COPILOT_SYSTEM_MESSAGE_SECTIONS)[number],
            );
            const override = resolveJavascriptExpression(
              lines,
              section.value,
              section.line,
            );
            if (override === undefined) continue;
            const overrideProperties = javascriptObjectEntries(override);
            const action = overrideProperties.find(
              ({ key }) => key === "action",
            );
            const resolvedAction =
              action === undefined
                ? undefined
                : resolveJavascriptExpression(lines, action.value, action.line);
            const fixedAction =
              /^\s*["'](append|prepend|preserve|remove|replace)["']\s*$/u.exec(
                resolvedAction?.value ?? "",
              )?.[1];
            const contentIsConsumed = knownSection
              ? fixedAction === undefined ||
                fixedAction === "append" ||
                fixedAction === "prepend" ||
                fixedAction === "replace"
              : fixedAction !== "remove";
            if (contentIsConsumed) {
              add(
                overrideProperties.find(({ key }) => key === "content"),
                "copilot-system-message-section-content",
              );
            }
            if (
              knownSection &&
              action !== undefined &&
              !/^\s*["'](?:append|prepend|preserve|remove|replace)["']\s*$/u.test(
                resolvedAction?.value ?? action.value,
              )
            ) {
              add(action, "copilot-system-message-section-transform");
            }
          }
        }
      }
    }
  }

  const addArrayProperties = (
    propertyName: "commands" | "customAgents" | "tools",
    names: ReadonlyArray<{
      kind: NodeCopilotTrustedInput["kind"];
      name: string;
    }>,
  ): void => {
    const arrayProperty = property(propertyName);
    if (arrayProperty === undefined) return;
    const array = resolveJavascriptExpression(
      lines,
      arrayProperty.value,
      arrayProperty.line,
    );
    if (array === undefined) return;
    for (const element of javascriptArrayEntries(array)) {
      const resolvedElement = resolveJavascriptExpression(
        lines,
        element.value,
        element.line,
      );
      if (resolvedElement === undefined) continue;
      const elementProperties = javascriptObjectEntries(resolvedElement);
      const infer = elementProperties.find(({ key }) => key === "infer");
      const resolvedInfer =
        infer === undefined
          ? undefined
          : resolveJavascriptExpression(lines, infer.value, infer.line);
      for (const name of names) {
        if (
          propertyName === "customAgents" &&
          name.name === "description" &&
          /^\s*false\s*$/u.test(resolvedInfer?.value ?? "")
        ) {
          continue;
        }
        add(
          elementProperties.find(({ key }) => key === name.name),
          name.kind,
        );
      }
    }
  };
  addArrayProperties("customAgents", [
    { name: "prompt", kind: "copilot-custom-agent-prompt" },
    { name: "description", kind: "copilot-custom-agent-description" },
  ]);
  addArrayProperties("tools", [
    { name: "description", kind: "copilot-tool-description" },
  ]);

  return inputs.filter(
    (input, index, all) =>
      all.findIndex(
        (candidate) =>
          candidate.kind === input.kind &&
          candidate.line === input.line &&
          candidate.expression === input.expression,
      ) === index,
  );
}

function javascriptExpressionIdentifiers(expression: string): string[] {
  const structural = javascriptStructuralLines(expression.split(/\r?\n/u)).join(
    "\n",
  );
  const templates = expression
    .split(/\r?\n/u)
    .map((line) => javascriptTemplateExpressionCode(line))
    .join("\n");
  return [...`${structural}\n${templates}`.matchAll(/\b[A-Za-z_$][\w$]*\b/gu)]
    .map((match) => match[0])
    .filter((identifier, index, all) => all.indexOf(identifier) === index);
}

function javascriptTrustedExpressionSource(
  lines: readonly string[],
  expression: string,
  expressionLine: number,
  sourcePatterns: readonly FrameworkModelPattern[],
  depth = 0,
  seen: ReadonlySet<string> = new Set(),
): { kind: string; line: number } | undefined {
  const direct = sourcePatterns.find((pattern) =>
    pattern.expression.test(expression),
  );
  if (direct !== undefined) return { kind: direct.kind, line: expressionLine };
  if (depth > 8) return undefined;
  for (const identifier of javascriptExpressionIdentifiers(expression)) {
    if (seen.has(identifier)) continue;
    const initializer = javascriptVariableInitializer(
      lines,
      identifier,
      expressionLine,
    );
    if (initializer === undefined) continue;
    const source = javascriptTrustedExpressionSource(
      lines,
      initializer.value,
      initializer.line,
      sourcePatterns,
      depth + 1,
      new Set([...seen, identifier]),
    );
    if (source !== undefined) return source;
  }
  return undefined;
}

function nodeCopilotPromptSource(
  lines: readonly string[],
  sink: NodeCopilotPromptSink,
  sourcePatterns: readonly FrameworkModelPattern[],
): NodeCopilotSourceResolution | undefined {
  for (const input of sink.inputs) {
    const source = javascriptTrustedExpressionSource(
      lines,
      input.expression,
      input.line,
      sourcePatterns,
    );
    if (source !== undefined) return { input, source };
  }
  return undefined;
}

function nodeAxiosUrlArgument(
  lines: readonly string[],
  sinkLine: number,
): NodeHttpUrlSink | undefined {
  const bindings = javascriptAxiosBindings(lines);
  if (bindings.size === 0) return undefined;
  const endLine = Math.min(lines.length, sinkLine + 12);
  const original = javascriptCodeLinesWithoutComments(
    lines.slice(sinkLine - 1, endLine),
  ).join("\n");
  const structural = javascriptStructuralLines(
    lines.slice(sinkLine - 1, endLine),
  ).join("\n");
  const methodCall =
    /\b([A-Za-z_$][\w$]*)\s*\.\s*(delete|get|head|options|patch|post|put|request)\s*(?:<[^;(){}]+>)?\s*\(/u.exec(
      structural,
    );
  if (methodCall?.index !== undefined && methodCall[1] !== undefined) {
    const binding = bindings.get(methodCall[1]);
    if (
      binding === undefined ||
      binding.declarationLine > sinkLine ||
      javascriptIdentifierReassignedBetween(
        lines,
        methodCall[1],
        binding.declarationLine,
        sinkLine,
      )
    ) {
      return undefined;
    }
    const open = structural.indexOf("(", methodCall.index);
    const close = matchingCallParenthesis(structural, open);
    if (open < 0 || close < 0) return undefined;
    const arguments_ = splitJavascriptArguments(
      original.slice(open + 1, close),
    );
    const value =
      methodCall[2] === "request"
        ? javascriptObjectPropertyValue(arguments_[0] ?? "", "url")
        : arguments_[0];
    if (value === undefined || value.trim() === "") return undefined;
    return {
      urlExpression: value.trim(),
      axiosReceiver: methodCall[1],
      callStartLine: sinkLine,
      callEndLine:
        sinkLine + (structural.slice(0, close).match(/\n/gu)?.length ?? 0),
      ...(binding.kind === "instance"
        ? {
            axiosConfigurationLine: binding.declarationLine,
            axiosConfigurationEndLine: binding.configurationEndLine,
          }
        : {}),
    };
  }

  const directCall = /\b([A-Za-z_$][\w$]*)\s*\(/u.exec(structural);
  if (directCall?.index === undefined || directCall[1] === undefined) {
    return undefined;
  }
  const binding = bindings.get(directCall[1]);
  if (
    binding === undefined ||
    binding.declarationLine > sinkLine ||
    javascriptIdentifierReassignedBetween(
      lines,
      directCall[1],
      binding.declarationLine,
      sinkLine,
    )
  ) {
    return undefined;
  }
  const open = structural.indexOf("(", directCall.index);
  const close = matchingCallParenthesis(structural, open);
  if (open < 0 || close < 0) return undefined;
  const first = splitJavascriptArguments(original.slice(open + 1, close))[0];
  if (first === undefined || first.trim() === "") return undefined;
  return {
    urlExpression: javascriptObjectPropertyValue(first, "url") ?? first.trim(),
    axiosReceiver: directCall[1],
    callStartLine: sinkLine,
    callEndLine:
      sinkLine + (structural.slice(0, close).match(/\n/gu)?.length ?? 0),
    ...(binding.kind === "instance"
      ? {
          axiosConfigurationLine: binding.declarationLine,
          axiosConfigurationEndLine: binding.configurationEndLine,
        }
      : {}),
  };
}

function nodeAxiosConfigurationControls(
  lines: readonly string[],
  sink: NodeHttpUrlSink,
  patterns: readonly FrameworkModelPattern[],
): Array<{ kind: string; line: number }> {
  const ranges = [
    ...(sink.axiosConfigurationLine !== undefined &&
    sink.axiosConfigurationEndLine !== undefined
      ? [[sink.axiosConfigurationLine, sink.axiosConfigurationEndLine] as const]
      : []),
    ...(sink.callStartLine !== undefined && sink.callEndLine !== undefined
      ? [[sink.callStartLine, sink.callEndLine] as const]
      : []),
  ];
  return ranges
    .flatMap(([startLine, endLine]) =>
      matchingJavascriptControlLines(
        lines.slice(startLine - 1, endLine),
        patterns,
        8,
      ).map((control) => ({
        ...control,
        line: control.line + startLine - 1,
      })),
    )
    .filter(
      (control, index, all) =>
        all.findIndex(
          (candidate) =>
            candidate.kind === control.kind && candidate.line === control.line,
        ) === index,
    );
}

function nodeHttpUrlSink(
  lines: readonly string[],
  sinkLine: number,
): NodeHttpUrlSink | undefined {
  const structural = javascriptStructuralLines([lines[sinkLine - 1] ?? ""])[0]!;
  if (
    /\b(?:fetch|got)\s*\(|\bgot\s*\.\s*(?:delete|get|head|options|patch|post|put|request)\s*\(|\b(?:https?|undici)\s*\.\s*(?:get|request)\s*\(/u.test(
      structural,
    )
  ) {
    return {};
  }
  return nodeAxiosUrlArgument(lines, sinkLine);
}

function nodeNativeHttpUrlArgument(
  lines: readonly string[],
  sinkLine: number,
): NodeHttpUrlSink | undefined {
  const endLine = Math.min(lines.length, sinkLine + 12);
  const original = javascriptCodeLinesWithoutComments(
    lines.slice(sinkLine - 1, endLine),
  ).join("\n");
  const structural = javascriptStructuralLines(
    lines.slice(sinkLine - 1, endLine),
  ).join("\n");
  const call =
    /\b(?:fetch|got)\s*\(|\bgot\s*\.\s*(?:delete|get|head|options|patch|post|put|request)\s*\(|\b(?:https?|undici)\s*\.\s*(?:get|request)\s*\(/u.exec(
      structural,
    );
  if (call?.index === undefined) return undefined;
  const open = structural.indexOf("(", call.index);
  const close = matchingCallParenthesis(structural, open);
  if (open < 0 || close < 0) return undefined;
  const first = splitJavascriptArguments(original.slice(open + 1, close))[0];
  if (first === undefined || first.trim() === "") return undefined;
  const urlExpression =
    javascriptObjectPropertyValue(first, "url") ??
    javascriptObjectPropertyValue(first, "href") ??
    javascriptObjectPropertyValue(first, "hostname") ??
    javascriptObjectPropertyValue(first, "host") ??
    first.trim();
  return {
    urlExpression,
    callStartLine: sinkLine,
    callEndLine:
      sinkLine + (structural.slice(0, close).match(/\n/gu)?.length ?? 0),
  };
}

function dotnetHttpClientSinkHasTypedReceiver(
  lines: readonly string[],
  sinkLine: number,
): boolean {
  const sinkExpression = javaCallExpression(lines, sinkLine, lines.length);
  if (
    /\bnew\s+HttpClient\s*\([^)]*\)\s*\.(?:DeleteAsync|GetAsync|GetByteArrayAsync|GetStreamAsync|GetStringAsync|PatchAsync|PostAsync|PutAsync)\s*\(/u.test(
      sinkExpression,
    )
  ) {
    return true;
  }
  const receiver =
    /\b([A-Za-z_]\w*)\s*\.(?:DeleteAsync|GetAsync|GetByteArrayAsync|GetStreamAsync|GetStringAsync|PatchAsync|PostAsync|PutAsync)\s*\(/u.exec(
      sinkExpression,
    )?.[1];
  if (receiver === undefined) return false;

  const structuralText = cFamilyStructuralLines(lines).join("\n");
  const escapedReceiver = escapeRegularExpression(receiver);
  const typedDeclaration = new RegExp(
    `\\bHttpClient\\s+${escapedReceiver}\\b`,
    "u",
  );
  const constructedClient = new RegExp(
    `\\bvar\\s+${escapedReceiver}\\s*=\\s*(?:new\\s+HttpClient\\s*\\(|[A-Za-z_]\\w*\\.CreateClient\\s*\\()`,
    "u",
  );
  return (
    typedDeclaration.test(structuralText) ||
    constructedClient.test(structuralText)
  );
}

function javaWebClientUriSinkHasTypedReceiver(
  lines: readonly string[],
  sinkLine: number,
): boolean {
  const structuralLines = cFamilyStructuralLines(lines);
  const structuralText = structuralLines.join("\n");
  const windowStart = Math.max(0, sinkLine - 13);
  const windowEnd = Math.min(lines.length, sinkLine + 12);
  const windowLines = structuralLines.slice(windowStart, windowEnd);
  const windowText = windowLines.join("\n");
  const precedingLength = structuralLines
    .slice(windowStart, Math.max(windowStart, sinkLine - 1))
    .join("\n").length;
  const uriCall = [...windowText.matchAll(/\.\s*uri\s*\(/gu)].find(
    (match) => (match.index ?? -1) >= precedingLength,
  );
  if (uriCall?.index === undefined) return false;

  const statementPrefix = windowText.slice(0, uriCall.index);
  const statementBoundary = Math.max(
    statementPrefix.lastIndexOf(";"),
    statementPrefix.lastIndexOf("{"),
    statementPrefix.lastIndexOf("}"),
  );
  const statement = windowText.slice(statementBoundary + 1);
  const webClientMethods = "delete|get|head|method|options|patch|post|put";
  const webClientImported =
    /^\s*import\s+org\.springframework\.web\.reactive\.function\.client\.(?:WebClient|\*)\s*;/mu.test(
      structuralText,
    );
  const shadowsWebClient = /\b(?:class|interface|record)\s+WebClient\b/u.test(
    structuralText,
  );

  const receiverIsTypedWebClient = (receiverName: string): boolean => {
    const receiver = escapeRegularExpression(receiverName);
    if (
      new RegExp(
        String.raw`\borg\s*\.\s*springframework\s*\.\s*web\s*\.\s*reactive\s*\.\s*function\s*\.\s*client\s*\.\s*WebClient\s+${receiver}\b`,
        "u",
      ).test(structuralText)
    ) {
      return true;
    }
    if (!webClientImported || shadowsWebClient) return false;
    return (
      new RegExp(String.raw`\bWebClient\s+${receiver}\b`, "u").test(
        structuralText,
      ) ||
      new RegExp(
        String.raw`\bvar\s+${receiver}\s*=\s*WebClient\s*\.\s*(?:create|builder)\s*\(`,
        "u",
      ).test(structuralText)
    );
  };

  const fullyQualifiedConstruction = new RegExp(
    String.raw`\borg\s*\.\s*springframework\s*\.\s*web\s*\.\s*reactive\s*\.\s*function\s*\.\s*client\s*\.\s*WebClient\s*\.\s*(?:create\s*\([^)]*\)|builder\s*\(\)[\s\S]*?\.\s*build\s*\(\))[\s\S]*?\.\s*(?:${webClientMethods})\s*\([^;{}]*\)[\s\S]*?\.\s*uri\s*\(`,
    "u",
  );
  if (fullyQualifiedConstruction.test(statement)) return true;
  if (
    webClientImported &&
    !shadowsWebClient &&
    new RegExp(
      String.raw`\bWebClient\s*\.\s*(?:create\s*\([^)]*\)|builder\s*\(\)[\s\S]*?\.\s*build\s*\(\))[\s\S]*?\.\s*(?:${webClientMethods})\s*\([^;{}]*\)[\s\S]*?\.\s*uri\s*\(`,
      "u",
    ).test(statement)
  ) {
    return true;
  }

  const directReceiver = new RegExp(
    String.raw`\b([A-Za-z_$][\w$]*)\s*\.\s*(?:${webClientMethods})\s*\([^;{}]*\)[\s\S]*?\.\s*uri\s*\(`,
    "u",
  ).exec(statement)?.[1];
  if (
    directReceiver !== undefined &&
    receiverIsTypedWebClient(directReceiver)
  ) {
    return true;
  }

  const uriReceiver = /\b([A-Za-z_$][\w$]*)\s*\.\s*uri\s*\(/u.exec(
    statement,
  )?.[1];
  if (uriReceiver === undefined) return false;
  const priorMethodText = structuralLines
    .slice(Math.max(0, sinkLine - MAX_WRAPPER_FUNCTION_LINES), sinkLine - 1)
    .join("\n");
  const requestSpec = escapeRegularExpression(uriReceiver);
  const assignedClient = new RegExp(
    String.raw`\b(?:var|(?:(?:org\s*\.\s*springframework\s*\.\s*web\s*\.\s*reactive\s*\.\s*function\s*\.\s*client\s*\.)?WebClient\s*\.\s*)?(?:RequestHeadersUriSpec|RequestBodyUriSpec)(?:\s*<[^;=]+>)?)\s+${requestSpec}\s*=\s*([A-Za-z_$][\w$]*)\s*\.\s*(?:${webClientMethods})\s*\(`,
    "u",
  ).exec(priorMethodText)?.[1];
  return (
    assignedClient !== undefined && receiverIsTypedWebClient(assignedClient)
  );
}

function javaOkHttpUrlSinkHasTypedDispatch(
  lines: readonly string[],
  sinkLine: number,
): boolean {
  const sinkExpression = javaOutboundCallExpression(
    lines,
    sinkLine,
    lines.length,
  );
  if (!/^\.\s*url\s*\(/u.test(sinkExpression)) return false;

  const method = exportedJavaMethods(lines).find(
    (candidate) =>
      sinkLine >= candidate.startLine && sinkLine <= candidate.endLine,
  );
  if (method === undefined) return false;

  const structuralLines = cFamilyStructuralLines(lines);
  const structuralText = structuralLines.join("\n");
  const methodLines = structuralLines.slice(
    method.startLine - 1,
    method.endLine,
  );
  const methodText = methodLines.join("\n");
  const sinkLineText = structuralLines[sinkLine - 1] ?? "";
  const sinkColumn = sinkLineText.search(/\.\s*url\s*\(/u);
  if (sinkColumn < 0) return false;
  const sinkOffset =
    methodLines
      .slice(0, sinkLine - method.startLine)
      .reduce((length, line) => length + line.length + 1, 0) + sinkColumn;

  const requestImported = /^\s*import\s+okhttp3\.(?:Request|\*)\s*;/mu.test(
    structuralText,
  );
  const clientImported = /^\s*import\s+okhttp3\.(?:OkHttpClient|\*)\s*;/mu.test(
    structuralText,
  );
  const callImported = /^\s*import\s+okhttp3\.(?:Call|\*)\s*;/mu.test(
    structuralText,
  );
  const shadowsRequest = /\b(?:class|interface|record)\s+Request\b/u.test(
    structuralText,
  );
  const shadowsClient = /\b(?:class|interface|record)\s+OkHttpClient\b/u.test(
    structuralText,
  );
  const shadowsCall = /\b(?:class|interface|record)\s+Call\b/u.test(
    structuralText,
  );
  const simpleRequestIsTyped = requestImported && !shadowsRequest;
  const simpleClientIsTyped = clientImported && !shadowsClient;
  const simpleCallIsTyped = callImported && !shadowsCall;
  const requestType = simpleRequestIsTyped
    ? String.raw`(?:okhttp3\s*\.\s*)?Request`
    : String.raw`okhttp3\s*\.\s*Request`;
  const requestBuilderConstruction = String.raw`new\s+${requestType}\s*\.\s*Builder\s*\(\s*\)`;
  const callType = simpleCallIsTyped
    ? String.raw`(?:(?:okhttp3\s*\.\s*)?Call|var)`
    : String.raw`(?:okhttp3\s*\.\s*Call|var)`;

  const clientReceiverIsTyped = (receiverName: string): boolean => {
    const receiver = escapeRegularExpression(receiverName);
    if (
      new RegExp(
        String.raw`\bokhttp3\s*\.\s*OkHttpClient\s+${receiver}\b`,
        "u",
      ).test(structuralText)
    ) {
      return true;
    }
    if (!simpleClientIsTyped) return false;
    return (
      new RegExp(String.raw`\bOkHttpClient\s+${receiver}\b`, "u").test(
        structuralText,
      ) ||
      new RegExp(
        String.raw`\bvar\s+${receiver}\s*=\s*new\s+(?:okhttp3\s*\.\s*)?OkHttpClient(?:\s*\.\s*Builder)?\s*\(`,
        "u",
      ).test(structuralText)
    );
  };

  const dispatchedByTypedClient = (
    textAfterConstruction: string,
    requestName: string,
  ): boolean => {
    const request = escapeRegularExpression(requestName);
    const directConstruction = new RegExp(
      String.raw`\bnew\s+okhttp3\s*\.\s*OkHttpClient(?:\s*\.\s*Builder\s*\(\s*\)[^;{}]{0,400}?\.\s*build\s*\(\s*\)|\s*\(\s*\))\s*\.\s*newCall\s*\(\s*${request}\s*\)\s*\.\s*(?:execute|enqueue)\s*\(`,
      "u",
    );
    if (directConstruction.test(textAfterConstruction)) return true;
    if (
      simpleClientIsTyped &&
      new RegExp(
        String.raw`\bnew\s+OkHttpClient(?:\s*\.\s*Builder\s*\(\s*\)[^;{}]{0,400}?\.\s*build\s*\(\s*\)|\s*\(\s*\))\s*\.\s*newCall\s*\(\s*${request}\s*\)\s*\.\s*(?:execute|enqueue)\s*\(`,
        "u",
      ).test(textAfterConstruction)
    ) {
      return true;
    }
    const dispatch = new RegExp(
      String.raw`\b([A-Za-z_$][\w$]*)\s*\.\s*newCall\s*\(\s*${request}\s*\)\s*\.\s*(?:execute|enqueue)\s*\(`,
      "gu",
    );
    if (
      [...textAfterConstruction.matchAll(dispatch)].some(
        (match) => match[1] !== undefined && clientReceiverIsTyped(match[1]),
      )
    ) {
      return true;
    }

    const preparedDispatch = new RegExp(
      String.raw`\b${callType}\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\.\s*newCall\s*\(\s*${request}\s*\)\s*;([^{}]{0,800}?)\b\1\s*\.\s*(?:execute|enqueue)\s*\(`,
      "gu",
    );
    return [...textAfterConstruction.matchAll(preparedDispatch)].some(
      (match) => {
        const callName = match[1];
        const clientName = match[2];
        const between = match[3] ?? "";
        if (callName === undefined || clientName === undefined) return false;
        const callReassigned = new RegExp(
          String.raw`\b${escapeRegularExpression(callName)}\s*=(?!=)`,
          "u",
        ).test(between);
        return !callReassigned && clientReceiverIsTyped(clientName);
      },
    );
  };

  const assignedRequest = new RegExp(
    String.raw`\b(?:${requestType}|var)\s+([A-Za-z_$][\w$]*)\s*=\s*${requestBuilderConstruction}[^;{}]{0,1600}?\.\s*url\s*\([^;{}]*\)[^;{}]{0,800}?\.\s*build\s*\(\s*\)`,
    "gu",
  );
  for (const match of methodText.matchAll(assignedRequest)) {
    if (match.index === undefined || match[1] === undefined) continue;
    const end = match.index + match[0].length;
    if (sinkOffset < match.index || sinkOffset >= end) continue;
    if (dispatchedByTypedClient(methodText.slice(end), match[1])) return true;
  }

  const builderReceiver = new RegExp(
    String.raw`\b([A-Za-z_$][\w$]*)\s*\.\s*url\s*\(`,
    "u",
  ).exec(sinkLineText)?.[1];
  if (builderReceiver !== undefined) {
    const builder = escapeRegularExpression(builderReceiver);
    const beforeSink = methodText.slice(0, sinkOffset);
    const afterSink = methodText.slice(sinkOffset);
    const typedBuilder = new RegExp(
      String.raw`\b(?:${requestType}\s*\.\s*Builder|var)\s+${builder}\s*=\s*${requestBuilderConstruction}`,
      "u",
    );
    const builtRequest = new RegExp(
      String.raw`\b(?:${requestType}|var)\s+([A-Za-z_$][\w$]*)\s*=\s*${builder}\s*\.\s*build\s*\(\s*\)`,
      "u",
    ).exec(afterSink);
    if (
      typedBuilder.test(beforeSink) &&
      builtRequest?.[1] !== undefined &&
      dispatchedByTypedClient(
        afterSink.slice((builtRequest.index ?? 0) + builtRequest[0].length),
        builtRequest[1],
      )
    ) {
      return true;
    }
  }

  const inlineStart = Math.max(0, sinkOffset - 1000);
  const inlineEnd = Math.min(methodText.length, sinkOffset + 1200);
  const inlineWindow = methodText.slice(inlineStart, inlineEnd);
  const inlineSinkOffset = sinkOffset - inlineStart;
  const inlineRequest = new RegExp(
    String.raw`\b([A-Za-z_$][\w$]*)\s*\.\s*newCall\s*\(\s*${requestBuilderConstruction}[^;{}]{0,800}?\.\s*url\s*\([^;{}]*\)[^;{}]{0,400}?\.\s*build\s*\(\s*\)\s*\)\s*\.\s*(?:execute|enqueue)\s*\(`,
    "gu",
  );
  if (
    [...inlineWindow.matchAll(inlineRequest)].some((match) => {
      if (match.index === undefined || match[1] === undefined) return false;
      const matchEnd = match.index + match[0].length;
      return (
        inlineSinkOffset >= match.index &&
        inlineSinkOffset < matchEnd &&
        clientReceiverIsTyped(match[1])
      );
    })
  ) {
    return true;
  }

  const directInlineRequest = new RegExp(
    String.raw`\bnew\s+(?:okhttp3\s*\.\s*)?OkHttpClient(?:\s*\.\s*Builder\s*\(\s*\)[^;{}]{0,400}?\.\s*build\s*\(\s*\)|\s*\(\s*\))\s*\.\s*newCall\s*\(\s*${requestBuilderConstruction}[^;{}]{0,800}?\.\s*url\s*\([^;{}]*\)[^;{}]{0,400}?\.\s*build\s*\(\s*\)\s*\)\s*\.\s*(?:execute|enqueue)\s*\(`,
    "gu",
  );
  return [...inlineWindow.matchAll(directInlineRequest)].some((match) => {
    if (match.index === undefined) return false;
    const matchEnd = match.index + match[0].length;
    return (
      inlineSinkOffset >= match.index &&
      inlineSinkOffset < matchEnd &&
      (/\bnew\s+okhttp3\s*\./u.test(match[0]) || simpleClientIsTyped)
    );
  });
}

function javaOutboundHttpSinkHasTypedReceiver(
  lines: readonly string[],
  sinkLine: number,
): boolean {
  if (javaOkHttpUrlSinkHasTypedDispatch(lines, sinkLine)) return true;
  if (javaWebClientUriSinkHasTypedReceiver(lines, sinkLine)) return true;
  const sinkExpression = cFamilyStructuralLines(
    lines.slice(sinkLine - 1, Math.min(lines.length, sinkLine + 12)),
  ).join("\n");
  const structuralText = cFamilyStructuralLines(lines).join("\n");

  const httpClientMethods = "send|sendAsync";
  if (
    new RegExp(
      `\\bjava\\s*\\.\\s*net\\s*\\.\\s*http\\s*\\.\\s*HttpClient\\s*\\.\\s*(?:newHttpClient|newBuilder)\\s*\\(\\)[\\s\\S]*?\\.\\s*(?:${httpClientMethods})\\s*\\(`,
      "u",
    ).test(sinkExpression)
  ) {
    return true;
  }
  const httpClientImported =
    /^\s*import\s+java\.net\.http\.(?:HttpClient|\*)\s*;/mu.test(
      structuralText,
    );
  const shadowsHttpClient = /\b(?:class|interface|record)\s+HttpClient\b/u.test(
    structuralText,
  );
  if (
    httpClientImported &&
    !shadowsHttpClient &&
    new RegExp(
      `\\bHttpClient\\s*\\.\\s*(?:newHttpClient|newBuilder)\\s*\\(\\)[\\s\\S]*?\\.\\s*(?:${httpClientMethods})\\s*\\(`,
      "u",
    ).test(sinkExpression)
  ) {
    return true;
  }
  const httpClientReceiver = new RegExp(
    `\\b([A-Za-z_$][\\w$]*)\\s*\\.\\s*(?:${httpClientMethods})\\s*\\(`,
    "u",
  ).exec(sinkExpression)?.[1];
  if (httpClientReceiver !== undefined) {
    const receiver = escapeRegularExpression(httpClientReceiver);
    const fullyQualifiedDeclaration = new RegExp(
      `\\bjava\\s*\\.\\s*net\\s*\\.\\s*http\\s*\\.\\s*HttpClient\\s+${receiver}\\b`,
      "u",
    );
    if (fullyQualifiedDeclaration.test(structuralText)) return true;
    const importedDeclaration = new RegExp(
      `\\bHttpClient\\s+${receiver}\\b`,
      "u",
    );
    const constructedClient = new RegExp(
      `\\bvar\\s+${receiver}\\s*=\\s*(?:java\\s*\\.\\s*net\\s*\\.\\s*http\\s*\\.\\s*)?HttpClient\\s*\\.\\s*(?:newHttpClient|newBuilder)\\s*\\(`,
      "u",
    );
    if (
      !shadowsHttpClient &&
      httpClientImported &&
      (importedDeclaration.test(structuralText) ||
        constructedClient.test(structuralText))
    ) {
      return true;
    }
  }

  const restTemplateMethods =
    "delete|exchange|execute|getForEntity|getForObject|headForHeaders|optionsForAllow|patchForObject|postForEntity|postForLocation|postForObject|put";
  if (
    new RegExp(
      `\\bnew\\s+org\\s*\\.\\s*springframework\\s*\\.\\s*web\\s*\\.\\s*client\\s*\\.\\s*RestTemplate\\s*\\([^)]*\\)\\s*\\.\\s*(?:${restTemplateMethods})\\s*\\(`,
      "u",
    ).test(sinkExpression)
  ) {
    return true;
  }
  const restTemplateImported =
    /^\s*import\s+org\.springframework\.web\.client\.(?:RestTemplate|\*)\s*;/mu.test(
      structuralText,
    );
  const shadowsRestTemplate =
    /\b(?:class|interface|record)\s+RestTemplate\b/u.test(structuralText);
  if (
    restTemplateImported &&
    !shadowsRestTemplate &&
    new RegExp(
      `\\bnew\\s+RestTemplate\\s*\\([^)]*\\)\\s*\\.\\s*(?:${restTemplateMethods})\\s*\\(`,
      "u",
    ).test(sinkExpression)
  ) {
    return true;
  }
  const restTemplateReceiver = new RegExp(
    `\\b([A-Za-z_$][\\w$]*)\\s*\\.\\s*(?:${restTemplateMethods})\\s*\\(`,
    "u",
  ).exec(sinkExpression)?.[1];
  if (restTemplateReceiver === undefined) return false;
  const receiver = escapeRegularExpression(restTemplateReceiver);
  const fullyQualifiedDeclaration = new RegExp(
    `\\borg\\s*\\.\\s*springframework\\s*\\.\\s*web\\s*\\.\\s*client\\s*\\.\\s*RestTemplate\\s+${receiver}\\b`,
    "u",
  );
  if (fullyQualifiedDeclaration.test(structuralText)) return true;
  const importedDeclaration = new RegExp(
    `\\bRestTemplate\\s+${receiver}\\b`,
    "u",
  );
  const constructedTemplate = new RegExp(
    `\\bvar\\s+${receiver}\\s*=\\s*new\\s+(?:org\\s*\\.\\s*springframework\\s*\\.\\s*web\\s*\\.\\s*client\\s*\\.\\s*)?RestTemplate\\s*\\(`,
    "u",
  );
  return (
    !shadowsRestTemplate &&
    restTemplateImported &&
    (importedDeclaration.test(structuralText) ||
      constructedTemplate.test(structuralText))
  );
}

function javaFilesystemSinkHasTypedReceiver(
  lines: readonly string[],
  sinkLine: number,
): boolean {
  const sinkExpression = javaCallExpression(lines, sinkLine, lines.length);
  const fileOperations =
    "copy|delete|deleteIfExists|lines|move|newBufferedReader|newBufferedWriter|newByteChannel|newInputStream|newOutputStream|readAllBytes|readAllLines|readString|write|writeString";
  const streamTypes =
    "FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile";
  if (
    new RegExp(
      `\\bjava\\s*\\.\\s*nio\\s*\\.\\s*file\\s*\\.\\s*Files\\s*\\.\\s*(?:${fileOperations})\\s*\\(`,
      "u",
    ).test(sinkExpression) ||
    new RegExp(
      `\\bnew\\s+java\\s*\\.\\s*io\\s*\\.\\s*(?:${streamTypes})\\s*\\(`,
      "u",
    ).test(sinkExpression)
  ) {
    return true;
  }

  const structuralText = cFamilyStructuralLines(lines).join("\n");
  const filesImported = /^\s*import\s+java\.nio\.file\.(?:Files|\*)\s*;/mu.test(
    structuralText,
  );
  const shadowsFilesType = /\b(?:class|interface|record)\s+Files\b/u.test(
    structuralText,
  );
  if (
    filesImported &&
    !shadowsFilesType &&
    new RegExp(`\\bFiles\\s*\\.\\s*(?:${fileOperations})\\s*\\(`, "u").test(
      sinkExpression,
    )
  ) {
    return true;
  }

  for (const streamType of streamTypes.split("|")) {
    const imported = new RegExp(
      `^\\s*import\\s+java\\.io\\.(?:${streamType}|\\*)\\s*;`,
      "mu",
    ).test(structuralText);
    const shadowed = new RegExp(
      `\\b(?:class|interface|record)\\s+${streamType}\\b`,
      "u",
    ).test(structuralText);
    const constructed = new RegExp(`\\bnew\\s+${streamType}\\s*\\(`, "u").test(
      sinkExpression,
    );
    if (imported && !shadowed && constructed) return true;
  }
  return false;
}

function javaMethodParameterIndexesReachingSink(
  lines: readonly string[],
  method: ExportedJavaMethod,
  sinkLine: number,
  sinkExpression: string,
): number[] {
  const structuralBody = cFamilyStructuralLines(
    lines.slice(method.startLine - 1, sinkLine),
  ).join("\n");
  const assignments = [
    ...structuralBody.matchAll(/\b([A-Za-z_$][\w$]*)\s*=(?!=)\s*([^;]+);/gu),
  ];
  return method.parameters.flatMap((parameter, parameterIndex) => {
    const reachingIdentifiers = new Set([parameter.name]);
    for (const assignment of assignments) {
      const target = assignment[1];
      const value = assignment[2];
      if (target === undefined || value === undefined) continue;
      const valueReaches = [...reachingIdentifiers].some((identifier) =>
        cFamilyLineReferencesIdentifier(value, identifier),
      );
      if (valueReaches) reachingIdentifiers.add(target);
      else reachingIdentifiers.delete(target);
    }
    return [...reachingIdentifiers].some((identifier) =>
      cFamilyLineReferencesIdentifier(sinkExpression, identifier),
    )
      ? [parameterIndex]
      : [];
  });
}

function dotnetFilesystemSinkHasTypedReceiver(
  lines: readonly string[],
  sinkLine: number,
  projectProvidesSystemIo = false,
): boolean {
  const sinkExpression = javaCallExpression(lines, sinkLine, lines.length);
  if (
    /\b(?:System\s*\.\s*IO\s*\.\s*)File\s*\.\s*(?:AppendAllLines|AppendAllText|AppendAllTextAsync|Copy|Create|CreateText|Delete|Move|Open|OpenHandle|OpenRead|OpenText|OpenWrite|ReadAllBytes|ReadAllBytesAsync|ReadAllLines|ReadAllLinesAsync|ReadAllText|ReadAllTextAsync|ReadLines|WriteAllBytes|WriteAllBytesAsync|WriteAllLines|WriteAllLinesAsync|WriteAllText|WriteAllTextAsync)\s*\(/u.test(
      sinkExpression,
    ) ||
    /\bnew\s+System\s*\.\s*IO\s*\.\s*FileStream\s*\(/u.test(sinkExpression)
  ) {
    return true;
  }

  const structuralLines = cFamilyStructuralLines(lines);
  const structuralText = structuralLines.join("\n");
  if (
    !projectProvidesSystemIo &&
    !/^\s*(?:global\s+)?using\s+System\.IO\s*;/mu.test(structuralText)
  ) {
    return false;
  }
  const shadowsFileType = /\b(?:class|record|struct)\s+File\b/u.test(
    structuralText,
  );
  const shadowsFileStreamType =
    /\b(?:class|record|struct)\s+FileStream\b/u.test(structuralText);
  const staticFileSink =
    /\bFile\s*\.\s*(?:AppendAllLines|AppendAllText|AppendAllTextAsync|Copy|Create|CreateText|Delete|Move|Open|OpenHandle|OpenRead|OpenText|OpenWrite|ReadAllBytes|ReadAllBytesAsync|ReadAllLines|ReadAllLinesAsync|ReadAllText|ReadAllTextAsync|ReadLines|WriteAllBytes|WriteAllBytesAsync|WriteAllLines|WriteAllLinesAsync|WriteAllText|WriteAllTextAsync)\s*\(/u.test(
      sinkExpression,
    );
  const fileStreamSink = /\bnew\s+FileStream\s*\(/u.test(sinkExpression);
  return (
    (staticFileSink && !shadowsFileType) ||
    (fileStreamSink && !shadowsFileStreamType)
  );
}

function dotnetProjectProvidesSystemIo(
  files: readonly SourceFileSnapshot[],
  sourcePath: string,
): boolean {
  const projects = files
    .filter(
      (file) =>
        file.extension === ".csproj" &&
        pathWithinDirectory(sourcePath, posix.dirname(file.path)),
    )
    .sort(
      (left, right) =>
        posix.dirname(right.path).length - posix.dirname(left.path).length,
    );
  const project = projects[0];
  if (project === undefined) return false;

  const projectRoot = posix.dirname(project.path);
  const configurationFiles = files.filter(
    (file) =>
      file.path === project.path ||
      (file.extension === ".props" &&
        pathWithinDirectory(sourcePath, posix.dirname(file.path))),
  );
  if (
    configurationFiles.some((file) => {
      const configuration = file.text.replace(/<!--[\s\S]*?-->/gu, "");
      return (
        /<ImplicitUsings\b[^>]*>\s*(?:enable|true)\s*<\/ImplicitUsings>/iu.test(
          configuration,
        ) ||
        /<Using\b[^>]*\bInclude\s*=\s*["']System\.IO["'][^>]*\/?\s*>/iu.test(
          configuration,
        )
      );
    })
  ) {
    return true;
  }

  return files.some(
    (file) =>
      file.extension === ".cs" &&
      pathWithinDirectory(file.path, projectRoot) &&
      /^\s*global\s+using\s+System\.IO\s*;/mu.test(
        cFamilyStructuralLines(file.lines).join("\n"),
      ),
  );
}

function pathWithinDirectory(path: string, directory: string): boolean {
  return (
    directory === "." || path === directory || path.startsWith(`${directory}/`)
  );
}

function pythonIdentifierReassignedBetween(
  lines: readonly string[],
  identifier: string,
  afterLine: number,
  beforeLine: number,
): boolean {
  const structuralLines = pythonStructuralLines(lines);
  const escapedIdentifier = escapeRegularExpression(identifier);
  const reassignment = new RegExp(
    `^\\s*${escapedIdentifier}\\s*(?::[^=]+)?(?:[+\\-*/%&|^]?=|:=)`,
    "u",
  );
  return structuralLines
    .slice(afterLine, Math.max(afterLine, beforeLine - 1))
    .some((candidate) => reassignment.test(candidate));
}

function javascriptIdentifierReassignedBetween(
  lines: readonly string[],
  identifier: string,
  afterLine: number,
  beforeLine: number,
): boolean {
  const escapedIdentifier = escapeRegularExpression(identifier);
  const reassignment = new RegExp(
    `(?:\\b${escapedIdentifier}\\s*(?:[+\\-*/%&|^?]=|=(?!=|>)|\\+\\+|--)|(?:\\+\\+|--)\\s*${escapedIdentifier}\\b|\\b(?:const|let|var)\\s+${escapedIdentifier}\\b)`,
    "u",
  );
  return lines
    .slice(afterLine, Math.max(afterLine, beforeLine - 1))
    .some((candidate) =>
      reassignment.test(javascriptCodeBeforeComment(candidate)),
    );
}

function javaIdentifierReassignedBetween(
  lines: readonly string[],
  identifier: string,
  afterLine: number,
  beforeLine: number,
): boolean {
  const escapedIdentifier = escapeRegularExpression(identifier);
  const reassignment = new RegExp(
    `(?:\\b${escapedIdentifier}\\s*(?:[+\\-*/%&|^]?=|\\+\\+|--)|(?:\\+\\+|--)\\s*${escapedIdentifier}\\b|\\b(?:final\\s+)?[A-Za-z_$][\\w$.[\\]<>?,]*\\s+${escapedIdentifier}\\b)`,
    "u",
  );
  const structuralLines = cFamilyStructuralLines(lines);
  return structuralLines
    .slice(afterLine, Math.max(afterLine, beforeLine - 1))
    .some((candidate) => reassignment.test(candidate));
}

function lineReferencesIdentifier(line: string, identifier: string): boolean {
  const expression = new RegExp(
    `\\b${escapeRegularExpression(identifier)}\\b`,
    "u",
  );
  return (
    expression.test(javascriptStructuralCode(line)) ||
    expression.test(javascriptTemplateExpressionCode(line))
  );
}

function escapeRegularExpression(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function matchingModelLines(
  lines: readonly string[],
  patterns: readonly FrameworkModelPattern[],
  limit: number,
): Array<{ kind: string; line: number }> {
  const matches: Array<{ kind: string; line: number }> = [];
  for (let index = 0; index < lines.length && matches.length < limit; index++) {
    for (const pattern of patterns) {
      if (pattern.expression.test(lines[index] ?? "")) {
        matches.push({ kind: pattern.kind, line: index + 1 });
        break;
      }
    }
  }
  return matches;
}

function matchingJavascriptModelLines(
  lines: readonly string[],
  patterns: readonly FrameworkModelPattern[],
  limit: number,
): Array<{ kind: string; line: number }> {
  const matches: Array<{ kind: string; line: number }> = [];
  for (let index = 0; index < lines.length && matches.length < limit; index++) {
    const structuralLine = javascriptStructuralCode(lines[index] ?? "");
    for (const pattern of patterns) {
      if (pattern.expression.test(structuralLine)) {
        matches.push({ kind: pattern.kind, line: index + 1 });
        break;
      }
    }
  }
  return matches;
}

function matchingJavascriptControlLines(
  lines: readonly string[],
  patterns: readonly FrameworkModelPattern[],
  limit: number,
): Array<{ kind: string; line: number }> {
  const matches: Array<{ kind: string; line: number }> = [];
  const codeLines = javascriptCodeLinesWithoutComments(lines);
  const structuralLines = javascriptStructuralLines(lines);
  for (
    let index = 0;
    index < codeLines.length && matches.length < limit;
    index++
  ) {
    for (const pattern of patterns) {
      const code = codeLines[index] ?? "";
      const structural = structuralLines[index] ?? "";
      const matched =
        pattern.kind === "redirects-disabled"
          ? /\bmaxRedirects\s*:\s*0\b/iu.test(structural) ||
            (/\bredirect\s*:/iu.test(structural) &&
              /\bredirect\s*:\s*["']error["']/iu.test(code))
          : pattern.expression.test(structural);
      if (matched) {
        matches.push({ kind: pattern.kind, line: index + 1 });
        break;
      }
    }
  }
  return matches;
}

function matchingPythonModelLines(
  lines: readonly string[],
  patterns: readonly FrameworkModelPattern[],
  limit: number,
): Array<{ kind: string; line: number }> {
  const matches: Array<{ kind: string; line: number }> = [];
  const structuralLines = pythonStructuralLines(lines);
  for (let index = 0; index < lines.length && matches.length < limit; index++) {
    const structuralLine = structuralLines[index] ?? "";
    for (const pattern of patterns) {
      if (pattern.expression.test(structuralLine)) {
        matches.push({ kind: pattern.kind, line: index + 1 });
        break;
      }
    }
  }
  return matches;
}

function matchingJavaModelLines(
  lines: readonly string[],
  patterns: readonly FrameworkModelPattern[],
  limit: number,
): Array<{ kind: string; line: number }> {
  const matches: Array<{ kind: string; line: number }> = [];
  const structuralLines = cFamilyStructuralLines(lines);
  for (let index = 0; index < lines.length && matches.length < limit; index++) {
    const structuralLine = structuralLines[index] ?? "";
    for (const pattern of patterns) {
      if (pattern.expression.test(structuralLine)) {
        matches.push({ kind: pattern.kind, line: index + 1 });
        break;
      }
    }
  }
  return matches;
}

function nearestModeledSource(
  sources: readonly { kind: string; line: number }[],
  sinkLine: number,
): { kind: string; line: number } {
  return [...sources].sort((left, right) => {
    const leftAfter = left.line > sinkLine ? 1 : 0;
    const rightAfter = right.line > sinkLine ? 1 : 0;
    return (
      leftAfter - rightAfter ||
      Math.abs(sinkLine - left.line) - Math.abs(sinkLine - right.line) ||
      left.line - right.line
    );
  })[0]!;
}

export async function buildCoverageGapInventory(
  scanDirectory: string | undefined,
  reviewedInventoryPaths?: ReadonlySet<string>,
  expectedCoverageMode?: string,
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
    const addGap = (gap: CoverageGapRecord): void => {
      gaps.push(
        reviewedInventoryPaths === undefined
          ? gap
          : {
              ...gap,
              directFileReviewObserved: reviewedInventoryPaths.has(path),
            },
      );
    };
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
      addGap({ path, reason: "missing_coverage_surface" });
    } else if (closed.length === 0) {
      addGap({
        path,
        reason:
          dispositions.length > 0 &&
          dispositions.every((disposition) => disposition === "needs_follow_up")
            ? "needs_follow_up"
            : "invalid_coverage_disposition",
        dispositions,
      });
    } else if (surfaces.length > 1) {
      addGap({
        path,
        reason: "conflicting_coverage_surfaces",
        dispositions,
      });
    } else if (
      reviewedInventoryPaths !== undefined &&
      !reviewedInventoryPaths.has(path)
    ) {
      addGap({ path, reason: "missing_direct_file_review" });
    } else {
      coveredPathCount += 1;
    }
  }
  for (let index = 0; index < coverage.deferredCount; index += 1) {
    gaps.push({
      path: `coverage.deferred[${index}]`,
      reason: "deferred_coverage_item",
    });
  }
  if (
    expectedCoverageMode !== undefined &&
    coverage.mode !== expectedCoverageMode
  ) {
    gaps.push({
      path: "coverage.mode",
      reason: "invalid_coverage_mode",
      expectedMode: expectedCoverageMode,
      actualMode: coverage.mode,
    });
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
  repository?: string,
): Promise<string> {
  if (scanDirectory === undefined) return "";
  const canonicalScanDirectory = await realpath(scanDirectory).catch(
    () => null,
  );
  if (canonicalScanDirectory === null) return "";
  const canonicalRepository =
    repository === undefined
      ? null
      : await realpath(repository).catch(() => null);
  const repositoryFileCache = new Map<string, string[] | null>();
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
    document = JSON.parse(
      stripUtf8Bom(findingsBytes.toString("utf8")),
    ) as unknown;
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
    const repositoryGrounding =
      canonicalRepository === null
        ? null
        : await repositoryCodeEvidenceGrounding(
            canonicalRepository,
            finding["codeEvidence"],
            locations,
            repositoryFileCache,
          );
    const substantiveCodeEvidence = isSubstantiveCodeEvidence(
      canonicalDraftCodeEvidence(finding["codeEvidence"]),
      locations,
    );
    if (!substantiveCodeEvidence || repositoryGrounding === false) {
      reasons.push("missing_or_unanchored_code_evidence");
    }
    if (repositoryGrounding === false) {
      reasons.push("invalid_or_ungrounded_code_evidence");
    }
    const codeEvidenceIds = findingCodeEvidenceIds(finding["codeEvidence"]);
    if (!isSubstantiveValidation(finding["validation"])) {
      reasons.push("missing_or_weak_validation");
    }
    reasons.push(
      ...validationClosureGaps(finding["validation"], codeEvidenceIds),
    );
    if (!isSubstantiveAttackPath(finding["attackPath"])) {
      reasons.push("missing_or_weak_attack_path");
    }
    reasons.push(
      ...attackPathClosureGaps(finding["attackPath"], codeEvidenceIds),
    );
    if (hasUnknownCodeEvidenceRefs(finding, codeEvidenceIds)) {
      reasons.push("unknown_code_evidence_refs");
    }
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

function validationClosureGaps(
  value: unknown,
  codeEvidenceIds: ReadonlySet<string>,
): FindingQualityGapReason[] {
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
  if (
    !hasNamedSubstantiveValue(value, ["evidence"]) &&
    !hasKnownCodeEvidenceRef(value, codeEvidenceIds, true)
  ) {
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

function hasKnownCodeEvidenceRef(
  value: unknown,
  codeEvidenceIds: ReadonlySet<string>,
  allowValidationEvidence = false,
): boolean {
  if (Array.isArray(value)) {
    return value.some((entry) =>
      hasKnownCodeEvidenceRef(entry, codeEvidenceIds, allowValidationEvidence),
    );
  }
  if (!isRecord(value)) return false;
  for (const [name, entry] of Object.entries(value)) {
    if (
      (["evidenceRefs", "evidence_refs"].includes(name) ||
        (allowValidationEvidence && name === "evidence")) &&
      Array.isArray(entry) &&
      entry.some(
        (reference) =>
          typeof reference === "string" && codeEvidenceIds.has(reference),
      )
    ) {
      return true;
    }
    if (
      hasKnownCodeEvidenceRef(entry, codeEvidenceIds, allowValidationEvidence)
    ) {
      return true;
    }
  }
  return false;
}

function attackPathClosureGaps(
  value: unknown,
  codeEvidenceIds: ReadonlySet<string>,
): FindingQualityGapReason[] {
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
    !["source", "sink"].every((field) =>
      hasSubstantiveOrKnownEvidenceValue(dataflow[field], codeEvidenceIds),
    ) ||
    !hasNamedSubstantiveValue(dataflow, ["outcome"], 3)
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
  if (
    !hasNamedSubstantiveValue(value, [
      "controlsBroken",
      "controls_broken",
      "brokenControls",
      "broken_controls",
      "controlBreaks",
      "control_breaks",
    ])
  ) {
    gaps.push("missing_broken_controls");
  }
  if (
    !hasNamedSubstantiveValue(value, ["evidenceRefs", "evidence_refs"], 3) &&
    !hasKnownCodeEvidenceRef(value, codeEvidenceIds)
  ) {
    gaps.push("missing_attack_path_evidence_refs");
  }
  return gaps;
}

function hasSubstantiveOrKnownEvidenceValue(
  value: unknown,
  codeEvidenceIds: ReadonlySet<string>,
): boolean {
  return (
    hasSubstantiveValue(value, 3) ||
    (typeof value === "string" && codeEvidenceIds.has(value))
  );
}

function findingCodeEvidenceIds(value: unknown): ReadonlySet<string> {
  if (!Array.isArray(value)) return new Set();
  return new Set(
    value.flatMap((evidence) => {
      if (!isRecord(evidence)) return [];
      const id = evidence["id"];
      return typeof id === "string" && id.trim() !== "" ? [id] : [];
    }),
  );
}

function hasUnknownCodeEvidenceRefs(
  finding: Record<string, unknown>,
  codeEvidenceIds: ReadonlySet<string>,
): boolean {
  for (const sectionName of [
    "rootCause",
    "validation",
    "attackPath",
  ] as const) {
    const section = finding[sectionName];
    if (hasUnknownEvidenceRefs(section, codeEvidenceIds)) return true;
  }
  return false;
}

function hasUnknownEvidenceRefs(
  value: unknown,
  codeEvidenceIds: ReadonlySet<string>,
): boolean {
  if (Array.isArray(value)) {
    return value.some((entry) =>
      hasUnknownEvidenceRefs(entry, codeEvidenceIds),
    );
  }
  if (!isRecord(value)) return false;
  for (const [name, entry] of Object.entries(value)) {
    if (name === "evidenceRefs" || name === "evidence_refs") {
      if (
        !Array.isArray(entry) ||
        entry.some(
          (reference) =>
            typeof reference !== "string" ||
            reference.trim() === "" ||
            !codeEvidenceIds.has(reference),
        )
      ) {
        return true;
      }
      continue;
    }
    if (hasUnknownEvidenceRefs(entry, codeEvidenceIds)) return true;
  }
  return false;
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

function stripUtf8Bom(value: string): string {
  return value.charCodeAt(0) === 0xfeff ? value.slice(1) : value;
}

async function repositoryCodeEvidenceGrounding(
  repository: string,
  value: unknown,
  findingLocations: readonly EvidenceLocation[],
  fileCache: Map<string, string[] | null>,
): Promise<boolean> {
  if (!Array.isArray(value) || value.length === 0) return false;

  let anchored = false;
  for (const evidence of value) {
    if (!isRecord(evidence)) return false;
    const path = draftEvidencePath(evidence);
    const startLine = draftEvidenceStartLine(evidence);
    const endLine = draftEvidenceEndLine(evidence, startLine);
    if (
      path === null ||
      startLine === null ||
      endLine === null ||
      endLine < startLine ||
      !hasSubstantiveValue(evidence["code"] ?? evidence["snippet"], 3) ||
      !hasSubstantiveValue(evidence["explanation"], 8)
    ) {
      return false;
    }

    let lines = fileCache.get(path);
    if (lines === undefined) {
      const bytes = await readBoundedRepositoryFile(repository, path);
      lines =
        bytes === null
          ? null
          : stripUtf8Bom(bytes.toString("utf8")).split(/\r?\n/u);
      fileCache.set(path, lines);
    }
    if (
      lines === null ||
      startLine > lines.length ||
      lines
        .slice(startLine - 1, Math.min(endLine, lines.length))
        .every((line) => line.trim() === "")
    ) {
      return false;
    }

    const primaryLocation = findingLocations[0];
    anchored ||=
      primaryLocation !== undefined &&
      evidenceLocationsOverlap({ path, startLine, endLine }, primaryLocation);
  }
  return anchored;
}

function draftEvidencePath(evidence: Record<string, unknown>): string | null {
  for (const key of ["path", "file", "filePath", "filename"]) {
    const candidate = evidence[key];
    if (typeof candidate !== "string") continue;
    const path = candidate.trim().replaceAll("\\", "/");
    return isSafeInventoryPath(path) ? path : null;
  }
  return null;
}

function draftEvidenceStartLine(
  evidence: Record<string, unknown>,
): number | null {
  return draftPositiveInteger(evidence, [
    "startLine",
    "start_line",
    "line",
    "lineNumber",
    "line_number",
  ]);
}

function draftEvidenceEndLine(
  evidence: Record<string, unknown>,
  startLine: number | null,
): number | null {
  return (
    draftPositiveInteger(evidence, [
      "endLine",
      "end_line",
      "endLineNumber",
      "end_line_number",
    ]) ?? startLine
  );
}

function canonicalDraftCodeEvidence(value: unknown): unknown {
  if (!Array.isArray(value)) return value;
  return value.map((entry) => {
    if (!isRecord(entry)) return entry;
    const path = draftEvidencePath(entry);
    const startLine = draftEvidenceStartLine(entry);
    const endLine = draftEvidenceEndLine(entry, startLine);
    return {
      ...entry,
      ...(path === null ? {} : { path }),
      ...(startLine === null ? {} : { startLine }),
      ...(endLine === null ? {} : { endLine }),
      ...(entry["code"] === undefined && entry["snippet"] !== undefined
        ? { code: entry["snippet"] }
        : {}),
    };
  });
}

function draftPositiveInteger(
  value: Record<string, unknown>,
  keys: readonly string[],
): number | null {
  for (const key of keys) {
    const candidate = value[key];
    if (Number.isSafeInteger(candidate) && Number(candidate) > 0) {
      return Number(candidate);
    }
  }
  return null;
}

function evidenceLocationsOverlap(
  left: EvidenceLocation,
  right: EvidenceLocation,
): boolean {
  const normalize = (path: string): string =>
    path.replaceAll("\\", "/").toLowerCase();
  if (normalize(left.path) !== normalize(right.path)) return false;
  const leftEnd = left.endLine ?? left.startLine;
  const rightEnd = right.endLine ?? right.startLine;
  const distance =
    left.startLine > rightEnd
      ? left.startLine - rightEnd
      : right.startLine > leftEnd
        ? right.startLine - leftEnd
        : 0;
  return distance === 0;
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
        ...(location["role"] === "source" || location["role"] === "sink"
          ? { role: location["role"] }
          : {}),
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
  const leftHasFixedUpdateBoundary =
    left.frameworkModel?.candidateControls.some(
      (control) => control.kind === "fixed-update-field-value-boundary",
    ) === true;
  const rightHasFixedUpdateBoundary =
    right.frameworkModel?.candidateControls.some(
      (control) => control.kind === "fixed-update-field-value-boundary",
    ) === true;
  return (
    right.priority - left.priority ||
    Number(leftHasFixedUpdateBoundary) - Number(rightHasFixedUpdateBoundary) ||
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
  deferredCount: number;
  mode: unknown;
} {
  if (coverageBytes === null) {
    return { readable: false, surfaces: [], deferredCount: 0, mode: undefined };
  }
  try {
    const coverage = JSON.parse(
      stripUtf8Bom(coverageBytes.toString("utf8")),
    ) as unknown;
    if (
      typeof coverage !== "object" ||
      coverage === null ||
      !Array.isArray((coverage as { surfaces?: unknown }).surfaces)
    ) {
      return {
        readable: false,
        surfaces: [],
        deferredCount: 0,
        mode: undefined,
      };
    }
    const deferred = (coverage as { deferred?: unknown }).deferred;
    return {
      readable: true,
      surfaces: (coverage as { surfaces: unknown[] }).surfaces.filter(
        (surface): surface is CoverageSurfaceDraft =>
          typeof surface === "object" && surface !== null,
      ),
      deferredCount: Array.isArray(deferred) ? deferred.length : 0,
      mode: (coverage as { mode?: unknown }).mode,
    };
  } catch {
    return { readable: false, surfaces: [], deferredCount: 0, mode: undefined };
  }
}

function compareCoverageGaps(
  left: CoverageGapRecord,
  right: CoverageGapRecord,
): number {
  const priority = {
    missing_coverage_surface: 0,
    missing_direct_file_review: 1,
    invalid_coverage_mode: 2,
    needs_follow_up: 3,
    deferred_coverage_item: 4,
    invalid_coverage_disposition: 5,
    conflicting_coverage_surfaces: 6,
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
    /^(?:Dockerfile|Gemfile|go\.mod|Jenkinsfile|Makefile|Rakefile)$/u.test(
      baseName,
    )
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
