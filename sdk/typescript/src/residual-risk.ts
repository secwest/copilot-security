import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { extname, isAbsolute, join, posix, relative, resolve } from "node:path";
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
const MAX_FRAMEWORK_WRAPPER_SUMMARIES = 64;
const MAX_FRAMEWORK_CROSS_FILE_RECORDS = 64;
const MAX_WRAPPER_FUNCTION_LINES = 160;
const MAX_WRAPPER_CALL_DISTANCE = 12;
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
  sourceExcerpt?: string;
  frameworkModel?: {
    schemaVersion: "1.1";
    id: string;
    language: string;
    scope: "same-file" | "cross-file-wrapper";
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

interface FrameworkWrapperSummary {
  model: FrameworkDataflowModel;
  file: SourceFileSnapshot;
  symbol: string;
  parameter: string;
  parameterIndex: number;
  declarationLine: number;
  sink: { kind: string; line: number; cweIds: readonly string[] };
  controls: Array<{ kind: string; line: number }>;
}

interface ImportedJavascriptSymbol {
  imported: string;
  local: string;
  moduleSpecifier: string;
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
    records.push(...frameworkDataflowRecords(normalizedPath, lines));
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

  records.push(...frameworkCrossFileDataflowRecords(sourceFiles));

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
): ResidualRiskRecord[] {
  const extension = extname(path).toLowerCase();
  const text = lines.join("\n");
  const records: ResidualRiskRecord[] = [];
  for (const model of FRAMEWORK_DATAFLOW_MODELS) {
    if (
      !model.extensions.has(extension) ||
      !model.activation.some((expression) => expression.test(text))
    ) {
      continue;
    }
    const sources = matchingModelLines(lines, model.sources, 16);
    const sinks = matchingModelLines(lines, model.sinks, 8);
    if (sources.length === 0 || sinks.length === 0) continue;
    const controls = matchingModelLines(lines, model.controls, 24);
    for (const sink of sinks) {
      const source = nearestModeledSource(sources, sink.line);
      const nearbyControls = controls
        .filter(
          (control) =>
            control.line >= Math.min(source.line, sink.line) - 8 &&
            control.line <= Math.max(source.line, sink.line) + 8,
        )
        .slice(0, 8);
      const sinkPattern = model.sinks.find(
        (pattern) => pattern.kind === sink.kind,
      );
      if (sinkPattern === undefined) continue;
      const startLine = Math.max(1, sink.line - CONTEXT_LINES_BEFORE);
      const endLine = Math.min(lines.length, sink.line + CONTEXT_LINES_AFTER);
      const sourceStart = Math.max(1, source.line - 2);
      const sourceEnd = Math.min(lines.length, source.line + 2);
      records.push({
        path,
        line: sink.line,
        categories: [
          `framework-dataflow:${model.id}`,
          `modeled-source:${source.kind}`,
          `modeled-sink:${sink.kind}`,
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
          schemaVersion: "1.1",
          id: model.id,
          language: model.language,
          scope: "same-file",
          source: { kind: source.kind, path, line: source.line },
          sink: {
            kind: sink.kind,
            path,
            line: sink.line,
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

function frameworkCrossFileDataflowRecords(
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
        const sources = matchingModelLines(
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
              schemaVersion: "1.1",
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
      const sinks = matchingModelLines(file.lines, model.sinks, 32);
      const controls = matchingModelLines(file.lines, model.controls, 64);
      for (const wrapper of exportedFunctions) {
        for (const sink of sinks) {
          if (sink.line < wrapper.startLine || sink.line > wrapper.endLine) {
            continue;
          }
          const sinkLine = javascriptCodeBeforeComment(
            file.lines[sink.line - 1] ?? "",
          );
          const parameterIndexes = wrapper.parameters.flatMap(
            (parameter, parameterIndex) =>
              lineReferencesIdentifier(sinkLine, parameter)
                ? [parameterIndex]
                : [],
          );
          if (parameterIndexes.length === 0) continue;
          const sinkPattern = model.sinks.find(
            (pattern) => pattern.kind === sink.kind,
          );
          if (sinkPattern === undefined) continue;
          for (const parameterIndex of parameterIndexes) {
            summaries.push({
              model,
              file,
              symbol: wrapper.symbol,
              parameter: wrapper.parameters[parameterIndex]!,
              parameterIndex,
              declarationLine: wrapper.startLine,
              sink: { ...sink, cweIds: sinkPattern.cweIds },
              controls: controls
                .filter(
                  (control) =>
                    control.line >= wrapper.startLine &&
                    control.line <= wrapper.endLine,
                )
                .slice(0, 8),
            });
            if (summaries.length >= MAX_FRAMEWORK_WRAPPER_SUMMARIES) {
              return summaries;
            }
          }
        }
      }
    }
  }
  return summaries;
}

function exportedJavascriptFunctions(
  lines: readonly string[],
): ExportedJavascriptFunction[] {
  const functions: ExportedJavascriptFunction[] = [];
  const patterns = [
    /^\s*export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/u,
    /^\s*export\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/u,
    /^\s*(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\s*\(([^)]*)\)/u,
    /^\s*export\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?([A-Za-z_$][\w$]*)\s*=>/u,
  ];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const match = patterns
      .map((pattern) => pattern.exec(line))
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
    const line = lines[index] ?? "";
    const match = expression.exec(line);
    if (match === null) continue;
    const open = line.indexOf("(", match.index);
    const close = matchingCallParenthesis(line, open);
    if (open < 0 || close < 0) continue;
    calls.push({
      line: index + 1,
      arguments: splitJavascriptArguments(line.slice(open + 1, close)),
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
    const escapedArgument = escapeRegularExpression(argument);
    const reassignment = new RegExp(
      `(?:\\b${escapedArgument}\\s*(?:[+*/%&|^?-]?=|\\+\\+|--)|(?:\\+\\+|--)\\s*${escapedArgument}\\b|\\b(?:const|let|var)\\s+${escapedArgument}\\b)`,
      "u",
    );
    const reassigned = lines
      .slice(line, callLine - 1)
      .some((candidate) => reassignment.test(candidate));
    if (!reassigned) return source;
  }
  return undefined;
}

function lineReferencesIdentifier(line: string, identifier: string): boolean {
  return new RegExp(`\\b${escapeRegularExpression(identifier)}\\b`, "u").test(
    line,
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
    const codeEvidenceIds = findingCodeEvidenceIds(finding["codeEvidence"]);
    if (!isSubstantiveValidation(finding["validation"])) {
      reasons.push("missing_or_weak_validation");
    }
    reasons.push(...validationClosureGaps(finding["validation"]));
    if (!isSubstantiveAttackPath(finding["attackPath"])) {
      reasons.push("missing_or_weak_attack_path");
    }
    reasons.push(...attackPathClosureGaps(finding["attackPath"]));
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
  if (!hasNamedSubstantiveValue(value, ["evidenceRefs", "evidence_refs"], 3)) {
    gaps.push("missing_attack_path_evidence_refs");
  }
  return gaps;
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
    if (!isRecord(section) || section["evidenceRefs"] === undefined) continue;
    const refs = section["evidenceRefs"];
    if (
      !Array.isArray(refs) ||
      refs.some(
        (reference) =>
          typeof reference !== "string" ||
          reference.trim() === "" ||
          !codeEvidenceIds.has(reference),
      )
    ) {
      return true;
    }
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
