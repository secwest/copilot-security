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
const MAX_FRAMEWORK_CROSS_FILE_RECORDS = 64;
const MAX_FRAMEWORK_MULTI_HOP_RECORDS = 64;
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
  ".csproj",
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
        kind: "single-path-component-validation",
        expression: /\.getFileName\s*\(\)|\.getNameCount\s*\(\)/iu,
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
    scope: "same-file" | "cross-file-wrapper" | "cross-file-multi-hop-wrapper";
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

interface ExportedDotnetMethod {
  ownerType: string;
  symbol: string;
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
  downstream: FrameworkWrapperSummary;
  controls: Array<{ kind: string; line: number }>;
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
  downstream: FrameworkWrapperSummary;
  controls: Array<{ kind: string; line: number }>;
}

type JavaFrameworkRelaySummary = DotnetFrameworkRelaySummary;

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
    const sources = JAVASCRIPT_EXTENSIONS.has(extension)
      ? matchingJavascriptModelLines(lines, model.sources, 16)
      : PYTHON_EXTENSIONS.has(extension)
        ? matchingPythonModelLines(lines, model.sources, 16)
        : extension === ".java" || extension === ".cs"
          ? matchingJavaModelLines(lines, model.sources, 16)
          : matchingModelLines(lines, model.sources, 16);
    const sinks = JAVASCRIPT_EXTENSIONS.has(extension)
      ? matchingJavascriptModelLines(
          lines,
          model.sinks,
          model.id === "node-http-ssrf" ? 64 : 8,
        )
      : PYTHON_EXTENSIONS.has(extension)
        ? matchingPythonModelLines(lines, model.sinks, 8)
        : extension === ".java" || extension === ".cs"
          ? matchingJavaModelLines(lines, model.sinks, 8)
          : matchingModelLines(lines, model.sinks, 8);
    if (sources.length === 0 || sinks.length === 0) continue;
    const controls = JAVASCRIPT_EXTENSIONS.has(extension)
      ? model.id === "node-http-ssrf"
        ? matchingJavascriptControlLines(lines, model.controls, 24)
        : matchingModelLines(lines, model.controls, 24)
      : PYTHON_EXTENSIONS.has(extension)
        ? matchingPythonModelLines(lines, model.controls, 24)
        : extension === ".java" || extension === ".cs"
          ? matchingJavaModelLines(lines, model.controls, 24)
          : matchingModelLines(lines, model.controls, 24);
    for (const sink of sinks) {
      const nodeHttpSink =
        model.id === "node-http-ssrf"
          ? nodeHttpUrlSink(lines, sink.line)
          : undefined;
      if (model.id === "node-http-ssrf" && nodeHttpSink === undefined) {
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
      const source =
        model.id === "node-http-ssrf" &&
        nodeHttpSink?.urlExpression !== undefined
          ? modeledCallSource(
              lines,
              sources,
              sink.line,
              nodeHttpSink.urlExpression,
              model.sources,
            )
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
        ...controls.filter(
          (control) =>
            control.line >= Math.min(source.line, sink.line) - 8 &&
            control.line <= Math.max(source.line, sink.line) + 8 &&
            nodeHttpGeneralControlApplies(nodeHttpSink, control.kind),
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
          schemaVersion: "1.2",
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
            const source = modeledJavaCallSource(
              caller.lines,
              callerMethod,
              call.line,
              argument,
              summary.model.sources,
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

function frameworkMultiHopDataflowRecords(
  files: readonly SourceFileSnapshot[],
): ResidualRiskRecord[] {
  const knownPaths = new Map(
    files.map((file) => [modelPathComparisonKey(file.path), file.path]),
  );
  const sinkSummaries = javascriptFrameworkWrapperSummaries(files);
  const relaySummaries = javascriptFrameworkRelaySummaries(
    files,
    sinkSummaries,
    knownPaths,
  );
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
          const sinkSummary = summary.downstream;
          const key = [
            summary.model.id,
            caller.path,
            call.line,
            summary.file.path,
            summary.downstreamCallLine,
            sinkSummary.file.path,
            sinkSummary.sink.line,
            summary.parameterIndex,
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
            ...summary.controls.map((control) => ({
              ...control,
              path: summary.file.path,
            })),
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
                {
                  kind: "wrapper-parameter",
                  path: summary.file.path,
                  line: summary.declarationLine,
                  symbol: summary.parameter,
                },
                {
                  kind: "relative-module-import",
                  path: summary.file.path,
                  line: summary.downstreamImport.line,
                  symbol: `${summary.downstreamImport.imported} as ${summary.downstreamImport.local}`,
                },
                {
                  kind: "wrapper-call-argument",
                  path: summary.file.path,
                  line: summary.downstreamCallLine,
                  symbol: `${summary.downstreamImport.local}[${sinkSummary.parameterIndex}]`,
                },
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
  const relaySummaries = pythonFrameworkRelaySummaries(
    files,
    sinkSummaries,
    knownPaths,
  );
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
          const sinkSummary = summary.downstream;
          const key = [
            summary.model.id,
            caller.path,
            call.line,
            summary.file.path,
            summary.downstreamCallLine,
            sinkSummary.file.path,
            sinkSummary.sink.line,
            summary.parameterIndex,
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
            ...summary.controls.map((control) => ({
              ...control,
              path: summary.file.path,
            })),
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
                {
                  kind: "wrapper-parameter",
                  path: summary.file.path,
                  line: summary.declarationLine,
                  symbol: summary.parameter,
                },
                {
                  kind: "relative-python-import",
                  path: summary.file.path,
                  line: summary.downstreamImport.line,
                  symbol: `${summary.downstreamImport.imported} as ${summary.downstreamImport.local}`,
                },
                {
                  kind: "wrapper-call-argument",
                  path: summary.file.path,
                  line: summary.downstreamCallLine,
                  symbol: `${summary.downstreamImport.local}[${sinkSummary.parameterIndex}]`,
                },
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

function frameworkJavaMultiHopDataflowRecords(
  files: readonly SourceFileSnapshot[],
): ResidualRiskRecord[] {
  const sinkSummaries = javaFrameworkWrapperSummaries(files);
  const ownerPaths = javaOwnerPaths(files);
  const relaySummaries = javaFrameworkRelaySummaries(
    files,
    sinkSummaries,
    ownerPaths,
  );
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
            if (call.arguments.length !== summary.parameterCount) continue;
            const argument = call.arguments[summary.parameterIndex];
            if (argument === undefined) continue;
            const source = modeledJavaCallSource(
              caller.lines,
              callerMethod,
              call.line,
              argument,
              summary.model.sources,
            );
            if (source === undefined) continue;
            const sinkSummary = summary.downstream;
            const recordKey = [
              summary.model.id,
              caller.path,
              call.line,
              summary.file.path,
              summary.downstreamCallLine,
              sinkSummary.file.path,
              sinkSummary.sink.line,
              summary.parameterIndex,
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
              ...summary.controls.map((control) => ({
                ...control,
                path: summary.file.path,
              })),
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
                  {
                    kind: "wrapper-parameter",
                    path: summary.file.path,
                    line: summary.declarationLine,
                    symbol: summary.parameter,
                  },
                  {
                    kind: "java-type-binding",
                    path: summary.file.path,
                    line:
                      summary.downstreamBinding.line ||
                      summary.downstreamCallLine,
                    symbol: `${summary.downstreamBinding.receiver}:${summary.downstreamBinding.ownerType}`,
                  },
                  {
                    kind: "wrapper-call-argument",
                    path: summary.file.path,
                    line: summary.downstreamCallLine,
                    symbol: `${summary.downstreamBinding.receiver}.${sinkSummary.symbol}[${sinkSummary.parameterIndex}]`,
                  },
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
  const relaySummaries = dotnetFrameworkRelaySummaries(
    files,
    sinkSummaries,
    ownerPaths,
  );
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
            if (call.arguments.length !== summary.parameterCount) continue;
            const argument = call.arguments[summary.parameterIndex];
            if (argument === undefined) continue;
            const source = modeledDotnetCallSource(
              caller.lines,
              callerMethod,
              call.line,
              argument,
              summary.model.sources,
            );
            if (source === undefined) continue;
            const sinkSummary = summary.downstream;
            const recordKey = [
              summary.model.id,
              caller.path,
              call.line,
              summary.file.path,
              summary.downstreamCallLine,
              sinkSummary.file.path,
              sinkSummary.sink.line,
              summary.parameterIndex,
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
              ...summary.controls.map((control) => ({
                ...control,
                path: summary.file.path,
              })),
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
                  {
                    kind: "wrapper-parameter",
                    path: summary.file.path,
                    line: summary.declarationLine,
                    symbol: summary.parameter,
                  },
                  {
                    kind: "dotnet-type-binding",
                    path: summary.file.path,
                    line:
                      summary.downstreamBinding.line ||
                      summary.downstreamCallLine,
                    symbol: `${summary.downstreamBinding.receiver}:${summary.downstreamBinding.ownerType}`,
                  },
                  {
                    kind: "wrapper-call-argument",
                    path: summary.file.path,
                    line: summary.downstreamCallLine,
                    symbol: `${summary.downstreamBinding.receiver}.${sinkSummary.symbol}[${sinkSummary.parameterIndex}]`,
                  },
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
  sinkSummaries: readonly FrameworkWrapperSummary[],
  ownerPaths: ReadonlyMap<string, ReadonlySet<string>>,
): JavaFrameworkRelaySummary[] {
  const summariesByOwnerAndMethod = new Map<
    string,
    FrameworkWrapperSummary[]
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
            if (downstream.file.path === file.path) continue;
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
  sinkSummaries: readonly FrameworkWrapperSummary[],
  ownerPaths: ReadonlyMap<string, ReadonlySet<string>>,
): DotnetFrameworkRelaySummary[] {
  const summariesByOwnerAndMethod = new Map<
    string,
    FrameworkWrapperSummary[]
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
            if (downstream.file.path === file.path) continue;
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
  sinkSummaries: readonly FrameworkWrapperSummary[],
  knownPaths: ReadonlyMap<string, string>,
): FrameworkRelaySummary[] {
  const summariesByFileAndSymbol = new Map<string, FrameworkWrapperSummary[]>();
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
  sinkSummaries: readonly FrameworkWrapperSummary[],
  knownPaths: ReadonlyMap<string, string>,
): FrameworkRelaySummary[] {
  const summariesByFileAndSymbol = new Map<string, FrameworkWrapperSummary[]>();
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
      const sinks = matchingJavascriptModelLines(file.lines, model.sinks, 32);
      const controls =
        model.id === "node-http-ssrf"
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
          if (model.id === "node-http-ssrf" && nodeHttpSink === undefined) {
            continue;
          }
          if (
            nodeHttpSink?.axiosReceiver !== undefined &&
            wrapper.parameters.includes(nodeHttpSink.axiosReceiver)
          ) {
            continue;
          }
          const sinkValue = nodeHttpSink?.urlExpression ?? sinkLine;
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
                control.line >= wrapper.startLine &&
                control.line <= wrapper.endLine &&
                nodeHttpGeneralControlApplies(nodeHttpSink, control.kind),
            ),
            ...(model.id === "node-http-ssrf" && nodeHttpSink !== undefined
              ? nodeAxiosConfigurationControls(
                  file.lines,
                  nodeHttpSink,
                  model.controls,
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
      const sinks = matchingPythonModelLines(file.lines, model.sinks, 32);
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
          const parameterIndexes = wrapper.parameters.flatMap(
            (parameter, parameterIndex) =>
              pythonLineReferencesIdentifier(sinkExpression, parameter)
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
            ...controls.filter(
              (control) =>
                control.line >= wrapper.startLine &&
                control.line <= wrapper.endLine,
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
      const controls = matchingJavaModelLines(file.lines, model.controls, 64);
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
          const parameterIndexes =
            model.id === "spring-http-path" || model.id === "spring-http-ssrf"
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
          const sinkControls = model.controls
            .filter((control) => control.expression.test(sinkExpression))
            .map((control) => ({ kind: control.kind, line: sink.line }));
          const methodControls = [
            ...sinkControls,
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
      const controls = matchingJavaModelLines(file.lines, model.controls, 64);
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
          const sinkControls = model.controls
            .filter((control) => control.expression.test(sinkExpression))
            .map((control) => ({ kind: control.kind, line: sink.line }));
          const methodControls = [
            ...sinkControls,
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
  const open = structural.indexOf("(");
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

function exportedPythonFunctions(
  lines: readonly string[],
): ExportedPythonFunction[] {
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

function javascriptCodeLinesWithoutComments(
  lines: readonly string[],
): string[] {
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
  return result;
}

function javascriptStructuralLines(lines: readonly string[]): string[] {
  return javascriptCodeLinesWithoutComments(lines).map((line) =>
    javascriptStructuralCode(line),
  );
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

function pythonStructuralLines(lines: readonly string[]): string[] {
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
    const line = lines[index] ?? "";
    const structuralLine = javascriptStructuralCode(line);
    const match = expression.exec(structuralLine);
    if (match === null) continue;
    const open = structuralLine.indexOf("(", match.index);
    const close = matchingCallParenthesis(structuralLine, open);
    if (open < 0 || close < 0) continue;
    calls.push({
      line: index + 1,
      arguments: splitJavascriptArguments(line.slice(open + 1, close)),
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
      !javaIdentifierReassignedBetween(
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

function modeledDotnetCallSource(
  lines: readonly string[],
  method: ExportedDotnetMethod,
  callLine: number,
  argument: string,
  sourcePatterns: readonly FrameworkModelPattern[],
): { kind: string; line: number } | undefined {
  const direct = sourcePatterns.find((pattern) =>
    pattern.expression.test(argument),
  );
  if (direct !== undefined) return { kind: direct.kind, line: callLine };
  if (!/^[A-Za-z_]\w*$/u.test(argument)) return undefined;
  for (const parameter of method.parameters) {
    if (parameter.name !== argument) continue;
    const source = sourcePatterns.find((pattern) =>
      pattern.expression.test(parameter.declaration),
    );
    if (source !== undefined) {
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
  );
}

interface NodeHttpUrlSink {
  urlExpression?: string;
  axiosReceiver?: string;
  axiosConfigurationLine?: number;
  axiosConfigurationEndLine?: number;
  callStartLine?: number;
  callEndLine?: number;
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
    `(?:\\b${escapedIdentifier}\\s*(?:[+*/%&|^?-]?=|\\+\\+|--)|(?:\\+\\+|--)\\s*${escapedIdentifier}\\b|\\b(?:const|let|var)\\s+${escapedIdentifier}\\b)`,
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
