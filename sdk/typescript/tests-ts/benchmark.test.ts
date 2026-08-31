import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { afterEach, describe, expect, test } from "bun:test";
import { evaluateBenchmark } from "../src/benchmark.js";
import {
  benchmarkFindingsPaths,
  buildBenchmarkSelection,
  selectBenchmarkCases,
} from "../src/benchmark-selection.js";

const roots: string[] = [];

async function containsFixtureSourceFile(
  directory: string,
  depth = 0,
): Promise<boolean> {
  if (depth > 8) return false;
  const entries = await readdir(directory, { withFileTypes: true });
  if (entries.some((entry) => entry.isFile())) return true;
  for (const entry of entries) {
    if (
      entry.isDirectory() &&
      (await containsFixtureSourceFile(join(directory, entry.name), depth + 1))
    ) {
      return true;
    }
  }
  return false;
}

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
            lineTolerance?: number;
          }>;
        }>;
      }>;
    };
    const pairs = [
      ["javascript-command-injection", "javascript-safe-command"],
      ["python-path-traversal", "python-safe-path"],
      [
        "javascript-archive-link-pivot",
        "javascript-safe-archive-link-isolation",
      ],
      ["javascript-decompression-bomb", "javascript-safe-decompression-limits"],
      ["javascript-aes-gcm-nonce-reuse", "javascript-safe-aes-gcm-nonces"],
      ["javascript-executable-file-upload", "javascript-safe-profile-upload"],
      ["javascript-http-request-smuggling", "javascript-safe-http-framing"],
      [
        "javascript-duplicate-parameter-authorization-bypass",
        "javascript-safe-canonical-query-authorization",
      ],
      ["javascript-idor", "javascript-safe-authorization"],
      ["javascript-sql-injection", "javascript-safe-sql"],
      ["javascript-nosql-auth-bypass", "javascript-safe-nosql-login"],
      ["javascript-ssrf", "javascript-safe-fetch"],
      ["javascript-dns-rebinding-ssrf", "javascript-safe-pinned-dns-fetch"],
      ["python-unsafe-deserialization", "python-safe-json"],
      ["python-numpy-allow-pickle", "python-numpy-no-pickle-control"],
      ["python-joblib-unsafe-load", "python-joblib-json-control"],
      ["python-torch-unsafe-load", "python-torch-weights-only-control"],
      ["python-pickle-unsafe-load", "python-pickle-json-control"],
      [
        "python-pickle-unpickler-unsafe-load",
        "python-pickle-unpickler-json-control",
      ],
      ["python-pyyaml-unsafe-load", "python-pyyaml-safe-load"],
      ["javascript-reflected-xss", "javascript-safe-html"],
      [
        "javascript-credentialed-cors-exfiltration",
        "javascript-safe-cors-allowlist",
      ],
      [
        "javascript-cross-site-websocket-hijacking",
        "javascript-safe-websocket-origin",
      ],
      ["javascript-web-cache-deception", "javascript-safe-private-cache"],
      [
        "javascript-tenant-cache-key-confusion",
        "javascript-safe-tenant-cache-isolation",
      ],
      [
        "javascript-http-response-splitting",
        "javascript-safe-http-response-headers",
      ],
      [
        "javascript-graphql-recovery-amplification",
        "javascript-safe-graphql-recovery-limits",
      ],
      [
        "javascript-forwarded-client-rate-limit-bypass",
        "javascript-safe-forwarded-client-budget",
      ],
      ["javascript-jwt-bypass", "javascript-safe-jwt"],
      [
        "javascript-jwt-algorithm-confusion",
        "javascript-safe-jwt-algorithm-binding",
      ],
      [
        "javascript-jwks-header-key-injection",
        "javascript-safe-jwks-key-origin",
      ],
      [
        "javascript-oidc-id-token-misbinding",
        "javascript-safe-oidc-id-token-binding",
      ],
      [
        "javascript-webauthn-account-misbinding",
        "javascript-safe-webauthn-account-binding",
      ],
      ["javascript-signed-webhook-replay", "javascript-safe-signed-webhook"],
      [
        "javascript-ecdsa-signature-malleability-replay",
        "javascript-safe-ecdsa-event-idempotency",
      ],
      [
        "javascript-saml-signature-wrapping",
        "javascript-safe-saml-assertion-binding",
      ],
      ["python-xxe", "python-safe-xml"],
      ["python-lxml-iterparse-xxe", "python-lxml-iterparse-patched-control"],
      ["python-lxml-etcompat-xxe", "python-lxml-etcompat-patched-control"],
      [
        "python-tarfile-unsafe-extraction",
        "python-tarfile-data-filter-control",
      ],
      ["python-hydra-unsafe-instantiate", "python-hydra-blocklist-control"],
      [
        "python-statemachine-unsafe-scxml-eval",
        "python-statemachine-restricted-evaluator-control",
      ],
      [
        "python-datamodel-codegen-import-injection",
        "python-datamodel-codegen-validated-import-control",
      ],
      [
        "python-sympy-unsafe-parse-expr",
        "python-sympy-restricted-namespace-control",
      ],
      ["javascript-prototype-pollution", "javascript-safe-preferences"],
      [
        "node-multi-hop-prototype-pollution",
        "node-multi-hop-safe-prototype-map",
      ],
      [
        "node-multi-hop-object-assign-prototype-pollution",
        "node-multi-hop-null-prototype-assign",
      ],
      [
        "node-multi-hop-lodash-merge-prototype-pollution",
        "node-multi-hop-patched-lodash-merge",
      ],
      [
        "node-multi-hop-locked-lodash-merge-prototype-pollution",
        "node-multi-hop-locked-patched-lodash-merge",
      ],
      [
        "node-multi-hop-lodash-merge-package-prototype-pollution",
        "node-multi-hop-patched-lodash-merge-package",
      ],
      [
        "node-multi-hop-merge-deep-prototype-pollution",
        "node-multi-hop-patched-merge-deep",
      ],
      [
        "node-multi-hop-extend-deep-prototype-pollution",
        "node-multi-hop-patched-extend-deep",
      ],
      [
        "node-multi-hop-deep-extend-prototype-pollution",
        "node-multi-hop-patched-deep-extend",
      ],
      [
        "node-multi-hop-just-extend-prototype-pollution",
        "node-multi-hop-patched-just-extend",
      ],
      [
        "node-multi-hop-merge-options-prototype-pollution",
        "node-multi-hop-patched-merge-options",
      ],
      [
        "node-multi-hop-node-extend-prototype-pollution",
        "node-multi-hop-patched-node-extend",
      ],
      [
        "node-multi-hop-assign-deep-prototype-pollution",
        "node-multi-hop-patched-assign-deep",
      ],
      [
        "node-multi-hop-mixin-deep-prototype-pollution",
        "node-multi-hop-patched-mixin-deep",
      ],
      [
        "node-multi-hop-merge-recursive-prototype-pollution",
        "node-multi-hop-patched-merge-recursive",
      ],
      [
        "node-multi-hop-js-toml-prototype-pollution",
        "node-multi-hop-patched-js-toml",
      ],
      [
        "node-multi-hop-jsonpath-plus-rce",
        "node-multi-hop-patched-jsonpath-plus",
      ],
      [
        "node-multi-hop-flat-unflatten-prototype-pollution",
        "node-multi-hop-patched-flat-unflatten",
      ],
      [
        "node-multi-hop-dset-prototype-pollution",
        "node-multi-hop-patched-dset",
      ],
      [
        "node-multi-hop-object-path-prototype-pollution",
        "node-multi-hop-patched-object-path",
      ],
      [
        "node-multi-hop-lodash-unset-prototype-deletion",
        "node-multi-hop-patched-lodash-unset",
      ],
      [
        "node-multi-hop-immutable-prototype-replacement",
        "node-multi-hop-patched-immutable",
      ],
      [
        "node-multi-hop-axios-prototype-gadget-chain",
        "node-multi-hop-patched-axios-prototype-gadget-chain",
      ],
      ["node-multi-hop-tmp-path-traversal", "node-multi-hop-patched-tmp"],
      [
        "node-multi-hop-nodemailer-raw-access",
        "node-multi-hop-patched-nodemailer-raw-access",
      ],
      [
        "node-multi-hop-brace-expansion-dos",
        "node-multi-hop-patched-brace-expansion",
      ],
      [
        "node-multi-hop-socketio-parser-dos",
        "node-multi-hop-patched-socketio-parser",
      ],
      [
        "node-socketio-server-transitive-parser-dos",
        "node-socketio-server-transitive-patched-parser",
      ],
      ["node-multi-hop-nanoid-size-dos", "node-multi-hop-patched-nanoid-size"],
      [
        "node-opcua-server-unbounded-nonce-cache",
        "node-opcua-server-bounded-nonce-cache",
      ],
      [
        "node-opcua-server-replayable-username-token",
        "node-opcua-server-nonce-bound-username-token",
      ],
      [
        "node-authjs-configuration-error-fail-open",
        "node-authjs-configuration-error-fail-closed",
      ],
      [
        "node-multi-hop-jsonata-expression-rce",
        "node-multi-hop-patched-jsonata-expression",
      ],
      [
        "node-multi-hop-liquidjs-template-rce",
        "node-multi-hop-repaired-liquidjs-template",
      ],
      [
        "node-multi-hop-prompty-nunjucks-template-rce",
        "node-multi-hop-patched-prompty-nunjucks-template",
      ],
      [
        "node-multi-hop-kysely-mysql-ddl-sql-injection",
        "node-multi-hop-patched-kysely-mysql-ddl-literal",
      ],
      [
        "node-multi-hop-urllib-cross-origin-credential-leak",
        "node-multi-hop-patched-urllib-cross-origin-credential",
      ],
      [
        "node-multi-hop-shescape-cmd-injection",
        "node-multi-hop-repaired-shescape-cmd",
      ],
      [
        "node-multi-hop-velocity-template-rce",
        "node-multi-hop-repaired-velocity-template",
      ],
      [
        "node-multi-hop-vm2-sandbox-escape",
        "node-multi-hop-repaired-vm2-sandbox",
      ],
      [
        "node-multi-hop-postcss-source-map-traversal",
        "node-multi-hop-patched-postcss",
      ],
      [
        "node-multi-hop-extract-zip-symlink-traversal",
        "node-multi-hop-safe-extract-zip",
      ],
      [
        "node-fastify-static-route-guard-bypass",
        "node-patched-fastify-static-route-guard",
      ],
      [
        "node-multi-hop-tar-linkpath-traversal",
        "node-multi-hop-patched-tar-linkpath",
      ],
      [
        "node-multi-hop-decompress-archive-escape",
        "node-multi-hop-repaired-decompress-archive",
      ],
      [
        "node-multi-hop-sequelize-oracle-sql-injection",
        "node-multi-hop-repaired-sequelize-oracle-query",
      ],
      [
        "node-multi-hop-shell-quote-object-token-command-injection",
        "node-multi-hop-repaired-shell-quote-object-token",
      ],
      [
        "node-multi-hop-tar-member-selection-recursion",
        "node-multi-hop-patched-tar-member-selection",
      ],
      [
        "node-multi-hop-tar-decompression-dos",
        "node-multi-hop-patched-tar-decompression",
      ],
      [
        "node-keystone-negative-take-max-take-bypass",
        "node-keystone-patched-negative-take-max-take",
      ],
      [
        "node-multi-hop-js-yaml-exponential-dos",
        "node-multi-hop-patched-js-yaml-flow-parser",
      ],
      [
        "node-multi-hop-js-yaml-omap-dos",
        "node-multi-hop-patched-js-yaml-omap",
      ],
      [
        "node-multi-hop-ip-address-leading-zero-ssrf",
        "node-multi-hop-patched-ip-address-leading-zero",
      ],
      [
        "node-multi-hop-fast-uri-authority-ssrf",
        "node-multi-hop-patched-fast-uri-authority",
      ],
      [
        "node-multi-hop-fast-uri-encoded-dot-path",
        "node-multi-hop-patched-fast-uri-encoded-dot-path",
      ],
      ["python-disabled-tls-verification", "python-safe-tls"],
      ["javascript-predictable-reset-token", "javascript-secure-reset-token"],
      ["python-ssti", "python-safe-template"],
      ["python-payout-toctou", "python-atomic-payout"],
      ["javascript-mass-assignment", "javascript-safe-account-update"],
      ["javascript-csrf-recovery-email", "javascript-safe-csrf-recovery-email"],
      ["c-packet-length-overflow", "c-bounded-packet-copy"],
      ["c-async-audit-use-after-free", "c-safe-async-audit-lifetime"],
      ["c-format-string-secret-disclosure", "c-safe-literal-format-audit"],
      [
        "javascript-ldap-filter-authorization",
        "javascript-safe-ldap-authorization",
      ],
      [
        "javascript-xpath-authentication-injection",
        "javascript-safe-xpath-authentication",
      ],
      [
        "javascript-oauth-account-linking-csrf",
        "javascript-safe-oauth-account-linking",
      ],
      ["javascript-session-fixation", "javascript-safe-session-rotation"],
      [
        "javascript-password-reset-host-poisoning",
        "javascript-safe-password-reset-origin",
      ],
      [
        "javascript-fail-open-policy-authorization",
        "javascript-safe-fail-closed-policy-authorization",
      ],
      [
        "javascript-redos-alias-validation",
        "javascript-safe-linear-alias-validation",
      ],
      [
        "kubernetes-privileged-sensitive-hostpath",
        "kubernetes-safe-isolated-volume",
      ],
      [
        "kubernetes-cluster-admin-broad-subject",
        "kubernetes-cluster-admin-specific-group",
      ],
      [
        "cloudformation-public-admin-role",
        "cloudformation-specific-admin-role",
      ],
      [
        "terraform-aws-public-admin-ingress",
        "terraform-aws-restricted-admin-ingress",
      ],
      ["php-pdo-tainted-prepared-sql-injection", "php-pdo-parameterized-query"],
      ["ruby-rails-open3-shell-injection", "ruby-rails-open3-argv-command"],
      ["rust-axum-shell-command-injection", "rust-axum-argv-command"],
      ["kotlin-ktor-shell-command-injection", "kotlin-ktor-argv-command"],
      [
        "kotlin-ktor-resource-shell-command-injection",
        "kotlin-ktor-resource-argv-command",
      ],
      [
        "kotlin-ktor-resource-live-command-list-injection",
        "kotlin-ktor-resource-live-command-list-argv",
      ],
      [
        "kotlin-ktor-resource-inline-pipeline-injection",
        "kotlin-ktor-resource-inline-pipeline-argv",
      ],
      [
        "kotlin-ktor-resource-builder-factory-injection",
        "kotlin-ktor-resource-builder-factory-argv",
      ],
      [
        "kotlin-ktor-resource-command-helper-injection",
        "kotlin-ktor-resource-command-helper-argv",
      ],
      [
        "kotlin-ktor-resource-env-executable-injection",
        "kotlin-ktor-resource-env-argv",
      ],
      [
        "kotlin-ktor-resource-runtime-env-executable-injection",
        "kotlin-ktor-resource-runtime-env-argv",
      ],
      [
        "kotlin-ktor-resource-runtime-list-env-executable-injection",
        "kotlin-ktor-resource-runtime-list-env-argv",
      ],
      [
        "node-multi-hop-rhinostone-swig-template-traversal",
        "node-multi-hop-repaired-rhinostone-swig-template-root",
      ],
      [
        "node-multi-hop-intlify-flat-json-prototype-pollution",
        "node-multi-hop-repaired-intlify-flat-json-prototype-guard",
      ],
      [
        "node-deepseek-mcp-http-cross-session-bypass",
        "node-deepseek-mcp-http-session-isolated",
      ],
      [
        "node-nextjs-dynamic-route-param-authorization-bypass",
        "node-nextjs-dynamic-route-param-isolated",
      ],
      [
        "node-plate-media-embed-metadata-xss",
        "node-plate-media-embed-metadata-isolated",
      ],
      [
        "node-defuddle-extractor-html-xss",
        "node-defuddle-extractor-html-isolated",
      ],
      [
        "node-pickem-terminal-control-injection",
        "node-pickem-terminal-control-isolated",
      ],
      [
        "node-logtape-syslog-structured-data-injection",
        "node-logtape-syslog-structured-data-escaped",
      ],
      [
        "node-suneditor-embed-external-script-xss",
        "node-suneditor-embed-external-script-blocked",
      ],
      [
        "node-contentful-mcp-management-token-host-redirect",
        "node-contentful-mcp-management-token-host-pinned",
      ],
      ["node-mcp-v2-command-injection", "node-mcp-v2-command-argv"],
      ["node-mcp-v2-argument-injection", "node-mcp-v2-argument-data"],
      ["node-mcp-v2-code-injection", "node-mcp-v2-arithmetic-parser"],
      [
        "node-mcp-v2-function-constructor",
        "node-mcp-v2-function-fixed-grammar",
      ],
      ["node-mcp-v2-worker-eval-injection", "node-mcp-v2-worker-data-boundary"],
      [
        "node-mcp-v2-sqlite-sql-injection",
        "node-mcp-v2-sqlite-bound-parameters",
      ],
      [
        "node-mcp-v2-sqlite-prepared-sql-injection",
        "node-mcp-v2-sqlite-prepared-bound-parameters",
      ],
      ["node-mcp-v2-regex-injection", "node-mcp-v2-fixed-patterns"],
      ["node-mcp-v2-ssrf", "node-mcp-v2-fixed-destination"],
      ["node-mcp-v2-path-traversal", "node-mcp-v2-fixed-file"],
      [
        "node-mcp-v2-runtime-alias-argument-injection",
        "node-mcp-v2-runtime-alias-argument-data",
      ],
      [
        "node-mcp-v2-imported-runtime-argument-injection",
        "node-mcp-v2-imported-runtime-argument-data",
      ],
      [
        "node-mcp-v2-fork-exec-argv-injection",
        "node-mcp-v2-fork-argument-data",
      ],
      [
        "node-mcp-v2-fork-module-path-injection",
        "node-mcp-v2-fork-fixed-module",
      ],
      [
        "node-mcp-v2-fork-exec-path-selection",
        "node-mcp-v2-fork-fixed-executable",
      ],
      [
        "node-mcp-v2-fork-relative-cwd-module-hijack",
        "node-mcp-v2-fork-absolute-module",
      ],
      [
        "node-mcp-v2-fork-node-options-injection",
        "node-mcp-v2-fork-environment-data",
      ],
      ["node-mcp-v2-node-options-injection", "node-mcp-v2-node-options-data"],
      [
        "node-mcp-v2-executable-search-path",
        "node-mcp-v2-fixed-executable-search",
      ],
      [
        "node-sails-action2-path-traversal",
        "node-sails-action2-fixed-thumbnail",
      ],
      [
        "node-sails-action2-wrapper-path-traversal",
        "node-sails-action2-wrapper-fixed-thumbnail",
      ],
      [
        "python-asyncssh-scp-download-path-traversal",
        "python-asyncssh-scp-repaired-control",
      ],
      [
        "python-chainlit-mcp-stdio-command-injection",
        "python-chainlit-mcp-stdio-repaired-control",
      ],
      [
        "javascript-trojan-source-authorization-bypass",
        "javascript-bidi-natural-language-control",
      ],
      [
        "node-nx-self-hosted-cache-archive-escape",
        "node-nx-self-hosted-cache-archive-contained",
      ],
      [
        "node-undici-socks5-cross-origin-routing",
        "node-undici-socks5-per-origin-pools",
      ],
      [
        "go-echo-static-encoded-separator-bypass",
        "go-echo-static-encoded-separator-repaired",
      ],
      [
        "traefik-replacepathregex-auth-bypass",
        "traefik-replacepathregex-repaired",
      ],
      [
        "traefik-docker-label-replacepathregex-auth-bypass",
        "traefik-docker-label-replacepathregex-repaired",
      ],
      [
        "traefik-directory-toml-replacepathregex-auth-bypass",
        "traefik-directory-toml-replacepathregex-repaired",
      ],
      [
        "spring-java-fluent-process-builder-injection",
        "spring-java-fluent-process-builder-argv",
      ],
      [
        "spring-java-live-command-list-injection",
        "spring-java-live-command-list-argv",
      ],
      [
        "spring-java-caller-command-list-injection",
        "spring-java-caller-command-list-argv",
      ],
      [
        "spring-java-collections-addall-injection",
        "spring-java-collections-addall-argv",
      ],
      [
        "spring-java-collections-copy-injection",
        "spring-java-collections-copy-argv",
      ],
      [
        "javascript-adversarial-command-injection",
        "javascript-adversarial-safe-command",
      ],
      [
        "java-r2dbc-databaseclient-sql-injection",
        "java-r2dbc-databaseclient-bound-parameter",
      ],
      [
        "java-r2dbc-spi-statement-sql-injection",
        "java-r2dbc-spi-statement-bound-parameter",
      ],
      ["python-asyncpg-sql-injection", "python-asyncpg-bound-parameter"],
      [
        "python-asyncpg-unicode-source-sql-injection",
        "python-asyncpg-unicode-source-bound-parameter",
      ],
      [
        "python-cross-file-list-iadd-command-injection",
        "python-cross-file-list-iadd-safe-command",
      ],
      [
        "python-cross-file-dict-update-command-injection",
        "python-cross-file-dict-update-safe-command",
      ],
      [
        "python-cross-file-object-field-command-injection",
        "python-cross-file-object-field-safe-command",
      ],
      [
        "python-cross-file-dataclass-field-command-injection",
        "python-cross-file-dataclass-field-safe-command",
      ],
      [
        "python-fastapi-pydantic-body-command-injection",
        "python-fastapi-pydantic-body-safe-command",
      ],
      [
        "python-fastapi-annotated-pydantic-body-command-injection",
        "python-fastapi-annotated-pydantic-body-safe-command",
      ],
      [
        "python-fastapi-embedded-pydantic-body-command-injection",
        "python-fastapi-embedded-pydantic-body-safe-command",
      ],
      ["python-fastapi-open-redirect", "python-fastapi-safe-local-redirect"],
      [
        "python-fastapi-response-class-open-redirect",
        "python-fastapi-response-class-safe-local-redirect",
      ],
      ["python-flask-open-redirect", "python-flask-safe-local-redirect"],
      [
        "python-flask-blueprint-open-redirect",
        "python-flask-blueprint-safe-local-redirect",
      ],
      [
        "python-flask-post-open-redirect",
        "python-flask-post-safe-local-redirect",
      ],
      ["python-django-open-redirect", "python-django-safe-local-redirect"],
      [
        "python-django-class-view-open-redirect",
        "python-django-class-view-safe-local-redirect",
      ],
      [
        "python-django-post-class-view-open-redirect",
        "python-django-post-class-view-safe-local-redirect",
      ],
      [
        "rust-axum-tokio-shell-command-injection",
        "rust-axum-tokio-argv-command",
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
        .get("c-format-string-secret-disclosure")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-134"]]);
    expect(
      cases
        .get("python-datamodel-codegen-import-injection")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-94", "CWE-95"]]);
    expect(
      cases
        .get("node-multi-hop-prompty-nunjucks-template-rce")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-94", "CWE-1336"]]);
    expect(
      cases
        .get("node-multi-hop-kysely-mysql-ddl-sql-injection")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-89"]]);
    expect(
      cases
        .get("node-multi-hop-urllib-cross-origin-credential-leak")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-201", "CWE-522"]]);
    expect(
      cases
        .get("javascript-archive-link-pivot")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([
      ["CWE-59", "CWE-22"],
      ["CWE-59", "CWE-22"],
    ]);
    expect(
      cases
        .get("javascript-archive-link-pivot")
        ?.expected.flatMap((expectation) => expectation.locations),
    ).toEqual([
      {
        path: "src/extractor.js",
        startLine: 12,
        endLine: 14,
        lineTolerance: 2,
      },
      {
        path: "src/extractor.js",
        startLine: 17,
        endLine: 19,
        lineTolerance: 2,
      },
    ]);
    expect(
      cases
        .get("javascript-decompression-bomb")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-409", "CWE-400"]]);
    expect(
      cases
        .get("javascript-decompression-bomb")
        ?.expected.flatMap((expectation) => expectation.locations),
    ).toEqual([
      {
        path: "src/importer.js",
        startLine: 11,
        endLine: 12,
        lineTolerance: 2,
      },
    ]);
    expect(
      cases
        .get("javascript-aes-gcm-nonce-reuse")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-323"]]);
    expect(
      cases
        .get("javascript-aes-gcm-nonce-reuse")
        ?.expected.flatMap((expectation) => expectation.locations),
    ).toEqual([
      {
        path: "src/profiles.js",
        startLine: 4,
        endLine: 17,
        lineTolerance: 2,
      },
    ]);
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
        .get("javascript-oauth-account-linking-csrf")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-352", "CWE-287"]]);
    expect(
      cases
        .get("javascript-oauth-account-linking-csrf")
        ?.expected.flatMap((expectation) => expectation.locations),
    ).toEqual([
      {
        path: "src/linking.js",
        startLine: 27,
        endLine: 31,
        lineTolerance: 3,
      },
    ]);
    expect(
      cases
        .get("javascript-session-fixation")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-384"]]);
    expect(
      cases
        .get("javascript-session-fixation")
        ?.expected.flatMap((expectation) => expectation.locations),
    ).toEqual([
      {
        path: "src/login.js",
        startLine: 25,
        endLine: 30,
        lineTolerance: 3,
      },
    ]);
    expect(
      cases
        .get("javascript-credentialed-cors-exfiltration")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-942", "CWE-200"]]);
    expect(
      cases
        .get("javascript-credentialed-cors-exfiltration")
        ?.expected.flatMap((expectation) => expectation.locations),
    ).toEqual([
      {
        path: "src/cors.js",
        startLine: 2,
        endLine: 5,
        lineTolerance: 3,
      },
    ]);
    expect(
      cases
        .get("javascript-cross-site-websocket-hijacking")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-346", "CWE-352", "CWE-200"]]);
    expect(
      cases
        .get("javascript-cross-site-websocket-hijacking")
        ?.expected.flatMap((expectation) => expectation.locations),
    ).toEqual([
      {
        path: "src/websocket-route.js",
        startLine: 1,
        endLine: 3,
        lineTolerance: 3,
      },
    ]);
    expect(
      cases
        .get("javascript-web-cache-deception")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-524", "CWE-200"]]);
    expect(
      cases
        .get("javascript-web-cache-deception")
        ?.expected.flatMap((expectation) => expectation.locations),
    ).toEqual([
      {
        path: "src/edge-cache.js",
        startLine: 10,
        endLine: 13,
        lineTolerance: 3,
      },
      {
        path: "src/origin.js",
        startLine: 10,
        endLine: 19,
        lineTolerance: 3,
      },
    ]);
    expect(
      cases
        .get("javascript-tenant-cache-key-confusion")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-524", "CWE-862"]]);
    expect(
      cases
        .get("javascript-tenant-cache-key-confusion")
        ?.expected.flatMap((expectation) => expectation.locations),
    ).toEqual([
      {
        path: "src/invoices.js",
        startLine: 52,
        endLine: 62,
        lineTolerance: 3,
      },
    ]);
    expect(
      cases
        .get("javascript-http-response-splitting")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-113", "CWE-200"]]);
    expect(
      cases
        .get("javascript-http-response-splitting")
        ?.expected.flatMap((expectation) => expectation.locations),
    ).toEqual([
      {
        path: "src/download.js",
        startLine: 6,
        endLine: 16,
        lineTolerance: 3,
      },
      {
        path: "src/download.js",
        startLine: 38,
        endLine: 44,
        lineTolerance: 3,
      },
    ]);
    expect(
      cases
        .get("javascript-graphql-recovery-amplification")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-307", "CWE-799"]]);
    expect(
      cases
        .get("javascript-graphql-recovery-amplification")
        ?.expected.flatMap((expectation) => expectation.locations),
    ).toEqual([
      {
        path: "src/graphql.js",
        startLine: 8,
        endLine: 23,
        lineTolerance: 3,
      },
      {
        path: "src/recovery.js",
        startLine: 9,
        endLine: 16,
        lineTolerance: 3,
      },
    ]);
    expect(
      cases
        .get("javascript-forwarded-client-rate-limit-bypass")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-345", "CWE-307"]]);
    expect(
      cases
        .get("javascript-forwarded-client-rate-limit-bypass")
        ?.expected.flatMap((expectation) => expectation.locations),
    ).toEqual([
      {
        path: "src/recovery.js",
        startLine: 1,
        endLine: 6,
        lineTolerance: 3,
      },
      {
        path: "src/recovery.js",
        startLine: 18,
        endLine: 30,
        lineTolerance: 3,
      },
    ]);
    expect(
      cases
        .get("javascript-duplicate-parameter-authorization-bypass")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-436", "CWE-863"]]);
    expect(
      cases
        .get("javascript-duplicate-parameter-authorization-bypass")
        ?.expected.flatMap((expectation) => expectation.locations),
    ).toEqual([
      {
        path: "src/gateway.js",
        startLine: 7,
        endLine: 13,
        lineTolerance: 3,
      },
      {
        path: "src/backend.js",
        startLine: 1,
        endLine: 8,
        lineTolerance: 3,
      },
    ]);
    expect(
      cases
        .get("javascript-jwt-algorithm-confusion")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-347", "CWE-287"]]);
    expect(
      cases
        .get("javascript-jwt-algorithm-confusion")
        ?.expected.flatMap((expectation) => expectation.locations),
    ).toEqual([
      {
        path: "src/token.js",
        startLine: 22,
        endLine: 35,
        lineTolerance: 3,
      },
      {
        path: "src/admin.js",
        startLine: 1,
        endLine: 5,
        lineTolerance: 3,
      },
    ]);
    expect(
      cases
        .get("javascript-password-reset-host-poisoning")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-640", "CWE-346"]]);
    expect(
      cases
        .get("javascript-password-reset-host-poisoning")
        ?.expected.flatMap((expectation) => expectation.locations),
    ).toEqual([
      {
        path: "src/password-reset.js",
        startLine: 11,
        endLine: 19,
        lineTolerance: 3,
      },
    ]);
    expect(
      cases
        .get("javascript-xpath-authentication-injection")
        ?.expected.flatMap((expectation) => expectation.locations),
    ).toEqual([
      {
        path: "src/authentication.js",
        startLine: 14,
        endLine: 15,
        lineTolerance: 3,
      },
    ]);
    expect(
      cases
        .get("c-packet-length-overflow")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-787", "CWE-120"]]);
    expect(
      cases
        .get("c-async-audit-use-after-free")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-416"]]);
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
    expect(
      cases
        .get("javascript-http-request-smuggling")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-444", "CWE-288"]]);
    expect(
      cases
        .get("javascript-saml-signature-wrapping")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-347", "CWE-345", "CWE-287"]]);
    expect(
      cases
        .get("javascript-jwks-header-key-injection")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-346", "CWE-347", "CWE-287"]]);
    expect(
      cases
        .get("javascript-oidc-id-token-misbinding")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-287", "CWE-345"]]);
    expect(
      cases
        .get("javascript-webauthn-account-misbinding")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-287", "CWE-304"]]);
    expect(
      cases
        .get("javascript-signed-webhook-replay")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-294"]]);
    expect(
      cases
        .get("javascript-ecdsa-signature-malleability-replay")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-294", "CWE-347"]]);
    expect(
      cases
        .get("javascript-ldap-filter-authorization")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-90", "CWE-863"]]);
    expect(
      cases
        .get("javascript-xpath-authentication-injection")
        ?.expected.map((expectation) => expectation.cwe),
    ).toEqual([["CWE-643", "CWE-287"]]);
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
    const asyncAuditUseAfterFree = join(
      benchmarkRoot,
      "fixtures",
      "c-async-audit-use-after-free",
    );
    const safeAsyncAuditLifetime = join(
      benchmarkRoot,
      "fixtures",
      "c-safe-async-audit-lifetime",
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
    const httpRequestSmuggling = join(
      benchmarkRoot,
      "fixtures",
      "javascript-http-request-smuggling",
    );
    const safeHttpFraming = join(
      benchmarkRoot,
      "fixtures",
      "javascript-safe-http-framing",
    );
    const jwksHeaderKeyInjection = join(
      benchmarkRoot,
      "fixtures",
      "javascript-jwks-header-key-injection",
    );
    const safeJwksKeyOrigin = join(
      benchmarkRoot,
      "fixtures",
      "javascript-safe-jwks-key-origin",
    );
    const oidcIdTokenMisbinding = join(
      benchmarkRoot,
      "fixtures",
      "javascript-oidc-id-token-misbinding",
    );
    const safeOidcIdTokenBinding = join(
      benchmarkRoot,
      "fixtures",
      "javascript-safe-oidc-id-token-binding",
    );
    const webauthnAccountMisbinding = join(
      benchmarkRoot,
      "fixtures",
      "javascript-webauthn-account-misbinding",
    );
    const safeWebauthnAccountBinding = join(
      benchmarkRoot,
      "fixtures",
      "javascript-safe-webauthn-account-binding",
    );
    const signedWebhookReplay = join(
      benchmarkRoot,
      "fixtures",
      "javascript-signed-webhook-replay",
    );
    const safeSignedWebhook = join(
      benchmarkRoot,
      "fixtures",
      "javascript-safe-signed-webhook",
    );
    const ecdsaMalleabilityReplay = join(
      benchmarkRoot,
      "fixtures",
      "javascript-ecdsa-signature-malleability-replay",
    );
    const safeEcdsaEventIdempotency = join(
      benchmarkRoot,
      "fixtures",
      "javascript-safe-ecdsa-event-idempotency",
    );
    const forwardedClientBypass = join(
      benchmarkRoot,
      "fixtures",
      "javascript-forwarded-client-rate-limit-bypass",
    );
    const safeForwardedClientBudget = join(
      benchmarkRoot,
      "fixtures",
      "javascript-safe-forwarded-client-budget",
    );
    const samlSignatureWrapping = join(
      benchmarkRoot,
      "fixtures",
      "javascript-saml-signature-wrapping",
    );
    const safeSamlAssertionBinding = join(
      benchmarkRoot,
      "fixtures",
      "javascript-safe-saml-assertion-binding",
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
      await readFile(join(asyncAuditUseAfterFree, "src", "session.c"), "utf8"),
    ).toContain("release_session(session)");
    expect(
      await readFile(join(asyncAuditUseAfterFree, "src", "session.c"), "utf8"),
    ).toContain(
      "pending_audit_session->send_report(pending_audit_session->peer, report)",
    );
    expect(
      await readFile(join(asyncAuditUseAfterFree, "src", "session.c"), "utf8"),
    ).not.toContain("pending_audit_session == session");
    expect(
      await readFile(join(safeAsyncAuditLifetime, "src", "session.c"), "utf8"),
    ).toContain("if (pending_audit_session == session)");
    expect(
      await readFile(join(safeAsyncAuditLifetime, "src", "session.c"), "utf8"),
    ).toContain("pending_audit_session = NULL");
    expect(
      await readFile(join(safeAsyncAuditLifetime, "src", "session.c"), "utf8"),
    ).toContain("slot_session()->handle == handle");
    expect(
      await readFile(join(safeAsyncAuditLifetime, "src", "session.c"), "utf8"),
    ).toContain("handle == UINT64_MAX ? 0 : handle + 1");
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
    expect(
      await readFile(join(httpRequestSmuggling, "src", "gateway.js"), "utf8"),
    ).toContain("content-length:");
    expect(
      await readFile(join(httpRequestSmuggling, "src", "backend.js"), "utf8"),
    ).toContain('transferEncoding === "chunked"');
    expect(
      await readFile(join(safeHttpFraming, "src", "gateway.js"), "utf8"),
    ).toContain("conflicting Content-Length and Transfer-Encoding rejected");
    expect(
      await readFile(join(safeHttpFraming, "src", "gateway.js"), "utf8"),
    ).toContain("request must contain exactly one complete message");
    expect(
      await readFile(join(jwksHeaderKeyInjection, "src", "token.js"), "utf8"),
    ).toContain("keyUrl.origin !== policy.allowedJwksOrigin");
    expect(
      await readFile(join(jwksHeaderKeyInjection, "src", "token.js"), "utf8"),
    ).toContain("policy.fetchJwks(keyUrl.href)");
    expect(
      await readFile(join(safeJwksKeyOrigin, "src", "token.js"), "utf8"),
    ).toContain("policy.fetchJwks(policy.expectedJwksUri)");
    expect(
      await readFile(join(safeJwksKeyOrigin, "src", "token.js"), "utf8"),
    ).toContain('if ("jku" in header || "x5u" in header)');
    expect(
      await readFile(join(oidcIdTokenMisbinding, "src", "login.js"), "utf8"),
    ).toContain("verifySignedIdToken(response.idToken");
    expect(
      await readFile(join(oidcIdTokenMisbinding, "src", "login.js"), "utf8"),
    ).not.toContain("claims.aud");
    expect(
      await readFile(join(safeOidcIdTokenBinding, "src", "login.js"), "utf8"),
    ).toContain("!intendedForClient(claims, pending.clientId)");
    expect(
      await readFile(join(safeOidcIdTokenBinding, "src", "login.js"), "utf8"),
    ).toContain("!sameSecret(claims.nonce, pending.nonce)");
    expect(
      await readFile(
        join(webauthnAccountMisbinding, "src", "server.js"),
        "utf8",
      ),
    ).toContain("state.sessions.set(sessionId, { userId: requestedUser.id })");
    expect(
      await readFile(
        join(webauthnAccountMisbinding, "src", "server.js"),
        "utf8",
      ),
    ).not.toContain("credential.ownerId !== requestedUser.id");
    expect(
      await readFile(
        join(safeWebauthnAccountBinding, "src", "server.js"),
        "utf8",
      ),
    ).toContain("credential.ownerId !== transaction.userId");
    expect(
      await readFile(
        join(safeWebauthnAccountBinding, "src", "server.js"),
        "utf8",
      ),
    ).toContain(
      "state.sessions.set(sessionId, { userId: credential.ownerId })",
    );
    expect(
      await readFile(join(signedWebhookReplay, "src", "webhook.js"), "utf8"),
    ).toContain("ledger.credit(event.data.accountId, event.data.amountCents)");
    expect(
      await readFile(join(signedWebhookReplay, "src", "webhook.js"), "utf8"),
    ).not.toContain("MAX_CLOCK_SKEW_SECONDS");
    expect(
      await readFile(join(safeSignedWebhook, "src", "webhook.js"), "utf8"),
    ).toContain("Math.abs(nowSeconds - timestamp)");
    expect(
      await readFile(join(safeSignedWebhook, "src", "webhook.js"), "utf8"),
    ).toContain("ledger.applyCreditOnce");
    expect(
      await readFile(
        join(ecdsaMalleabilityReplay, "src", "webhook.js"),
        "utf8",
      ),
    ).toContain('createHash("sha256").update(signature)');
    expect(
      await readFile(
        join(ecdsaMalleabilityReplay, "src", "webhook.js"),
        "utf8",
      ),
    ).toContain("ledger.applySignatureOnce");
    expect(
      await readFile(
        join(safeEcdsaEventIdempotency, "src", "webhook.js"),
        "utf8",
      ),
    ).toContain("this.#consumedEventIds.has(eventId)");
    expect(
      await readFile(
        join(safeEcdsaEventIdempotency, "src", "webhook.js"),
        "utf8",
      ),
    ).toContain("ledger.applyEventOnce");
    expect(
      await readFile(join(forwardedClientBypass, "src", "recovery.js"), "utf8"),
    ).toContain('forwarded.split(",")[0].trim()');
    expect(
      await readFile(join(forwardedClientBypass, "src", "recovery.js"), "utf8"),
    ).not.toContain("trustedProxies.has(peerAddress)");
    expect(
      await readFile(
        join(safeForwardedClientBudget, "src", "recovery.js"),
        "utf8",
      ),
    ).toContain("while (index > 0 && trustedProxies.has(chain[index]))");
    expect(
      await readFile(
        join(safeForwardedClientBudget, "src", "recovery.js"),
        "utf8",
      ),
    ).toContain(
      "this.#attemptsByAccount.set(request.accountId, accountAttempts)",
    );
    expect(
      await readFile(join(samlSignatureWrapping, "src", "saml.js"), "utf8"),
    ).toContain("createSession(presentedAssertion)");
    expect(
      await readFile(join(safeSamlAssertionBinding, "src", "saml.js"), "utf8"),
    ).toContain("response.signature.referenceId !== signedAssertion.id");
    expect(
      await readFile(join(safeSamlAssertionBinding, "src", "saml.js"), "utf8"),
    ).toContain("createSession(signedAssertion)");
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-password-reset-host-poisoning",
          "src",
          "password-reset.js",
        ),
        "utf8",
      ),
    ).toContain('request.headers["x-forwarded-host"]');
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-password-reset-host-poisoning",
          "src",
          "password-reset.js",
        ),
        "utf8",
      ),
    ).toContain("mailer.sendPasswordReset");
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-safe-password-reset-origin",
          "src",
          "password-reset.js",
        ),
        "utf8",
      ),
    ).toContain(
      'const PUBLIC_ORIGIN = new URL("https://accounts.example.test")',
    );
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-credentialed-cors-exfiltration",
          "src",
          "cors.js",
        ),
        "utf8",
      ),
    ).toContain('setHeader("Access-Control-Allow-Origin", origin)');
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-credentialed-cors-exfiltration",
          "src",
          "cors.js",
        ),
        "utf8",
      ),
    ).toContain('setHeader("Access-Control-Allow-Credentials", "true")');
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-safe-cors-allowlist",
          "src",
          "cors.js",
        ),
        "utf8",
      ),
    ).toContain(
      'const TRUSTED_ORIGINS = new Set(["https://portal.example.test"])',
    );
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-cross-site-websocket-hijacking",
          "src",
          "websocket-route.js",
        ),
        "utf8",
      ),
    ).toContain(
      'const session = sessions.get(String(request.cookies.sid ?? ""))',
    );
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-safe-websocket-origin",
          "src",
          "websocket-route.js",
        ),
        "utf8",
      ),
    ).toContain(
      'const TRUSTED_WEBSOCKET_ORIGINS = new Set(["https://portal.example.test"])',
    );
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-web-cache-deception",
          "src",
          "edge-cache.js",
        ),
        "utf8",
      ),
    ).toContain("sharedCache.set(cacheKey");
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-web-cache-deception",
          "src",
          "origin.js",
        ),
        "utf8",
      ),
    ).toContain("request.path.replace");
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-safe-private-cache",
          "src",
          "edge-cache.js",
        ),
        "utf8",
      ),
    ).toContain("isExplicitlyPublic");
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-safe-private-cache",
          "src",
          "origin.js",
        ),
        "utf8",
      ),
    ).toContain('request.path !== "/account"');
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-tenant-cache-key-confusion",
          "src",
          "invoices.js",
        ),
        "utf8",
      ),
    ).toContain("const cacheKey = `invoice:${invoiceId}`");
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-safe-tenant-cache-isolation",
          "src",
          "invoices.js",
        ),
        "utf8",
      ),
    ).toContain(
      "const cacheKey = `tenant:${session.tenantId}:invoice:${invoiceId}`",
    );
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-http-response-splitting",
          "src",
          "download.js",
        ),
        "utf8",
      ),
    ).toContain('headers.get("x-accel-redirect")');
    expect(
      await readFile(
        join(
          benchmarkRoot,
          "fixtures",
          "javascript-safe-http-response-headers",
          "src",
          "download.js",
        ),
        "utf8",
      ),
    ).toContain("/[\\u0000-\\u001f\\u007f]/u.test(filename)");
    for (const benchmarkCase of manifest.cases) {
      expect(benchmarkCase.findingsPaths).toHaveLength(3);
      const fixtureRoot = join(benchmarkRoot, benchmarkCase.fixture);
      expect(
        (await readFile(join(fixtureRoot, "README.md"), "utf8")).trim().length,
      ).toBeGreaterThan(0);
      expect(await containsFixtureSourceFile(join(fixtureRoot, "src"))).toBe(
        true,
      );
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
  }, 15_000);

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
    const repositoryWideScan = await readFile(
      join(
        pluginRoot,
        "security-scan",
        "references",
        "repository-wide-scan.md",
      ),
      "utf8",
    );
    const finalReport = await readFile(
      resolve(
        process.cwd(),
        "_bundled_plugin",
        "references",
        "final-report.md",
      ),
      "utf8",
    );

    expect(deepScan).toContain("at least five independent discovery passes");
    expect(deepScan).toContain("compositional and temporal attack paths");
    expect(deepScan).toContain("security-value generation");
    expect(deepScan).toContain("check/use and state races");
    expect(deepScan).toContain(
      "For ECDSA/DSA signature-representation candidates",
    );
    expect(deepScan).toContain("bulk object binding and mass assignment");
    expect(deepScan).toContain("browser-ambient credential CSRF");
    expect(deepScan).toContain("Credentialed CORS response authorization:");
    expect(deepScan).toContain("Cross-site WebSocket handshake authorization:");
    expect(deepScan).toContain(
      "Web cache deception and shared-cache isolation:",
    );
    expect(deepScan).toContain("Application authorization-cache isolation:");
    expect(deepScan).toContain(
      "GraphQL execution amplification and resolver-scoped enforcement:",
    );
    expect(deepScan).toContain(
      "Forwarded client identity and proxy-chain trust:",
    );
    expect(deepScan).toContain("regular-expression complexity:");
    expect(deepScan).toContain(
      "external authentication and authorization decision failure:",
    );
    expect(deepScan).toContain(
      "outbound destination continuity and DNS rebinding:",
    );
    expect(deepScan).toContain("native memory safety:");
    expect(deepScan).toContain("destination object extents");
    expect(deepScan).toContain("same-address reuse witness");
    expect(deepScan).toContain("Do not invent concurrency");
    expect(deepScan).toContain("document-query and NoSQL operator injection:");
    expect(deepScan).toContain(
      "LDAP filter and directory authorization injection:",
    );
    expect(deepScan).toContain(
      "XPath/XQuery expression and selected-node security binding:",
    );
    expect(deepScan).toContain(
      "OAuth/OIDC authorization-code and account-linking transaction binding:",
    );
    expect(deepScan).toContain(
      "Login session fixation and authentication lifecycle:",
    );
    expect(deepScan).toContain(
      "Account-recovery and identity-link origin binding:",
    );
    expect(deepScan).toContain("untrusted upload and content placement:");
    expect(deepScan).toContain("HTTP request framing and smuggling:");
    expect(deepScan).toContain(
      "Duplicate query, form, and body parameter interpretation:",
    );
    expect(deepScan).toContain(
      "HTTP response-header injection and response splitting:",
    );
    expect(deepScan).toContain("archive symlink and hardlink traversal:");
    expect(deepScan).toContain("decompression bombs and data amplification:");
    expect(deepScan).toContain("authenticated-encryption nonce and IV reuse:");
    expect(deepScan).toContain(
      "JWT/JWS/OIDC algorithm, key-family, key origin, and claim binding:",
    );
    expect(deepScan).toContain(
      "OIDC signed ID-token client and transaction binding:",
    );
    expect(deepScan).toContain("asymmetric public-key bytes can");
    expect(deepScan).toContain("be reinterpreted as an HMAC secret");
    expect(deepScan).toContain("SAML and federated assertion binding:");
    expect(standardScan).toContain("bulk object binding");
    expect(standardScan).toContain("mass assignment");
    expect(standardScan).toContain("browser-ambient credential CSRF");
    expect(standardScan).toContain("credentialed CORS origin authorization");
    expect(standardScan).toContain(
      "WebSocket handshake Origin authorization and bidirectional channel exposure",
    );
    expect(standardScan).toContain(
      "web-cache deception across edge cache keys",
    );
    expect(standardScan).toContain(
      "application authorization caches across trusted principal/tenant/role",
    );
    expect(standardScan).toContain(
      "GraphQL alias/batch/fragment amplification",
    );
    expect(standardScan).toContain(
      "forwarded client identity from the direct peer",
    );
    expect(standardScan).toContain(
      "regular-expression catastrophic backtracking",
    );
    expect(standardScan).toContain(
      "external authentication/authorization policy decisions",
    );
    expect(standardScan).toContain(
      "DNS-rebinding SSRF across hostname validation",
    );
    expect(standardScan).toContain(
      "native memory allocation/copy/index/lifetime",
    );
    expect(standardScan).toContain("callbacks, timers, queues, registries");
    expect(standardScan).toContain(
      "SQL and document-database query selectors/operators",
    );
    expect(standardScan).toContain("LDAP filter construction");
    expect(standardScan).toContain("XPath/XQuery predicate construction");
    expect(standardScan).toContain(
      "OAuth/OIDC authorization-code state, nonce, PKCE",
    );
    expect(standardScan).toContain(
      "login session fixation and authenticated-session",
    );
    expect(standardScan).toContain(
      "password-reset, verification, invitation, and magic-login absolute URL origins",
    );
    expect(standardScan).toContain("untrusted uploads and");
    expect(standardScan).toContain("HTTP message framing and parser agreement");
    expect(standardScan).toContain(
      "duplicate query/form/body parameter decoding",
    );
    expect(standardScan).toContain(
      "HTTP response-header injection and response splitting",
    );
    expect(standardScan).toContain("archive symlink/hardlink target traversal");
    expect(standardScan).toContain("decompression bombs across actual output");
    expect(standardScan).toContain(
      "authenticated encryption across exact algorithm/mode",
    );
    expect(standardScan).toContain("JWT/OIDC algorithm-to-key-family binding");
    expect(standardScan).toContain(
      "signed OIDC ID-token audience, authorized-party, nonce, callback-session",
    );
    expect(standardScan).toContain(
      "ECDSA/DSA signature representation and malleability",
    );
    expect(standardScan).toContain("public-key-as-HMAC confusion");
    expect(standardScan).toContain("SAML/federated signed-assertion selection");
    expect(diffScan).toContain("mass-assignment field controls");
    expect(diffScan).toContain("writable-field sets");
    expect(diffScan).toContain("anti-CSRF token");
    expect(diffScan).toContain("changed CORS origin reflection");
    expect(diffScan).toContain("changed WebSocket/socket.io upgrade handlers");
    expect(diffScan).toContain("changed CDN/proxy/application cache keys");
    expect(diffScan).toContain(
      "changed server-side object, response, permission, entitlement, or policy",
    );
    expect(diffScan).toContain(
      "changed GraphQL alias, fragment, nesting, batch",
    );
    expect(diffScan).toContain("changed `Forwarded`, `X-Forwarded-For`");
    expect(diffScan).toContain("changed regex literals");
    expect(diffScan).toContain(
      "changed external authorization or entitlement calls",
    );
    expect(diffScan).toContain("changed outbound URL parsing");
    expect(diffScan).toContain("terminator space");
    expect(diffScan).toContain("use-after-free");
    expect(diffScan).toContain("request-controlled document selectors");
    expect(diffScan).toContain("changed RFC 4515 assertion escaping");
    expect(diffScan).toContain("new XPath/XQuery interpolation");
    expect(diffScan).toContain(
      "changed OAuth/OIDC authorization-code initiation or callback `state`",
    );
    expect(diffScan).toContain(
      "changed anonymous-session creation or adoption",
    );
    expect(diffScan).toContain(
      "changed password-reset, verification, invitation, or magic-link absolute URL construction",
    );
    expect(diffScan).toContain("new multipart/file inputs");
    expect(diffScan).toContain("duplicate or conflicting `Content-Length` and");
    expect(diffScan).toContain("changed query/form/body parsing");
    expect(diffScan).toContain("changed response-header construction");
    expect(diffScan).toContain("changed archive entry-type handling");
    expect(diffScan).toContain(
      "changed archive/document/protocol/media/package decompressors",
    );
    expect(diffScan).toContain("changed AEAD algorithm/mode selection");
    expect(diffScan).toContain(
      "changed ECDSA/DSA signature encoding or canonicalization",
    );
    expect(diffScan).toContain(
      "SAML/SSO assertion ID lookup, signature-reference resolution",
    );
    expect(diffScan).toContain(
      "JWT/JWS/OIDC `alg`, accepted algorithm set, signature-versus-MAC",
    );
    expect(diffScan).toContain("public-key/symmetric-secret representation");
    expect(diffScan).toContain(
      "changed OIDC relying-party client registration",
    );
    expect(discovery).toContain(
      "distinguish attacker-controlled template source from attacker-controlled data",
    );
    expect(discovery).toContain("effective output space or entropy");
    expect(discovery).toContain("attacker-reachable mutation path");
    expect(discovery).toContain("route-level ownership check does not");
    expect(discovery).toContain("bearer-only APIs");
    expect(discovery).toContain("For credentialed CORS response exposure");
    expect(discovery).toContain("For cross-site WebSocket hijacking");
    expect(discovery).toContain("For web cache deception");
    expect(discovery).toContain("For ECDSA/DSA-signed operations");
    expect(discovery).toContain("Prefer CWE-524 for cross-principal edge, CDN");
    expect(discovery).toContain("For application-level authorization caches");
    expect(discovery).toContain(
      "server-side application cache bypasses the otherwise correct",
    );
    expect(discovery).toContain("For native memory safety");
    expect(discovery).toContain("bounded API is neither vulnerable");
    expect(discovery).toContain("For temporal memory safety");
    expect(discovery).toContain("object-lifetime ledger");
    expect(discovery).toContain("Do not infer parallel execution");
    expect(discovery).toContain("For document-query and NoSQL APIs");
    expect(discovery).toContain(
      "For LDAP searches used in authentication, group membership",
    );
    expect(discovery).toContain("DN escaping are different contexts");
    expect(discovery).toContain(
      "For XPath and XQuery used to select accounts, tenants, permissions",
    );
    expect(discovery).toContain(
      "XML/HTML escaping is not XPath literal or expression safety",
    );
    expect(discovery).toContain(
      "parameterization when request-controlled values",
    );
    expect(discovery).toContain("For direct uploads and content placement");
    expect(discovery).toContain(
      "another file, process, startup phase, or worker",
    );
    expect(discovery).toContain(
      "For HTTP request-smuggling and desynchronization",
    );
    expect(discovery).toContain("Do not promote header names alone");
    expect(discovery).toContain(
      "For duplicate query, form, or body parameter confusion",
    );
    expect(discovery).toContain(
      "For HTTP response-header injection and response splitting",
    );
    expect(discovery).toContain(
      "Treat archive link targets as independent attacker-controlled paths",
    );
    expect(discovery).toContain(
      "Treat compressed-data expansion as a separate archive",
    );
    expect(discovery).toContain(
      "Treat authenticated-encryption nonce or IV generation as a key-scoped state",
    );
    expect(discovery).toContain(
      "For SAML and other signed federated identity objects",
    );
    expect(discovery).toContain("For JWT/JWS/OIDC verification");
    expect(discovery).toContain(
      "reinterpretation of a published RSA/EC/OKP public key as an HMAC secret",
    );
    expect(discovery).toContain(
      "Do not report `kid`, `jku`, JWKS fetching, or OIDC discovery",
    );
    expect(discovery).toContain(
      "For OIDC ID-token acceptance, separately test an otherwise valid token",
    );
    expect(discovery).toContain(
      "For OAuth/OIDC authorization-code login, account-linking, consent",
    );
    expect(discovery).toContain(
      "PKCE does not by itself prove callback-session",
    );
    expect(discovery).toContain("For login session fixation");
    expect(discovery).toContain(
      "Do not report pre-authentication session continuity alone",
    );
    expect(discovery).toContain(
      "For password-reset, email-verification, invitation, magic-login",
    );
    expect(discovery).toContain(
      "Strong token entropy, digest-only storage, short expiry",
    );
    expect(discovery).toContain(
      "For GraphQL and GraphQL-like execution engines",
    );
    expect(discovery).toContain(
      "Preserve the mapping from one transport envelope",
    );
    expect(discovery).toContain("For proxy-derived client identity");
    expect(discovery).toContain(
      "Begin at the rightmost transport peer and peel only verified proxy hops",
    );
    expect(discovery).toContain("For regular-expression denial of service");
    expect(discovery).toContain(
      "For external authentication and authorization policy decisions",
    );
    expect(discovery).toContain("For hostname-based outbound requests");
    expect(validation).toContain("predictable security value:");
    expect(validation).toContain("check/use or state race:");
    expect(validation).toContain("bulk object binding/mass assignment:");
    expect(validation).toContain("browser CSRF:");
    expect(validation).toContain("credentialed CORS response exposure:");
    expect(validation).toContain("cross-site WebSocket hijacking:");
    expect(validation).toContain("web cache deception:");
    expect(validation).toContain("application authorization-cache isolation:");
    expect(validation).toContain("GraphQL operation amplification:");
    expect(validation).toContain(
      "forwarded client-identity/proxy-trust bypass:",
    );
    expect(validation).toContain("regular-expression denial of service:");
    expect(validation).toContain("external authorization fail-open:");
    expect(validation).toContain("DNS-rebinding SSRF:");
    expect(validation).toContain("native memory corruption:");
    expect(validation).toContain("use-after-free / use-after-lifetime:");
    expect(validation).toContain("concurrency and reentrancy prerequisite:");
    expect(validation).toContain("document-query/NoSQL operator injection:");
    expect(validation).toContain("LDAP filter injection:");
    expect(validation).toContain("XPath/XQuery injection:");
    expect(validation).toContain("untrusted upload/content placement:");
    expect(validation).toContain("HTTP request smuggling/desynchronization:");
    expect(validation).toContain(
      "duplicate-parameter authorization confusion:",
    );
    expect(validation).toContain(
      "For HTTP response-header injection or response splitting",
    );
    expect(validation).toContain("for archive symlink and hardlink pivots");
    expect(validation).toContain(
      "for decompression-bomb and data-amplification candidates",
    );
    expect(validation).toContain(
      "for authenticated-encryption nonce/IV-reuse candidates",
    );
    expect(validation).toContain("ECDSA/DSA signature-malleability replay:");
    expect(validation).toContain("JWT/JWS/OIDC remote key origin:");
    expect(validation).toContain(
      "OIDC ID-token client and transaction binding:",
    );
    expect(validation).toContain("JWT/JWS algorithm and key-type confusion:");
    expect(validation).toContain(
      "OAuth/OIDC authorization-code transaction or account-linking CSRF:",
    );
    expect(validation).toContain(
      "reject attacker state in the victim session before exchange",
    );
    expect(validation).toContain("login session fixation:");
    expect(validation).toContain(
      "distinct unpredictable post-authentication identifier",
    );
    expect(validation).toContain(
      "password-reset/verification/magic-link origin poisoning:",
    );
    expect(validation).toContain(
      "attacker receives no token or security capability",
    );
    expect(validation).toContain("SAML signed-byte-to-session binding:");
    expect(attackPath).toContain("For mass-assignment findings");
    expect(attackPath).toContain("For CSRF findings");
    expect(attackPath).toContain(
      "For credentialed CORS response-exposure findings",
    );
    expect(attackPath).toContain("For cross-site WebSocket-hijacking findings");
    expect(attackPath).toContain("For web-cache-deception findings");
    expect(attackPath).toContain(
      "For application authorization-cache findings",
    );
    expect(attackPath).toContain(
      "For GraphQL operation-amplification findings",
    );
    expect(attackPath).toContain(
      "For forwarded client-identity and proxy-trust findings",
    );
    expect(attackPath).toContain(
      "For regular-expression denial-of-service findings",
    );
    expect(attackPath).toContain(
      "For external authorization fail-open findings",
    );
    expect(attackPath).toContain("For DNS-rebinding SSRF findings");
    expect(attackPath).toContain("For native-memory findings");
    expect(attackPath).toContain("For document-query and NoSQL findings");
    expect(attackPath).toContain("For LDAP filter findings");
    expect(attackPath).toContain("For XPath/XQuery findings");
    expect(attackPath).toContain(
      "For untrusted upload and content-placement findings",
    );
    expect(attackPath).toContain(
      "For HTTP request-smuggling and desynchronization findings",
    );
    expect(attackPath).toContain(
      "For duplicate-parameter authorization-confusion findings",
    );
    expect(attackPath).toContain(
      "For HTTP response-header injection and response-splitting findings",
    );
    expect(attackPath).toContain("For archive symlink and hardlink findings");
    expect(attackPath).toContain(
      "For decompression-bomb and data-amplification findings",
    );
    expect(attackPath).toContain(
      "For authenticated-encryption nonce/IV-reuse findings",
    );
    expect(attackPath).toContain(
      "For ECDSA/DSA signature-malleability replay findings",
    );
    expect(attackPath).toContain("For SAML/federated signed-object findings");
    expect(attackPath).toContain("For JWT/JWS/OIDC remote-key findings");
    expect(attackPath).toContain("For JWT/JWS algorithm-confusion findings");
    expect(attackPath).toContain("For OIDC ID-token client-binding findings");
    expect(attackPath).toContain(
      "For OAuth/OIDC authorization-code login and account-linking findings",
    );
    expect(attackPath).toContain("For login session-fixation findings");
    expect(attackPath).toContain(
      "For password-reset, verification, invitation, or magic-link origin findings",
    );
    expect(severityPolicy).toContain(
      "CSRF when it enables important state-changing actions",
    );
    expect(severityPolicy).toContain("CSRF on low-impact actions");
    expect(severityPolicy).toContain("Credentialed CORS exposure");
    expect(severityPolicy).toContain("CORS reports based only");
    expect(severityPolicy).toContain("Cross-site WebSocket hijacking");
    expect(severityPolicy).toContain("WebSocket-hijacking reports based only");
    expect(severityPolicy).toContain("Web cache deception that stores");
    expect(severityPolicy).toContain("Web-cache-deception reports based only");
    expect(severityPolicy).toContain(
      "Application authorization-cache key confusion",
    );
    expect(severityPolicy).toContain(
      "Application authorization-cache reports based only",
    );
    expect(severityPolicy).toContain(
      "GraphQL operation amplification that converts",
    );
    expect(severityPolicy).toContain(
      "Forwarded client-identity spoofing that defeats enough authentication",
    );
    expect(severityPolicy).toContain(
      "Regular-expression denial of service that lets",
    );
    expect(severityPolicy).toContain("Regular-expression reports based only");
    expect(severityPolicy).toContain(
      "External authentication or authorization failure that defaults to",
    );
    expect(severityPolicy).toContain(
      "External authorization fail-open that reliably converts",
    );
    expect(severityPolicy).toContain(
      "Fail-open reports based only on a `catch`",
    );
    expect(severityPolicy).toContain("DNS rebinding supports `high`");
    expect(severityPolicy).toContain(
      "DNS-rebinding or SSRF reports based only",
    );
    expect(severityPolicy).toContain("GraphQL reports based only on aliases");
    expect(severityPolicy).toContain(
      "Forwarded-client or proxy-trust reports based only",
    );
    expect(severityPolicy).toContain(
      "Memory corruption that is theoretical, non-triggerable",
    );
    expect(severityPolicy).toContain(
      "Document-query or NoSQL operator injection",
    );
    expect(severityPolicy).toContain(
      "JWT/JWS algorithm/key-type confusion that lets an unauthenticated attacker",
    );
    expect(severityPolicy).toContain(
      "JWT algorithm-confusion reports based only on support for more than one",
    );
    expect(severityPolicy).toContain(
      "LDAP filter injection that demonstrably bypasses authentication",
    );
    expect(severityPolicy).toContain(
      "XPath or XQuery injection that demonstrably selects a privileged account",
    );
    expect(severityPolicy).toContain(
      "Untrusted upload or content placement that writes attacker-controlled bytes",
    );
    expect(severityPolicy).toContain(
      "HTTP request smuggling that demonstrably crosses",
    );
    expect(severityPolicy).toContain(
      "Duplicate-parameter interpretation conflict that lets",
    );
    expect(severityPolicy).toContain(
      "HTTP response splitting that lets an unauthenticated attacker",
    );
    expect(severityPolicy).toContain(
      "HTTP response-header injection or response splitting that reliably causes",
    );
    expect(severityPolicy).toContain(
      "Archive symlink or hardlink traversal that reliably converts",
    );
    expect(severityPolicy).toContain(
      "Decompression-bomb or data-amplification behavior that lets",
    );
    expect(severityPolicy).toContain(
      "Authenticated-encryption key/nonce reuse that lets an attacker recover",
    );
    expect(severityPolicy).toContain(
      "ECDSA/DSA signature malleability that reliably bypasses replay",
    );
    expect(severityPolicy).toContain(
      "Signature-malleability reports based only on ECDSA/DSA accepting both high-S",
    );
    expect(severityPolicy).toContain(
      "Request-smuggling claims based only on `Content-Length`",
    );
    expect(severityPolicy).toContain(
      "Duplicate-parameter or parameter-pollution claims based only",
    );
    expect(severityPolicy).toContain(
      "Response-header-injection claims based only on string interpolation",
    );
    expect(severityPolicy).toContain(
      "Archive-link reports based only on symlink/hardlink support",
    );
    expect(severityPolicy).toContain(
      "Decompression-bomb reports based only on a decompressor call",
    );
    expect(severityPolicy).toContain(
      "AEAD nonce/IV reports based only on a constant",
    );
    expect(severityPolicy).toContain(
      "SAML/SSO signature wrapping or signed-object confusion",
    );
    expect(severityPolicy).toContain(
      "SAML/SSO reports based only on multiple assertions",
    );
    expect(severityPolicy).toContain("JWT/JWS/OIDC key-origin confusion");
    expect(severityPolicy).toContain(
      "OAuth/OIDC authorization-code or account-linking transaction confusion",
    );
    expect(severityPolicy).toContain(
      "OIDC ID-token client or nonce misbinding that lets an attacker replay",
    );
    expect(severityPolicy).toContain(
      "OIDC ID-token reports based only on absent `aud`, `azp`, or nonce checks",
    );
    expect(severityPolicy).toContain(
      "Session fixation that lets a remote attacker preserve",
    );
    expect(severityPolicy).toContain(
      "Account-recovery or identity-link origin poisoning that discloses",
    );
    expect(severityPolicy).toContain(
      "JWT/JWKS reports based only on the presence of `kid`",
    );
    expect(severityPolicy).toContain(
      "OAuth/OIDC callback reports based only on missing `state`, nonce, or PKCE",
    );
    expect(severityPolicy).toContain(
      "Session-management reports based only on a pre-authentication session",
    );
    expect(severityPolicy).toContain(
      "Recovery-link reports based only on a `Host`, `Forwarded`",
    );
    expect(threatModelGuidance).toContain(
      "HTTP framing/parser agreement across proxies",
    );
    expect(threatModelGuidance).toContain(
      "duplicate query/form/body parameter trust across raw bytes",
    );
    expect(threatModelGuidance).toContain("HTTP response-header trust across");
    expect(threatModelGuidance).toContain(
      "archive extraction and restore/import trust across member names",
    );
    expect(threatModelGuidance).toContain(
      "compressed-data trust across archive, package, document",
    );
    expect(threatModelGuidance).toContain(
      "authenticated-encryption trust across algorithm/mode",
    );
    expect(threatModelGuidance).toContain(
      "ECDSA/DSA signature representation and malleability",
    );
    expect(threatModelGuidance).toContain(
      "JWT/JWS/OIDC algorithm-to-key-family and signature-versus-MAC binding",
    );
    expect(threatModelGuidance).toContain(
      "LDAP filter and directory group/role authorization binding",
    );
    expect(threatModelGuidance).toContain(
      "XPath/XQuery expression and selected-node authentication/authorization binding",
    );
    expect(threatModelGuidance).toContain(
      "OAuth/OIDC authorization-code state, nonce, PKCE, callback-session",
    );
    expect(threatModelGuidance).toContain(
      "signed OIDC ID-token audience/authorized-party/nonce/client-session binding",
    );
    expect(threatModelGuidance).toContain(
      "credentialed CORS response authorization",
    );
    expect(threatModelGuidance).toContain(
      "cookie-authenticated WebSocket handshake Origin authorization",
    );
    expect(threatModelGuidance).toContain(
      "web-cache deception and shared-cache isolation",
    );
    expect(threatModelGuidance).toContain(
      "application authorization-cache isolation across trusted principal/tenant/role/resource key dimensions",
    );
    expect(threatModelGuidance).toContain(
      "GraphQL aliases/fragments/nesting/batches/persisted documents",
    );
    expect(threatModelGuidance).toContain(
      "forwarded client identity across the direct peer",
    );
    expect(threatModelGuidance).toContain(
      "regular-expression catastrophic backtracking",
    );
    expect(threatModelGuidance).toContain(
      "external authentication and authorization policy/entitlement decisions",
    );
    expect(threatModelGuidance).toContain("outbound URL and DNS trust");
    expect(repositoryWideScan).toContain(
      "OAuth/OIDC authorization-code state, nonce, PKCE, callback-session",
    );
    expect(repositoryWideScan).toContain(
      "signed OIDC ID-token audience/authorized-party/nonce/client-session misbinding",
    );
    expect(repositoryWideScan).toContain(
      "credentialed CORS origin authorization",
    );
    expect(repositoryWideScan).toContain(
      "cookie-authenticated WebSocket upgrade Origin authorization",
    );
    expect(repositoryWideScan).toContain(
      "web-cache deception across edge/shared-cache keys",
    );
    expect(repositoryWideScan).toContain(
      "server-side application authorization-cache key isolation",
    );
    expect(repositoryWideScan).toContain(
      "For HTTP response headers, trace untrusted redirect targets",
    );
    expect(repositoryWideScan).toContain(
      "For archive extraction and restore/import paths",
    );
    expect(repositoryWideScan).toContain(
      "For decompression and data-amplification paths",
    );
    expect(repositoryWideScan).toContain("For authenticated encryption");
    expect(repositoryWideScan).toContain("For ECDSA/DSA-signed operations");
    expect(repositoryWideScan).toContain(
      "GraphQL aliases/fragments/nesting/batches/persisted documents",
    );
    expect(repositoryWideScan).toContain(
      "For proxy-derived client identity, begin at the socket peer",
    );
    expect(repositoryWideScan).toContain(
      "For duplicate parameters, preserve the raw ordered input",
    );
    expect(repositoryWideScan).toContain(
      "regular-expression catastrophic backtracking",
    );
    expect(repositoryWideScan).toContain(
      "For external authorization and entitlement decisions",
    );
    expect(repositoryWideScan).toContain(
      "For hostname-based outbound requests",
    );
    expect(finalReport).toContain(
      "For external authorization fail-open findings",
    );
    expect(finalReport).toContain(
      "For application authorization-cache findings",
    );
    expect(finalReport).toContain(
      "For HTTP response-header injection or response-splitting findings",
    );
    expect(finalReport).toContain(
      "For archive symlink or hardlink traversal findings",
    );
    expect(finalReport).toContain(
      "For decompression-bomb and data-amplification findings",
    );
    expect(finalReport).toContain(
      "For authenticated-encryption nonce/IV-reuse findings",
    );
    expect(finalReport).toContain(
      "For ECDSA/DSA signature-malleability replay findings",
    );
    expect(finalReport).toContain(
      "For forwarded client-identity or proxy-trust findings",
    );
    expect(finalReport).toContain(
      "For duplicate-parameter authorization-confusion findings",
    );
    expect(finalReport).toContain("For OIDC ID-token client-binding findings");
    expect(finalReport).toContain("For DNS-rebinding SSRF findings");
    expect(repositoryWideScan).toContain(
      "JWT/JWS token-selected algorithm and key-family confusion",
    );
    expect(threatModelGuidance).toContain(
      "session management including login fixation and authenticated-session rotation",
    );
    expect(repositoryWideScan).toContain(
      "login session fixation and authenticated-session rotation",
    );
    expect(threatModelGuidance).toContain(
      "password-reset, verification, invitation, and magic-login link origin binding",
    );
    expect(repositoryWideScan).toContain(
      "password-reset, verification, invitation, and magic-login absolute URL origin binding",
    );
    expect(threatModelGuidance).toContain("SAML/federated signed-object");
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
      requireRunStatus: false,
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
      requireRunStatus: false,
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

  test("enforces required and forbidden finding semantics without regex execution", async () => {
    const root = await fixtureRoot();
    const findingsPath = join(
      root,
      "results",
      "conditional-iac",
      "findings.json",
    );
    await writeJson(join(root, "manifest.json"), {
      schemaVersion: "1.0",
      cases: [
        {
          id: "conditional-iac",
          findingsPath: "conditional-iac/findings.json",
          expected: [
            {
              id: "public-role",
              cwe: ["CWE-269"],
              locations: [{ path: "template.yaml", startLine: 17 }],
              requiredValidationTextAnyOf: [
                ["caller-side sts:AssumeRole permission", "identity policy"],
                ["if deployed", "deployed unchanged"],
              ],
              requiredAttackPathTextAnyOf: [
                ["caller-side sts:AssumeRole permission", "identity policy"],
                ["if deployed", "deployed unchanged"],
              ],
              forbiddenText: [
                "an AWS principal is the only precondition",
                "STS returns a role session",
              ],
            },
          ],
        },
      ],
    });
    await writeFindings(findingsPath, [
      finding({
        id: "public-role",
        cwe: ["CWE-269"],
        path: "template.yaml",
        line: 17,
        validation: {
          remainingUncertainty:
            "Deployment is unknown, but an AWS principal is the only precondition.",
        },
        attackPath: { outcome: "STS returns a role session." },
      }),
    ]);

    const rejected = await evaluateBenchmark({
      manifestPath: join(root, "manifest.json"),
      resultsDirectory: join(root, "results"),
      requireRunStatus: false,
    });
    expect(rejected.passed).toBe(false);
    expect(rejected.cases[0]?.runs[0]?.matches[0]).toMatchObject({
      contentSemanticsAccepted: false,
      missingRequiredTextAnyOf: [],
      missingRequiredValidationTextAnyOf: [
        ["caller-side sts:AssumeRole permission", "identity policy"],
        ["if deployed", "deployed unchanged"],
      ],
      missingRequiredAttackPathTextAnyOf: [
        ["caller-side sts:AssumeRole permission", "identity policy"],
        ["if deployed", "deployed unchanged"],
      ],
      presentForbiddenText: [
        "an AWS principal is the only precondition",
        "STS returns a role session",
      ],
    });

    await writeFindings(findingsPath, [
      finding({
        id: "public-role",
        cwe: ["CWE-269"],
        path: "template.yaml",
        line: 17,
        validation: {
          remainingUncertainty:
            "If the role is deployed unchanged, an external caller still needs caller-side `sts:AssumeRole` permission.",
        },
        attackPath: {
          outcome:
            "If the role is deployed unchanged, the external caller obtains a role session only with caller-side `sts:AssumeRole` permission.",
        },
      }),
    ]);
    const accepted = await evaluateBenchmark({
      manifestPath: join(root, "manifest.json"),
      resultsDirectory: join(root, "results"),
      requireRunStatus: false,
    });
    expect(accepted.passed).toBe(true);
    expect(accepted.cases[0]?.runs[0]?.matches[0]).toMatchObject({
      contentSemanticsAccepted: true,
      missingRequiredTextAnyOf: [],
      missingRequiredValidationTextAnyOf: [],
      missingRequiredAttackPathTextAnyOf: [],
      presentForbiddenText: [],
    });
  });

  test("does not credit code evidence whose endpoint roles contradict finding locations", async () => {
    const root = await fixtureRoot();
    await writeJson(join(root, "manifest.json"), {
      schemaVersion: "1.0",
      thresholds: { minCodeEvidenceRate: 1 },
      cases: [
        {
          id: "role-confused-evidence",
          findingsPath: "role-confused-evidence/findings.json",
          expected: [
            {
              id: "path-traversal",
              cwe: ["CWE-22"],
              locations: [{ path: "src/store.cs", startLine: 20 }],
              requireCodeEvidence: true,
            },
          ],
        },
      ],
    });
    const confused = finding({
      id: "role-confused-path",
      cwe: ["CWE-22"],
      path: "src/store.cs",
      line: 20,
      codeEvidence: [
        {
          id: "request-source",
          label: "Request source",
          path: "src/controller.cs",
          startLine: 10,
          role: "sink",
          code: "[FromQuery] string path",
          explanation: "The request controls the path value.",
        },
        {
          id: "filesystem-sink",
          label: "Filesystem sink",
          path: "src/store.cs",
          startLine: 20,
          role: "sink",
          code: "File.ReadAllText(path)",
          explanation: "The path reaches the filesystem read.",
        },
      ],
    });
    confused["locations"] = [
      {
        path: "src/controller.cs",
        startLine: 10,
        role: "source",
      },
      { path: "src/store.cs", startLine: 20, role: "sink" },
    ];
    await writeFindings(
      join(root, "results", "role-confused-evidence", "findings.json"),
      [confused],
    );

    const report = await evaluateBenchmark({
      manifestPath: join(root, "manifest.json"),
      resultsDirectory: join(root, "results"),
      requireRunStatus: false,
    });

    expect(report.passed).toBe(false);
    expect(report.metrics).toMatchObject({
      truePositives: 1,
      codeEvidenceRate: 0,
    });
    expect(report.cases[0]?.runs[0]?.matches[0]).toMatchObject({
      codeEvidencePresent: true,
      codeEvidenceSubstantive: false,
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
      requireRunStatus: false,
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
      requireRunStatus: false,
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

  test("rejects absolute, parent, sibling-prefix, and UNC result paths", async () => {
    const root = await fixtureRoot();
    const invalidPaths = [
      resolve(root, "outside", "findings.json"),
      "../outside/findings.json",
      "..\\results-backup\\findings.json",
      "case/../outside/findings.json",
      "\\\\server\\share\\findings.json",
    ];

    for (const findingsPath of invalidPaths) {
      await writeJson(join(root, "manifest.json"), {
        schemaVersion: "1.0",
        cases: [{ id: "escape", findingsPath, expected: [] }],
      });
      await expect(
        evaluateBenchmark({
          manifestPath: join(root, "manifest.json"),
          resultsDirectory: join(root, "results"),
          requireRunStatus: false,
        }),
      ).rejects.toThrow(
        "must be a normalized relative path beneath the benchmark results directory",
      );
    }
  });

  test("rejects a result path whose parent junction escapes the results directory", async () => {
    const root = await fixtureRoot();
    const results = join(root, "results");
    const outside = join(root, "outside-results");
    await mkdir(results, { recursive: true });
    await writeFindings(join(outside, "findings.json"), []);
    await symlink(
      outside,
      join(results, "pivot"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await writeJson(join(root, "manifest.json"), {
      schemaVersion: "1.0",
      cases: [
        {
          id: "junction-escape",
          findingsPath: "pivot/findings.json",
          expected: [],
        },
      ],
    });

    const report = await evaluateBenchmark({
      manifestPath: join(root, "manifest.json"),
      resultsDirectory: results,
      requireRunStatus: false,
    });

    expect(report.passed).toBe(false);
    expect(report.cases[0]?.runs[0]).toMatchObject({
      completed: false,
      passed: false,
    });
    expect(report.cases[0]?.runs[0]?.error).toContain(
      "findings parent escapes the benchmark results directory",
    );
  });

  test("rejects an oversized manifest before parsing it", async () => {
    const root = await fixtureRoot();
    const manifestPath = join(root, "oversized-manifest.json");
    await writeFile(manifestPath, "{");
    await truncate(manifestPath, 4 * 1024 * 1024 + 1);

    await expect(evaluateBenchmark({ manifestPath })).rejects.toThrow(
      "4194304-byte limit",
    );
  });

  test("evaluates committed legacy specialized manifests under their exact gates", async () => {
    const root = await fixtureRoot();
    await writeJson(join(root, "manifest.json"), {
      schemaVersion: "1.0",
      thresholds: {
        completionRate: 1,
        precision: 1,
        recall: 1,
        f1: 1,
        casePassRate: 1,
        negativeControlPassRate: 1,
        stableDetectionRate: 1,
        validationCoverage: 1,
        attackPathCoverage: 1,
        codeEvidenceCoverage: 1,
        severityAccuracy: 1,
        maxFalsePositivesPerRun: 0,
      },
      cases: [
        {
          id: "legacy-path",
          findingsPath: "legacy-path/findings.json",
          expected: [
            {
              title: "Legacy path traversal",
              cwe: ["CWE-22"],
              acceptableSeverities: ["critical", "high"],
              path: "document.go",
              line: 14,
              lineTolerance: 2,
              requireValidation: true,
              requireAttackPath: true,
              requireCodeEvidence: true,
            },
          ],
        },
        {
          id: "legacy-safe-path",
          findingsPath: "legacy-safe-path/findings.json",
          expected: [],
        },
      ],
    });
    await writeFindings(join(root, "results", "legacy-path", "findings.json"), [
      finding({
        id: "legacy-path",
        cwe: ["CWE-22"],
        path: "document.go",
        line: 14,
        validation: {
          method: "executable witness",
          summary: "A parent path reads the sibling secret.",
          assertions: ["The response contains the sibling secret."],
        },
        attackPath: {
          summary: "A remote query value reaches the filesystem read.",
          steps: ["Supply a parent path.", "Read the sibling file."],
        },
        codeEvidence: [
          {
            id: "filesystem-sink",
            label: "Request-derived file read",
            path: "document.go",
            startLine: 14,
            role: "sink",
            code: "os.ReadFile(filepath.Join(base, relative))",
            explanation: "The unchecked relative path reaches the read.",
          },
        ],
      }),
    ]);
    await writeFindings(
      join(root, "results", "legacy-safe-path", "findings.json"),
      [],
    );

    const report = await evaluateBenchmark({
      manifestPath: join(root, "manifest.json"),
      resultsDirectory: join(root, "results"),
      requireRunStatus: false,
    });
    expect(report.passed).toBe(true);
    expect(report.metrics).toMatchObject({
      truePositives: 1,
      falsePositives: 0,
      falseNegatives: 0,
      precision: 1,
      recall: 1,
      f1: 1,
      negativeCasePassRate: 1,
    });
    expect(report.cases[0]?.stableExpectations).toEqual([
      "legacy-expectation-1",
    ]);
    expect(report.thresholds).toHaveLength(12);
    expect(report.thresholds.every(({ passed }) => passed)).toBe(true);

    await writeJson(join(root, "manifest.json"), {
      schemaVersion: "1.0",
      thresholds: { precision: 1, minPrecision: 1 },
      cases: [],
    });
    await expect(
      evaluateBenchmark({ manifestPath: join(root, "manifest.json") }),
    ).rejects.toThrow("both minPrecision and legacy precision");

    await writeJson(join(root, "manifest.json"), {
      schemaVersion: "1.0",
      thresholds: { precision: null },
      cases: [],
    });
    await expect(
      evaluateBenchmark({ manifestPath: join(root, "manifest.json") }),
    ).rejects.toThrow("must be between 0 and 1");
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
      requireRunStatus: false,
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
        requireRunStatus: false,
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

  test("requires receipts by default and allows an explicit compatibility opt-out", async () => {
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
      requireRunStatus: false,
    });
    const receiptBound = await evaluateBenchmark({
      manifestPath: join(root, "manifest.json"),
      resultsDirectory: join(root, "results"),
    });

    expect(compatible.metrics.completedRuns).toBe(1);
    expect(receiptBound.metrics.completedRuns).toBe(0);
    expect(receiptBound.cases[0]?.runs[0]?.error).toContain(
      "Missing run status for benchmark case manual-control",
    );
  });

  test("gates seeded campaigns on exact sealed seed-coverage closure", async () => {
    const root = await fixtureRoot();
    const output = join(root, "results", "seeded-control", "run-1");
    const receiptPath = join(
      output,
      "artifacts",
      "03_coverage",
      "external_sarif_seed_coverage.json",
    );
    const expectation = {
      total: 1,
      inScope: 1,
      reportable: 0,
      rejected: 1,
      deferred: 0,
      outOfScope: 0,
    };
    await writeJson(join(root, "manifest.json"), {
      schemaVersion: "1.0",
      cases: [
        {
          id: "seeded-control",
          seedSarif: ["seed.sarif"],
          expectedSeedCoverage: expectation,
          findingsPath: "seeded-control/run-1/findings.json",
          expected: [],
        },
      ],
    });
    await writeFindings(join(output, "findings.json"), []);
    await writeJson(join(output, "coverage.json"), {
      surfaces: [
        {
          id: "external-sarif-seed-closure",
          receiptRefs: [
            "artifacts/03_coverage/external_sarif_seed_coverage.json",
          ],
        },
      ],
    });
    await writeJson(receiptPath, {
      documentType: "copilot-security.external-sarif-seed-coverage",
      schemaVersion: "1.0",
      summary: expectation,
      seeds: [
        {
          instance: "sarif-seed-00001",
          disposition: "rejected",
        },
      ],
    });
    const receiptSha256 = createHash("sha256")
      .update(await readFile(receiptPath))
      .digest("hex");
    await writeJson(join(output, "scan-manifest.json"), {
      scan: {
        artifacts: [
          {
            path: "artifacts/03_coverage/external_sarif_seed_coverage.json",
            sha256: receiptSha256,
          },
        ],
      },
    });

    const accepted = await evaluateBenchmark({
      manifestPath: join(root, "manifest.json"),
      resultsDirectory: join(root, "results"),
      requireRunStatus: false,
    });
    expect(accepted.passed).toBe(true);

    await writeJson(receiptPath, {
      documentType: "copilot-security.external-sarif-seed-coverage",
      schemaVersion: "1.0",
      summary: { ...expectation, rejected: 0, deferred: 1 },
      seeds: [
        {
          instance: "sarif-seed-00001",
          disposition: "deferred",
        },
      ],
    });
    const rejected = await evaluateBenchmark({
      manifestPath: join(root, "manifest.json"),
      resultsDirectory: join(root, "results"),
      requireRunStatus: false,
    });
    expect(rejected.passed).toBe(false);
    expect(rejected.cases[0]?.runs[0]?.error).toContain(
      "seed coverage rejected does not match",
    );

    await writeJson(join(root, "manifest.json"), {
      schemaVersion: "1.0",
      cases: [
        {
          id: "inconsistent-seed-gate",
          seedSarif: ["seed.sarif"],
          expectedSeedCoverage: { ...expectation, inScope: 0 },
          expected: [],
        },
      ],
    });
    await expect(
      evaluateBenchmark({ manifestPath: join(root, "manifest.json") }),
    ).rejects.toThrow("expectedSeedCoverage is inconsistent");
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
