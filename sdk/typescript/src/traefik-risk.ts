import { posix } from "node:path";

import { parseDocument } from "yaml";

import type { GoHttpSourceFile } from "./go-http-risk.js";

const MAX_RECORDS = 32;
const CONTEXT_LINES_BEFORE = 4;
const CONTEXT_LINES_AFTER = 8;
const AUTH_MIDDLEWARE_KEYS = new Set([
  "basicAuth",
  "digestAuth",
  "forwardAuth",
]);

interface TraefikFileRuntime {
  composePath: string;
  imageLine: number;
  version: string;
  dynamicPath: string;
}

interface TraefikDockerRuntime {
  composePath: string;
  imageLine: number;
  version: string;
  exposedByDefault: boolean;
}

interface ComposeLabel {
  line: number;
  value: string;
}

interface TraefikRouter {
  name: string;
  prefix: string;
  service: string;
  middlewares: string[];
  entryPoints: string[];
  line: number;
}

export interface TraefikReplacePathRegexRecord {
  path: string;
  line: number;
  categories: string[];
  priority: number;
  startLine: number;
  endLine: number;
  excerpt: string;
  sourceExcerpt: string;
  frameworkModel: {
    schemaVersion: "1.2";
    id: "traefik-replacepathregex-auth-bypass";
    language: "traefik-yaml" | "traefik-compose-labels";
    scope: "cross-file";
    source: { kind: string; path: string; line: number; symbol: string };
    sink: {
      kind: "traefik-replacepathregex-prefix-rewrite";
      path: string;
      line: number;
      symbol: string;
      cweIds: readonly ["CWE-22"];
    };
    propagators: Array<{
      kind: string;
      path: string;
      line: number;
      symbol?: string;
    }>;
    candidateControls: [];
  };
}

function recordValue(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  return value as Record<string, unknown>;
}

function stringList(value: unknown): string[] | undefined {
  if (
    !Array.isArray(value) ||
    !value.every((entry) => typeof entry === "string")
  ) {
    return undefined;
  }
  return value;
}

function stringOrStringList(value: unknown): string[] | undefined {
  if (typeof value === "string") return [value];
  return stringList(value);
}

function yamlRoot(file: GoHttpSourceFile): Record<string, unknown> | undefined {
  if (file.extension !== ".yaml" && file.extension !== ".yml") return undefined;
  try {
    const document = parseDocument(file.text, { uniqueKeys: true });
    if (document.errors.length > 0 || document.warnings.length > 0) {
      return undefined;
    }
    return recordValue(document.toJS({ maxAliasCount: 0 }));
  } catch {
    return undefined;
  }
}

function escapeRegularExpression(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function excludedPath(path: string): boolean {
  return /(?:^|\/)(?:test|tests|testing|example|examples|vendor)(?:\/|$)/iu.test(
    path,
  );
}

function keyExpression(key: string): RegExp {
  const escaped = escapeRegularExpression(key);
  return new RegExp(`^\\s*(?:${escaped}|"${escaped}"|'${escaped}')\\s*:`, "u");
}

function keyLine(
  lines: readonly string[],
  key: string,
  afterLine = 1,
): number | undefined {
  const expression = keyExpression(key);
  for (
    let index = Math.max(0, afterLine - 1);
    index < lines.length;
    index += 1
  ) {
    if (expression.test(lines[index] ?? "")) return index + 1;
  }
  return undefined;
}

function childKeyLine(
  lines: readonly string[],
  parentLine: number | undefined,
  key: string,
): number | undefined {
  if (parentLine === undefined) return undefined;
  const parent = lines[parentLine - 1] ?? "";
  const parentIndent = /^\s*/u.exec(parent)?.[0].length ?? 0;
  const expression = keyExpression(key);
  let childIndent: number | undefined;
  for (let index = parentLine; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (/^\s*(?:#.*)?$/u.test(line)) continue;
    const indent = /^\s*/u.exec(line)?.[0].length ?? 0;
    if (indent <= parentIndent) return undefined;
    childIndent ??= indent;
    if (indent === childIndent && expression.test(line)) return index + 1;
  }
  return undefined;
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

function stableVersion(version: string): [number, number, number] | undefined {
  const match = /^(\d+)\.(\d+)\.(\d+)$/u.exec(version);
  if (match === null) return undefined;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function compareVersion(
  left: readonly [number, number, number],
  right: readonly [number, number, number],
): number {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index]! !== right[index]!) return left[index]! - right[index]!;
  }
  return 0;
}

function affectedVersion(version: string): boolean {
  const parsed = stableVersion(version);
  if (parsed === undefined) return false;
  if (parsed[0] === 2) return compareVersion(parsed, [2, 11, 51]) <= 0;
  if (parsed[0] !== 3) return false;
  if (compareVersion(parsed, [3, 6, 0]) < 0) return false;
  if (compareVersion(parsed, [3, 6, 22]) <= 0) return true;
  return (
    compareVersion(parsed, [3, 7, 0]) >= 0 &&
    compareVersion(parsed, [3, 7, 6]) <= 0
  );
}

function relativeVolumePath(value: string): string | undefined {
  const source = value.trim().replaceAll("\\", "/");
  if (
    source.startsWith("/") ||
    /^[A-Za-z]:/u.test(source) ||
    source.split("/").includes("..")
  ) {
    return undefined;
  }
  return source.startsWith("./") ? source.slice(2) : source;
}

function mountedVolumeSource(
  value: unknown,
  target: string,
): string | undefined {
  if (typeof value === "string") {
    const match = /^([^:]+):([^:]+)(?::(?:ro|rw))?$/u.exec(value.trim());
    if (match === null || match[2] !== target) return undefined;
    return relativeVolumePath(match[1]!);
  }
  const volume = recordValue(value);
  if (
    volume === undefined ||
    (volume["type"] !== undefined && volume["type"] !== "bind") ||
    typeof volume["source"] !== "string" ||
    volume["target"] !== target ||
    (volume["read_only"] !== undefined &&
      typeof volume["read_only"] !== "boolean")
  ) {
    return undefined;
  }
  return relativeVolumePath(volume["source"]);
}

function hasDockerSocketMount(value: unknown): boolean {
  if (!Array.isArray(value)) return false;
  return value.some((entry) => {
    if (typeof entry === "string") {
      return /^\/var\/run\/docker\.sock:\/var\/run\/docker\.sock(?::(?:ro|rw))?$/u.test(
        entry.trim(),
      );
    }
    const volume = recordValue(entry);
    return (
      volume !== undefined &&
      (volume["type"] === undefined || volume["type"] === "bind") &&
      volume["source"] === "/var/run/docker.sock" &&
      volume["target"] === "/var/run/docker.sock" &&
      (volume["read_only"] === undefined ||
        typeof volume["read_only"] === "boolean")
    );
  });
}

function fileRuntimes(
  files: readonly GoHttpSourceFile[],
): TraefikFileRuntime[] {
  const runtimes: TraefikFileRuntime[] = [];
  for (const file of files) {
    if (excludedPath(file.path)) continue;
    const root = yamlRoot(file);
    const services = recordValue(root?.["services"]);
    if (services === undefined) continue;
    const servicesLine = keyLine(file.lines, "services");
    for (const [serviceName, service] of Object.entries(services)) {
      const configuration = recordValue(service);
      if (configuration === undefined) continue;
      const image = configuration?.["image"];
      if (typeof image !== "string") continue;
      const imageMatch = /^traefik:v?(\d+\.\d+\.\d+)$/u.exec(image);
      if (imageMatch === null || !affectedVersion(imageMatch[1]!)) continue;
      const commands = stringOrStringList(configuration["command"]);
      const volumes = configuration["volumes"];
      if (commands === undefined || !Array.isArray(volumes)) continue;
      const provider = commands
        .map((command) => /^--providers\.file\.filename=(.+)$/u.exec(command))
        .find((match) => match !== null);
      if (provider === undefined || provider === null) continue;
      const source = volumes
        .map((volume) => mountedVolumeSource(volume, provider[1]!))
        .find((candidate) => candidate !== undefined);
      if (source === undefined || source === "") continue;
      const dynamicPath = posix.normalize(
        posix.join(posix.dirname(file.path), source),
      );
      if (dynamicPath === ".." || dynamicPath.startsWith("../")) continue;
      const serviceLine = childKeyLine(file.lines, servicesLine, serviceName);
      const imageLine = childKeyLine(file.lines, serviceLine, "image");
      if (imageLine === undefined) continue;
      runtimes.push({
        composePath: file.path,
        imageLine,
        version: imageMatch[1]!,
        dynamicPath,
      });
    }
  }
  return runtimes;
}

function dockerRuntimes(
  files: readonly GoHttpSourceFile[],
): TraefikDockerRuntime[] {
  const runtimes: TraefikDockerRuntime[] = [];
  for (const file of files) {
    if (excludedPath(file.path)) continue;
    const root = yamlRoot(file);
    const services = recordValue(root?.["services"]);
    if (services === undefined) continue;
    const servicesLine = keyLine(file.lines, "services");
    for (const [serviceName, rawService] of Object.entries(services)) {
      const service = recordValue(rawService);
      if (service === undefined) continue;
      const image = service["image"];
      if (typeof image !== "string") continue;
      const imageMatch = /^traefik:v?(\d+\.\d+\.\d+)$/u.exec(image);
      if (imageMatch === null || !affectedVersion(imageMatch[1]!)) continue;
      const commands = stringOrStringList(service["command"]);
      const exposureOptions = commands?.filter((command) =>
        command.startsWith("--providers.docker.exposedbydefault"),
      );
      if (
        commands === undefined ||
        !commands.some(
          (command) =>
            command === "--providers.docker" ||
            command === "--providers.docker=true",
        ) ||
        commands.includes("--providers.docker=false") ||
        exposureOptions?.some(
          (command) =>
            command !== "--providers.docker.exposedbydefault" &&
            command !== "--providers.docker.exposedbydefault=true" &&
            command !== "--providers.docker.exposedbydefault=false",
        ) ||
        commands.some(
          (command) =>
            command.startsWith("--providers.docker.constraints") ||
            command.startsWith("--providers.docker.swarmmode") ||
            (command.startsWith("--providers.docker.endpoint") &&
              command !==
                "--providers.docker.endpoint=unix:///var/run/docker.sock"),
        ) ||
        !hasDockerSocketMount(service["volumes"])
      ) {
        continue;
      }
      const serviceLine = childKeyLine(file.lines, servicesLine, serviceName);
      const imageLine = childKeyLine(file.lines, serviceLine, "image");
      if (imageLine === undefined) continue;
      runtimes.push({
        composePath: file.path,
        imageLine,
        version: imageMatch[1]!,
        exposedByDefault: !commands.includes(
          "--providers.docker.exposedbydefault=false",
        ),
      });
    }
  }
  return runtimes;
}

function pathPrefix(rule: unknown): string | undefined {
  if (typeof rule !== "string") return undefined;
  const match = /^PathPrefix\(`([^`]+)`\)$/u.exec(rule.trim());
  const prefix = match?.[1];
  if (
    prefix === undefined ||
    !prefix.startsWith("/") ||
    prefix === "/" ||
    prefix.endsWith("/") ||
    prefix.includes("..")
  ) {
    return undefined;
  }
  return prefix;
}

function routers(
  file: GoHttpSourceFile,
  value: Record<string, unknown>,
  routersLine: number | undefined,
): TraefikRouter[] {
  const result: TraefikRouter[] = [];
  for (const [name, raw] of Object.entries(value)) {
    const router = recordValue(raw);
    const prefix = pathPrefix(router?.["rule"]);
    const service = router?.["service"];
    const middlewares = stringList(router?.["middlewares"]);
    const entryPoints = stringList(router?.["entryPoints"]);
    const line = childKeyLine(file.lines, routersLine, name);
    if (
      prefix === undefined ||
      typeof service !== "string" ||
      service === "" ||
      middlewares === undefined ||
      middlewares.length === 0 ||
      entryPoints === undefined ||
      entryPoints.length === 0 ||
      line === undefined
    ) {
      continue;
    }
    result.push({ name, prefix, service, middlewares, entryPoints, line });
  }
  return result;
}

function hasAuthMiddleware(
  router: TraefikRouter,
  middlewares: Record<string, unknown>,
): boolean {
  return router.middlewares.some((name) => {
    const middleware = recordValue(middlewares[name]);
    if (middleware === undefined) return false;
    return Object.entries(middleware).some(([key, value]) => {
      if (!AUTH_MIDDLEWARE_KEYS.has(key)) return false;
      const configuration = recordValue(value);
      if (configuration === undefined) return false;
      if (key === "forwardAuth") {
        return (
          typeof configuration["address"] === "string" &&
          configuration["address"] !== ""
        );
      }
      const users = stringList(configuration["users"]);
      return (
        (users !== undefined && users.some((user) => user !== "")) ||
        (typeof configuration["usersFile"] === "string" &&
          configuration["usersFile"] !== "")
      );
    });
  });
}

function sameEntryPoint(left: TraefikRouter, right: TraefikRouter): boolean {
  return left.entryPoints.some((entryPoint) =>
    right.entryPoints.includes(entryPoint),
  );
}

function vulnerableRewrite(
  value: unknown,
  prefix: string,
): { regex: string; replacement: string } | undefined {
  const middleware = recordValue(value);
  const rewrite = recordValue(middleware?.["replacePathRegex"]);
  const regex = rewrite?.["regex"];
  const replacement = rewrite?.["replacement"];
  if (regex !== `^${prefix}(.*)` || replacement !== "/$1") {
    return undefined;
  }
  return { regex, replacement };
}

function recordsForRuntime(
  file: GoHttpSourceFile,
  runtime: TraefikFileRuntime,
): TraefikReplacePathRegexRecord[] {
  const root = yamlRoot(file);
  const http = recordValue(root?.["http"]);
  const routerMap = recordValue(http?.["routers"]);
  const middlewareMap = recordValue(http?.["middlewares"]);
  const services = recordValue(http?.["services"]);
  if (
    routerMap === undefined ||
    middlewareMap === undefined ||
    services === undefined
  ) {
    return [];
  }
  const httpLine = keyLine(file.lines, "http");
  const routersLine = childKeyLine(file.lines, httpLine, "routers");
  const middlewaresLine = childKeyLine(file.lines, httpLine, "middlewares");
  const configuredRouters = routers(file, routerMap, routersLine);
  const records: TraefikReplacePathRegexRecord[] = [];
  for (const publicRouter of configuredRouters) {
    if (publicRouter.middlewares.length !== 1) continue;
    const rewriteName = publicRouter.middlewares[0]!;
    const rewrite = vulnerableRewrite(
      middlewareMap[rewriteName],
      publicRouter.prefix,
    );
    if (rewrite === undefined || services[publicRouter.service] === undefined)
      continue;
    const protectedRouter = configuredRouters.find(
      (candidate) =>
        candidate.name !== publicRouter.name &&
        candidate.service === publicRouter.service &&
        candidate.prefix !== publicRouter.prefix &&
        sameEntryPoint(candidate, publicRouter) &&
        hasAuthMiddleware(candidate, middlewareMap),
    );
    if (protectedRouter === undefined) continue;
    const rewriteNameLine = childKeyLine(
      file.lines,
      middlewaresLine,
      rewriteName,
    );
    const sinkLine = childKeyLine(
      file.lines,
      rewriteNameLine,
      "replacePathRegex",
    );
    if (rewriteNameLine === undefined || sinkLine === undefined) continue;
    const startLine = Math.max(1, sinkLine - CONTEXT_LINES_BEFORE);
    const endLine = Math.min(file.lines.length, sinkLine + CONTEXT_LINES_AFTER);
    const sourceStart = Math.max(1, publicRouter.line - 1);
    const sourceEnd = Math.min(file.lines.length, protectedRouter.line + 6);
    records.push({
      path: file.path,
      line: sinkLine,
      categories: [
        "framework-dataflow:traefik-replacepathregex-auth-bypass",
        "modeled-source:public-traefik-prefix-router",
        "modeled-sink:traefik-replacepathregex-prefix-rewrite",
      ],
      priority: 138,
      startLine,
      endLine,
      excerpt: sourceExcerpt(file.lines, startLine, endLine),
      sourceExcerpt: sourceExcerpt(file.lines, sourceStart, sourceEnd),
      frameworkModel: {
        schemaVersion: "1.2",
        id: "traefik-replacepathregex-auth-bypass",
        language: "traefik-yaml",
        scope: "cross-file",
        source: {
          kind: "public-traefik-prefix-router",
          path: file.path,
          line: publicRouter.line,
          symbol: publicRouter.name,
        },
        sink: {
          kind: "traefik-replacepathregex-prefix-rewrite",
          path: file.path,
          line: sinkLine,
          symbol: rewriteName,
          cweIds: ["CWE-22"],
        },
        propagators: [
          {
            kind: "separator-free-prefix-capture",
            path: file.path,
            line: sinkLine,
            symbol: `${rewrite.regex} -> ${rewrite.replacement}`,
          },
          {
            kind: "shared-protected-backend",
            path: file.path,
            line: protectedRouter.line,
            symbol: `${protectedRouter.name}:${protectedRouter.prefix}`,
          },
          {
            kind: "affected-traefik-container",
            path: runtime.composePath,
            line: runtime.imageLine,
            symbol: `traefik@${runtime.version}:compose-image-exact:replacepathregex-auth-bypass`,
          },
        ],
        candidateControls: [],
      },
    });
  }
  return records;
}

function labelLine(
  lines: readonly string[],
  labelsLine: number | undefined,
  key: string,
): number | undefined {
  if (labelsLine === undefined) return undefined;
  const parent = lines[labelsLine - 1] ?? "";
  const parentIndent = /^\s*/u.exec(parent)?.[0].length ?? 0;
  const escaped = escapeRegularExpression(key);
  const expression = new RegExp(
    `^\\s*(?:-\\s*)?(?:"|')?${escaped}(?:=|(?:"|')?\\s*:)`,
    "iu",
  );
  for (let index = labelsLine; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (/^\s*(?:#.*)?$/u.test(line)) continue;
    const indent = /^\s*/u.exec(line)?.[0].length ?? 0;
    if (indent <= parentIndent) return undefined;
    if (expression.test(line)) return index + 1;
  }
  return undefined;
}

function composeLabels(
  file: GoHttpSourceFile,
  serviceName: string,
  service: Record<string, unknown>,
  servicesLine: number | undefined,
): Map<string, ComposeLabel> | undefined {
  const rawLabels = service["labels"];
  if (!Array.isArray(rawLabels) && recordValue(rawLabels) === undefined) {
    return undefined;
  }
  const serviceLine = childKeyLine(file.lines, servicesLine, serviceName);
  const labelsLine = childKeyLine(file.lines, serviceLine, "labels");
  if (labelsLine === undefined) return undefined;
  const entries: Array<[string, string]> = [];
  if (Array.isArray(rawLabels)) {
    for (const raw of rawLabels) {
      if (typeof raw !== "string") return undefined;
      const separator = raw.indexOf("=");
      if (separator < 1) {
        if (raw.trim().toLowerCase().startsWith("traefik.")) return undefined;
        continue;
      }
      entries.push([raw.slice(0, separator).trim(), raw.slice(separator + 1)]);
    }
  } else {
    for (const [key, raw] of Object.entries(recordValue(rawLabels)!)) {
      if (
        typeof raw !== "string" &&
        typeof raw !== "number" &&
        typeof raw !== "boolean"
      ) {
        if (key.toLowerCase().startsWith("traefik.")) return undefined;
        continue;
      }
      entries.push([key, String(raw)]);
    }
  }
  const labels = new Map<string, ComposeLabel>();
  for (const [rawKey, value] of entries) {
    const key = rawKey.toLowerCase();
    if (!key.startsWith("traefik.")) continue;
    if (labels.has(key)) return undefined;
    const line = labelLine(file.lines, labelsLine, rawKey);
    if (line === undefined) return undefined;
    labels.set(key, { line, value });
  }
  return labels;
}

function commaList(value: string | undefined): string[] | undefined {
  if (value === undefined || !concreteLabelValue(value)) return undefined;
  const entries = value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");
  return entries.length === 0 ? undefined : entries;
}

function dockerResourceName(value: string): string | undefined {
  if (!concreteLabelValue(value)) return undefined;
  const normalized = value.trim().toLowerCase();
  if (normalized.endsWith("@docker")) return normalized.slice(0, -7);
  return normalized.includes("@") || normalized === "" ? undefined : normalized;
}

function dockerRouters(
  labels: ReadonlyMap<string, ComposeLabel>,
): TraefikRouter[] {
  const names = [...labels.keys()]
    .map((key) => /^traefik\.http\.routers\.([^.]+)\.rule$/u.exec(key)?.[1])
    .filter((name): name is string => name !== undefined);
  const routers: TraefikRouter[] = [];
  for (const name of names) {
    const rule = labels.get(`traefik.http.routers.${name}.rule`)?.value;
    if (!concreteLabelValue(rule)) continue;
    const prefix = pathPrefix(rule);
    const service = dockerResourceName(
      labels.get(`traefik.http.routers.${name}.service`)?.value ?? "",
    );
    const middlewares = commaList(
      labels.get(`traefik.http.routers.${name}.middlewares`)?.value,
    )?.map(dockerResourceName);
    const entryPoints = commaList(
      labels.get(`traefik.http.routers.${name}.entrypoints`)?.value,
    );
    const line = labels.get(`traefik.http.routers.${name}.rule`)?.line;
    if (
      prefix === undefined ||
      service === undefined ||
      middlewares === undefined ||
      middlewares.some((middleware) => middleware === undefined) ||
      entryPoints === undefined ||
      line === undefined
    ) {
      continue;
    }
    routers.push({
      name,
      prefix,
      service,
      middlewares: middlewares as string[],
      entryPoints,
      line,
    });
  }
  return routers;
}

function concreteLabelValue(value: string | undefined): boolean {
  if (value === undefined || value.trim() === "") return false;
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== "$") continue;
    const next = value[index + 1];
    if (next === "$") {
      index += 1;
      continue;
    }
    if (next === "{" || (next !== undefined && /[A-Za-z_]/u.test(next))) {
      return false;
    }
  }
  return true;
}

function dockerAuthMiddleware(
  router: TraefikRouter,
  labels: ReadonlyMap<string, ComposeLabel>,
): boolean {
  return router.middlewares.some((name) => {
    const prefix = `traefik.http.middlewares.${name}`;
    const forwardAddress = labels.get(`${prefix}.forwardauth.address`)?.value;
    if (
      concreteLabelValue(forwardAddress) &&
      /^https?:\/\//iu.test(forwardAddress!.trim())
    ) {
      return true;
    }
    for (const type of ["basicauth", "digestauth"]) {
      if (concreteLabelValue(labels.get(`${prefix}.${type}.users`)?.value)) {
        return true;
      }
    }
    return false;
  });
}

function dockerServiceDefined(
  service: string,
  labels: ReadonlyMap<string, ComposeLabel>,
): boolean {
  const port = labels.get(
    `traefik.http.services.${service}.loadbalancer.server.port`,
  )?.value;
  if (port === undefined || !/^\d+$/u.test(port.trim())) return false;
  const number = Number(port);
  return number >= 1 && number <= 65_535;
}

function dockerRewrite(
  name: string,
  prefix: string,
  labels: ReadonlyMap<string, ComposeLabel>,
): { line: number; regex: string; replacement: string } | undefined {
  const base = `traefik.http.middlewares.${name}.replacepathregex`;
  const regexLabel = labels.get(`${base}.regex`);
  const replacement = labels.get(`${base}.replacement`)?.value;
  if (
    regexLabel?.value !== `^${prefix}(.*)` ||
    !["/$1", "/$$1", "/$${1}"].includes(replacement ?? "")
  ) {
    return undefined;
  }
  return { line: regexLabel.line, regex: regexLabel.value, replacement: "/$1" };
}

function dockerLabelRecords(
  file: GoHttpSourceFile,
  runtime: TraefikDockerRuntime,
): TraefikReplacePathRegexRecord[] {
  const root = yamlRoot(file);
  const services = recordValue(root?.["services"]);
  if (services === undefined) return [];
  const servicesLine = keyLine(file.lines, "services");
  const records: TraefikReplacePathRegexRecord[] = [];
  for (const [composeService, rawService] of Object.entries(services)) {
    const service = recordValue(rawService);
    if (service === undefined) continue;
    const labels = composeLabels(file, composeService, service, servicesLine);
    if (labels === undefined) continue;
    const enableLabel = labels.get("traefik.enable");
    const enable = enableLabel?.value.trim().toLowerCase();
    if (
      (enableLabel !== undefined && enable !== "true") ||
      (!runtime.exposedByDefault && enable !== "true")
    ) {
      continue;
    }
    const configuredRouters = dockerRouters(labels);
    for (const publicRouter of configuredRouters) {
      if (publicRouter.middlewares.length !== 1) continue;
      const rewriteName = publicRouter.middlewares[0]!;
      const rewrite = dockerRewrite(rewriteName, publicRouter.prefix, labels);
      if (
        rewrite === undefined ||
        !dockerServiceDefined(publicRouter.service, labels)
      ) {
        continue;
      }
      const protectedRouter = configuredRouters.find(
        (candidate) =>
          candidate.name !== publicRouter.name &&
          candidate.service === publicRouter.service &&
          candidate.prefix !== publicRouter.prefix &&
          sameEntryPoint(candidate, publicRouter) &&
          dockerAuthMiddleware(candidate, labels),
      );
      if (protectedRouter === undefined) continue;
      const startLine = Math.max(1, rewrite.line - CONTEXT_LINES_BEFORE);
      const endLine = Math.min(
        file.lines.length,
        rewrite.line + CONTEXT_LINES_AFTER,
      );
      const sourceStart = Math.max(
        1,
        Math.min(publicRouter.line, protectedRouter.line) - 1,
      );
      const sourceEnd = Math.min(
        file.lines.length,
        Math.max(publicRouter.line, protectedRouter.line) + 3,
      );
      records.push({
        path: file.path,
        line: rewrite.line,
        categories: [
          "framework-dataflow:traefik-replacepathregex-auth-bypass",
          "modeled-source:public-traefik-prefix-router",
          "modeled-sink:traefik-replacepathregex-prefix-rewrite",
        ],
        priority: 138,
        startLine,
        endLine,
        excerpt: sourceExcerpt(file.lines, startLine, endLine),
        sourceExcerpt: sourceExcerpt(file.lines, sourceStart, sourceEnd),
        frameworkModel: {
          schemaVersion: "1.2",
          id: "traefik-replacepathregex-auth-bypass",
          language: "traefik-compose-labels",
          scope: "cross-file",
          source: {
            kind: "public-traefik-prefix-router",
            path: file.path,
            line: publicRouter.line,
            symbol: publicRouter.name,
          },
          sink: {
            kind: "traefik-replacepathregex-prefix-rewrite",
            path: file.path,
            line: rewrite.line,
            symbol: rewriteName,
            cweIds: ["CWE-22"],
          },
          propagators: [
            {
              kind: "separator-free-prefix-capture",
              path: file.path,
              line: rewrite.line,
              symbol: `${rewrite.regex} -> ${rewrite.replacement}`,
            },
            {
              kind: "shared-protected-backend",
              path: file.path,
              line: protectedRouter.line,
              symbol: `${protectedRouter.name}:${protectedRouter.prefix}`,
            },
            {
              kind: "docker-provider-labeled-service",
              path: file.path,
              line: labels.get(
                `traefik.http.services.${publicRouter.service}.loadbalancer.server.port`,
              )!.line,
              symbol: composeService,
            },
            {
              kind: "affected-traefik-container",
              path: runtime.composePath,
              line: runtime.imageLine,
              symbol: `traefik@${runtime.version}:compose-image-exact:replacepathregex-auth-bypass`,
            },
          ],
          candidateControls: [],
        },
      });
    }
  }
  return records;
}

export function traefikReplacePathRegexRecords(
  files: readonly GoHttpSourceFile[],
): TraefikReplacePathRegexRecord[] {
  const byPath = new Map(files.map((file) => [file.path, file]));
  const records: TraefikReplacePathRegexRecord[] = [];
  const emitted = new Set<string>();
  for (const runtime of fileRuntimes(files)) {
    const dynamicFile = byPath.get(runtime.dynamicPath);
    if (dynamicFile === undefined || excludedPath(dynamicFile.path)) continue;
    for (const record of recordsForRuntime(dynamicFile, runtime)) {
      const identity = `${record.path}:${record.line}:${runtime.composePath}:${runtime.version}`;
      if (emitted.has(identity)) continue;
      emitted.add(identity);
      records.push(record);
      if (records.length >= MAX_RECORDS) return records;
    }
  }
  for (const runtime of dockerRuntimes(files)) {
    const composeFile = byPath.get(runtime.composePath);
    if (composeFile === undefined) continue;
    for (const record of dockerLabelRecords(composeFile, runtime)) {
      const identity = `${record.path}:${record.line}:${runtime.composePath}:${runtime.version}:docker`;
      if (emitted.has(identity)) continue;
      emitted.add(identity);
      records.push(record);
      if (records.length >= MAX_RECORDS) return records;
    }
  }
  return records;
}
