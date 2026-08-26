import { posix } from "node:path";

import {
  assignedCallResult,
  goCalls,
  goFunctions,
  goImportAlias,
  type GoCall,
  type GoFunction,
  type GoHttpSourceFile,
} from "./go-http-risk.js";

const CONTEXT_LINES_BEFORE = 5;
const CONTEXT_LINES_AFTER = 7;
const MAX_RECORDS = 32;
const ECHO_MODULES = [
  "github.com/labstack/echo/v5",
  "github.com/labstack/echo/v4",
  "github.com/labstack/echo",
] as const;

type EchoModule = (typeof ECHO_MODULES)[number];

interface EchoDependency {
  module: EchoModule;
  version: string;
  path: string;
  line: number;
}

interface ProtectedGroup {
  prefix: string;
  group: string;
  groupLine: number;
  middlewareLine: number;
  routeLine: number;
}

export interface GoEchoEncodedSeparatorRecord {
  path: string;
  line: number;
  categories: string[];
  priority: number;
  startLine: number;
  endLine: number;
  excerpt: string;
  sourceExcerpt?: string;
  frameworkModel: {
    schemaVersion: "1.2";
    id: "go-echo-static-encoded-separator-auth-bypass";
    language: "go";
    scope: "same-file";
    source: { kind: string; path: string; line: number };
    sink: {
      kind: "echo-root-static-file-handler";
      path: string;
      line: number;
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

function escapeRegularExpression(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function excludedPath(path: string): boolean {
  return (
    /(?:^|\/)(?:test|tests|testing|example|examples|vendor)(?:\/|$)/iu.test(
      path,
    ) || /(?:^|\/)[^/]+_test\.go$/iu.test(path)
  );
}

function literalPath(expression: string): string | undefined {
  const match = /^\s*(?:"([^"\\]*)"|`([^`]*)`)\s*$/u.exec(expression);
  return match?.[1] ?? match?.[2];
}

function isProtectedPrefix(prefix: string): boolean {
  return (
    prefix.startsWith("/") &&
    prefix !== "/" &&
    !prefix.includes(":") &&
    !prefix.includes("*") &&
    !prefix.includes("\\")
  );
}

function isWildcardGetRoute(call: GoCall, group: string): boolean {
  if (
    !new RegExp(`^${escapeRegularExpression(group)}\\.(?:GET|Any)$`, "u").test(
      call.name,
    )
  ) {
    return false;
  }
  const route = literalPath(call.rawArguments[0] ?? "");
  return route === "/*" && (call.rawArguments[1]?.trim().length ?? 0) > 0;
}

function hasMiddleware(arguments_: readonly string[]): boolean {
  return arguments_.some((argument) => {
    const value = argument.trim();
    return value !== "" && value !== "nil";
  });
}

function protectedGroups(
  calls: readonly GoCall[],
  instance: string,
): ProtectedGroup[] {
  const groups: ProtectedGroup[] = [];
  for (const call of calls) {
    if (call.name !== `${instance}.Group`) continue;
    const prefix = literalPath(call.rawArguments[0] ?? "");
    const group = assignedCallResult(call);
    if (
      prefix === undefined ||
      !isProtectedPrefix(prefix) ||
      group === undefined
    ) {
      continue;
    }
    const laterCalls = calls.filter((candidate) => candidate.line >= call.line);
    const inlineMiddleware = hasMiddleware(call.arguments.slice(1));
    const use = laterCalls.find(
      (candidate) =>
        candidate.name === `${group}.Use` && hasMiddleware(candidate.arguments),
    );
    if (!inlineMiddleware && use === undefined) continue;
    const middlewareLine = inlineMiddleware ? call.line : use!.line;
    const route = laterCalls.find(
      (candidate) =>
        candidate.line >= middlewareLine &&
        isWildcardGetRoute(candidate, group),
    );
    if (route === undefined) continue;
    groups.push({
      prefix,
      group,
      groupLine: call.line,
      middlewareLine,
      routeLine: route.line,
    });
  }
  return groups;
}

function rootStaticCalls(calls: readonly GoCall[], instance: string): GoCall[] {
  return calls.filter(
    (call) =>
      (call.name === `${instance}.Static` ||
        call.name === `${instance}.StaticFS`) &&
      literalPath(call.rawArguments[0] ?? "") === "/" &&
      (call.rawArguments[1]?.trim().length ?? 0) > 0,
  );
}

function serverStart(
  function_: GoFunction,
  calls: readonly GoCall[],
  instance: string,
  afterLine: number,
): GoCall | undefined {
  const direct = calls.find(
    (call) =>
      call.line > afterLine &&
      new RegExp(
        `^${escapeRegularExpression(instance)}\\.(?:Start|StartTLS|StartAutoTLS|StartServer|StartH2CServer)$`,
        "u",
      ).test(call.name),
  );
  if (direct !== undefined) return direct;
  const httpAlias = goImportAlias(function_.file.lines, "net/http", "http");
  if (httpAlias === undefined || httpAlias === "." || httpAlias === "_") {
    return undefined;
  }
  return calls.find(
    (call) =>
      call.line > afterLine &&
      new RegExp(
        `^${escapeRegularExpression(httpAlias)}\\.(?:ListenAndServe|ListenAndServeTLS)$`,
        "u",
      ).test(call.name) &&
      call.arguments.some((argument) => argument.trim() === instance),
  );
}

function stableBinding(
  function_: GoFunction,
  name: string,
  declarationLine: number,
  throughLine: number,
): boolean {
  const escaped = escapeRegularExpression(name);
  for (let line = declarationLine + 1; line <= throughLine; line += 1) {
    const structural = function_.structuralLines[line - 1] ?? "";
    if (new RegExp(`^\\s*${escaped}\\s*(?::=|=)`, "u").test(structural)) {
      return false;
    }
  }
  return true;
}

function moduleVersion(version: string): [number, number, number] | undefined {
  const match = /^v(\d+)\.(\d+)\.(\d+)(?:\+incompatible)?$/u.exec(version);
  if (match === null) return undefined;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function below(
  value: readonly [number, number, number],
  boundary: readonly [number, number, number],
): boolean {
  for (let index = 0; index < value.length; index += 1) {
    if (value[index]! < boundary[index]!) return true;
    if (value[index]! > boundary[index]!) return false;
  }
  return false;
}

function affectedVersion(module: EchoModule, version: string): boolean {
  const parsed = moduleVersion(version);
  if (parsed === undefined) return false;
  if (module === "github.com/labstack/echo/v5") {
    return parsed[0] === 5 && below(parsed, [5, 2, 0]);
  }
  if (module === "github.com/labstack/echo/v4") {
    return parsed[0] === 4 && below(parsed, [4, 15, 3]);
  }
  return parsed[0] <= 3 && (parsed[0] < 3 || !below([3, 3, 10], parsed));
}

function goModDependency(
  file: GoHttpSourceFile,
  files: readonly GoHttpSourceFile[],
  module: EchoModule,
): EchoDependency | undefined {
  const sourceDirectory = posix.dirname(file.path);
  const candidates = files
    .filter((candidate) => posix.basename(candidate.path) === "go.mod")
    .filter((candidate) => {
      const directory = posix.dirname(candidate.path);
      return (
        directory === "." ||
        sourceDirectory === directory ||
        sourceDirectory.startsWith(`${directory}/`)
      );
    })
    .sort((left, right) => right.path.length - left.path.length);
  const nearest = candidates[0];
  if (nearest === undefined) return undefined;

  let requireBlock = false;
  let replaceBlock = false;
  const requirements: Array<{ version: string; line: number }> = [];
  let replaced = false;
  const escapedModule = escapeRegularExpression(module);
  for (let index = 0; index < nearest.lines.length; index += 1) {
    const code = (nearest.lines[index] ?? "").replace(/\/\/.*$/u, "").trim();
    if (code === "") continue;
    if (/^require\s*\($/u.test(code)) {
      requireBlock = true;
      continue;
    }
    if (/^replace\s*\($/u.test(code)) {
      replaceBlock = true;
      continue;
    }
    if (code === ")") {
      requireBlock = false;
      replaceBlock = false;
      continue;
    }
    const requirement = new RegExp(
      `^(?:require\\s+)?${escapedModule}\\s+(v[^\\s]+)$`,
      "u",
    ).exec(code);
    if (
      (requireBlock || code.startsWith(`require ${module} `)) &&
      requirement !== null
    ) {
      requirements.push({ version: requirement[1]!, line: index + 1 });
    }
    if (
      (replaceBlock && new RegExp(`^${escapedModule}\\b`, "u").test(code)) ||
      new RegExp(`^replace\\s+${escapedModule}\\b`, "u").test(code)
    ) {
      replaced = true;
    }
  }
  if (replaced || requirements.length !== 1) return undefined;
  const requirement = requirements[0]!;
  if (!affectedVersion(module, requirement.version)) return undefined;
  return {
    module,
    version: requirement.version,
    path: nearest.path,
    line: requirement.line,
  };
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

function record(
  function_: GoFunction,
  constructor: GoCall,
  group: ProtectedGroup,
  staticCall: GoCall,
  start: GoCall,
  dependency: EchoDependency,
): GoEchoEncodedSeparatorRecord {
  const file = function_.file;
  const startLine = Math.max(1, staticCall.line - CONTEXT_LINES_BEFORE);
  const endLine = Math.min(
    file.lines.length,
    staticCall.line + CONTEXT_LINES_AFTER,
  );
  const sourceStart = Math.max(1, group.groupLine - 2);
  const sourceEnd = Math.min(file.lines.length, group.routeLine + 2);
  return {
    path: file.path,
    line: staticCall.line,
    categories: [
      "framework-dataflow:go-echo-static-encoded-separator-auth-bypass",
      "modeled-source:echo-protected-route-prefix",
      "modeled-sink:echo-root-static-file-handler",
    ],
    priority: 132,
    startLine,
    endLine,
    excerpt: sourceExcerpt(file.lines, startLine, endLine),
    sourceExcerpt: sourceExcerpt(file.lines, sourceStart, sourceEnd),
    frameworkModel: {
      schemaVersion: "1.2",
      id: "go-echo-static-encoded-separator-auth-bypass",
      language: "go",
      scope: "same-file",
      source: {
        kind: "echo-protected-route-prefix",
        path: file.path,
        line: group.groupLine,
      },
      sink: {
        kind: "echo-root-static-file-handler",
        path: file.path,
        line: staticCall.line,
        cweIds: ["CWE-22"],
      },
      propagators: [
        {
          kind: "official-echo-instance",
          path: file.path,
          line: constructor.line,
          symbol: assignedCallResult(constructor),
        },
        {
          kind: "middleware-protected-prefix",
          path: file.path,
          line: group.middlewareLine,
          symbol: group.prefix,
        },
        {
          kind: "protected-wildcard-get-route",
          path: file.path,
          line: group.routeLine,
          symbol: group.group,
        },
        {
          kind: "operational-echo-server",
          path: file.path,
          line: start.line,
          symbol: start.name,
        },
        {
          kind: "echo-runtime-dependency",
          path: dependency.path,
          line: dependency.line,
          symbol: `${dependency.module}@${dependency.version}:go-mod-exact:encoded-separator-static-auth-bypass`,
        },
      ],
      candidateControls: [],
    },
  };
}

export function goEchoEncodedSeparatorRecords(
  files: readonly GoHttpSourceFile[],
): GoEchoEncodedSeparatorRecord[] {
  const records: GoEchoEncodedSeparatorRecord[] = [];
  const emitted = new Set<string>();
  for (const file of files.filter(
    (candidate) =>
      candidate.extension === ".go" && !excludedPath(candidate.path),
  )) {
    for (const module of ECHO_MODULES) {
      const alias = goImportAlias(file.lines, module, "echo");
      if (alias === undefined || alias === "." || alias === "_") continue;
      const dependency = goModDependency(file, files, module);
      if (dependency === undefined) continue;
      for (const function_ of goFunctions(file)) {
        const calls = goCalls(function_);
        for (const constructor of calls.filter(
          (call) => call.name === `${alias}.New`,
        )) {
          const instance = assignedCallResult(constructor);
          if (instance === undefined) continue;
          const groups = protectedGroups(calls, instance);
          const staticCalls = rootStaticCalls(calls, instance);
          for (const group of groups) {
            for (const staticCall of staticCalls) {
              const lastRegistrationLine = Math.max(
                group.routeLine,
                staticCall.line,
              );
              const start = serverStart(
                function_,
                calls,
                instance,
                lastRegistrationLine,
              );
              if (
                start === undefined ||
                !stableBinding(
                  function_,
                  instance,
                  constructor.line,
                  start.line,
                ) ||
                !stableBinding(
                  function_,
                  group.group,
                  group.groupLine,
                  start.line,
                )
              ) {
                continue;
              }
              const identity = `${file.path}:${staticCall.line}:${module}:${dependency.version}`;
              if (emitted.has(identity)) continue;
              emitted.add(identity);
              records.push(
                record(
                  function_,
                  constructor,
                  group,
                  staticCall,
                  start,
                  dependency,
                ),
              );
              if (records.length >= MAX_RECORDS) return records;
            }
          }
        }
      }
    }
  }
  return records;
}
