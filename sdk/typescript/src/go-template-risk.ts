import { posix } from "node:path";
import {
  fixedMapNames,
  goAssignment,
  goCalls,
  goFunctions,
  goHttpRequestParameters,
  goImportAlias,
  referencedTaint,
  requestSource,
  type GoCall,
  type GoFunction,
  type GoHttpSourceFile,
  type GoPropagator,
  type GoTaint,
} from "./go-http-risk.js";

const CONTEXT_LINES_BEFORE = 5;
const CONTEXT_LINES_AFTER = 7;
const MAX_RECORDS = 64;

type GoTemplateSinkKind =
  | "go-text-template-execution"
  | "go-text-template-named-execution";

export interface GoTemplateInjectionRecord {
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
    id: "go-http-template-injection";
    language: "go";
    scope: "same-file" | "cross-file-wrapper";
    source: { kind: string; path: string; line: number };
    sink: {
      kind: GoTemplateSinkKind;
      path: string;
      line: number;
      cweIds: readonly ["CWE-1336"];
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

interface TemplateState {
  source: GoTaint;
  propagators: GoPropagator[];
}

interface TemplateSink {
  kind: GoTemplateSinkKind;
  line: number;
  source: GoTaint;
  propagators: GoPropagator[];
}

interface BuilderState {
  propagators: GoPropagator[];
}

interface WrapperSummary {
  file: GoHttpSourceFile;
  packageName: string;
  functionName: string;
  parameterName: string;
  parameterIndex: number;
  parameterLine: number;
  sink: TemplateSink;
}

function requestParameters(function_: GoFunction): string[] {
  return goHttpRequestParameters(function_);
}

function fixedTemplateSelection(
  expression: string,
  line: number,
  requests: readonly string[],
  maps: ReadonlySet<string>,
  taints: ReadonlyMap<string, GoTaint>,
): boolean {
  const selection = /^\s*([A-Za-z_]\w*)\s*\[([\s\S]+)\]\s*$/u.exec(expression);
  return (
    selection !== null &&
    maps.has(selection[1]!) &&
    (requestSource(selection[2]!, requests, line) !== undefined ||
      referencedTaint(selection[2]!, taints) !== undefined)
  );
}

function sourceFor(
  expression: string | undefined,
  line: number,
  requests: readonly string[],
  taints: ReadonlyMap<string, GoTaint>,
  maps: ReadonlySet<string>,
): GoTaint | undefined {
  if (
    expression === undefined ||
    fixedTemplateSelection(expression, line, requests, maps, taints)
  ) {
    return undefined;
  }
  return (
    requestSource(expression, requests, line) ??
    referencedTaint(expression, taints)?.taint
  );
}

function aliasShadowed(function_: GoFunction, alias: string): boolean {
  if (function_.parameters.some((parameter) => parameter.name === alias)) {
    return true;
  }
  for (
    let line = function_.bodyStartLine;
    line <= function_.endLine;
    line += 1
  ) {
    const assignment = goAssignment(function_.structuralLines[line - 1] ?? "");
    if (assignment?.names.includes(alias) === true) return true;
  }
  return false;
}

function callReceiver(call: GoCall, method: string): string | undefined {
  const match = new RegExp(`^([A-Za-z_]\\w*)\\.${method}$`, "u").exec(
    call.name,
  );
  return match?.[1];
}

function hasExactConstructor(expression: string, alias: string): boolean {
  const escaped = alias.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return new RegExp(`\\b${escaped}\\.New\\s*\\(`, "u").test(expression);
}

function hasCall(expression: string, method: string): boolean {
  return new RegExp(`\\.${method}\\s*\\(`, "u").test(expression);
}

function withAssignment(taint: GoTaint, line: number, symbol: string): GoTaint {
  return {
    ...taint,
    propagators: [
      ...taint.propagators,
      { kind: "go-string-assignment", line, symbol },
    ],
  };
}

function analyzeFunction(
  function_: GoFunction,
  initialTaints: ReadonlyMap<string, GoTaint> = new Map(),
): TemplateSink[] {
  const alias = goImportAlias(
    function_.file.lines,
    "text/template",
    "template",
  );
  if (alias === undefined || aliasShadowed(function_, alias)) return [];

  const requests = requestParameters(function_);
  const maps = fixedMapNames(function_);
  const taints = new Map(initialTaints);
  const builders = new Map<string, BuilderState>();
  const templates = new Map<string, TemplateState>();
  const callsByLine = new Map<number, GoCall[]>();
  for (const call of goCalls(function_)) {
    const calls = callsByLine.get(call.line) ?? [];
    calls.push(call);
    callsByLine.set(call.line, calls);
  }
  const sinks: TemplateSink[] = [];

  for (
    let line = function_.bodyStartLine;
    line <= function_.endLine;
    line += 1
  ) {
    const structural = function_.structuralLines[line - 1] ?? "";
    const assignment = goAssignment(structural);
    const calls = callsByLine.get(line) ?? [];
    const parseCalls = calls.filter(
      (call) => call.name === "Parse" || call.name.endsWith(".Parse"),
    );
    const assignmentParses =
      assignment !== undefined && hasCall(assignment.value, "Parse");
    let replacedTemplate: TemplateState | undefined;
    let replacedBuilder: BuilderState | undefined;

    if (assignment !== undefined) {
      const primary = assignment.names[0]!;
      replacedTemplate = templates.get(primary);
      replacedBuilder = builders.get(primary);
      const previousTemplate = templates.get(assignment.value.trim());
      const previousBuilder = builders.get(assignment.value.trim());
      const source = requestSource(assignment.value, requests, line);
      const prior = referencedTaint(assignment.value, taints);
      const fixedSelection = fixedTemplateSelection(
        assignment.value,
        line,
        requests,
        maps,
        taints,
      );
      for (const name of assignment.names) {
        taints.delete(name);
        templates.delete(name);
        builders.delete(name);
      }
      if (!fixedSelection && source !== undefined) taints.set(primary, source);
      else if (!fixedSelection && prior !== undefined) {
        taints.set(primary, withAssignment(prior.taint, line, primary));
      }
      if (previousTemplate !== undefined && !assignmentParses) {
        templates.set(primary, {
          ...previousTemplate,
          propagators: [
            ...previousTemplate.propagators,
            { kind: "go-template-object-alias", line, symbol: primary },
          ],
        });
      }
      if (previousBuilder !== undefined && !assignmentParses) {
        builders.set(primary, {
          propagators: [
            ...previousBuilder.propagators,
            { kind: "go-template-builder-alias", line, symbol: primary },
          ],
        });
      }
      const selfTemplateCall = new RegExp(
        `^\\s*${primary.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}\\.(?:Delims|Funcs|Option)\\s*\\(`,
        "u",
      ).test(assignment.value);
      if (selfTemplateCall && replacedBuilder !== undefined) {
        builders.set(primary, {
          propagators: [...replacedBuilder.propagators],
        });
      }
      if (selfTemplateCall && replacedTemplate !== undefined) {
        templates.set(primary, {
          ...replacedTemplate,
          propagators: [...replacedTemplate.propagators],
        });
      }
      if (hasExactConstructor(assignment.value, alias)) {
        builders.set(primary, {
          propagators: [
            {
              kind: "go-text-template-construction",
              line,
              symbol: `${alias}.New`,
            },
            ...(hasCall(assignment.value, "Funcs")
              ? [
                  {
                    kind: "go-template-function-map",
                    line,
                    symbol: "Funcs",
                  },
                ]
              : []),
          ],
        });
      }
    }

    for (const call of calls) {
      const funcsReceiver = callReceiver(call, "Funcs");
      if (funcsReceiver !== undefined) {
        const builder = builders.get(funcsReceiver);
        if (builder !== undefined) {
          builder.propagators.push({
            kind: "go-template-function-map",
            line,
            symbol: `${funcsReceiver}.Funcs`,
          });
        }
        const parsed = templates.get(funcsReceiver);
        if (parsed !== undefined) {
          parsed.propagators.push({
            kind: "go-template-function-map",
            line,
            symbol: `${funcsReceiver}.Funcs`,
          });
        }
      }
    }

    let directParsed: TemplateState | undefined;
    for (const call of parseCalls) {
      const receiver = callReceiver(call, "Parse");
      const parseExpression = assignment?.value ?? structural;
      const exactChain =
        hasExactConstructor(parseExpression, alias) && call.name === "Parse";
      const builder =
        receiver === undefined ? undefined : builders.get(receiver);
      const priorTemplate =
        receiver === undefined
          ? undefined
          : templates.get(receiver) ??
            (assignment?.names[0] === receiver ? replacedTemplate : undefined);
      const priorBuilder =
        builder ??
        (exactChain && assignment !== undefined
          ? builders.get(assignment.names[0]!)
          : undefined) ??
        (assignment?.names[0] === receiver ? replacedBuilder : undefined);
      if (
        !exactChain &&
        priorBuilder === undefined &&
        priorTemplate === undefined
      ) {
        continue;
      }
      const source = sourceFor(call.arguments[0], line, requests, taints, maps);
      if (source === undefined) continue;
      const capabilities = [
        ...(priorBuilder?.propagators ?? priorTemplate?.propagators ?? []),
      ];
      if (
        exactChain &&
        !capabilities.some(
          (propagator) => propagator.kind === "go-text-template-construction",
        )
      ) {
        capabilities.push({
          kind: "go-text-template-construction",
          line,
          symbol: `${alias}.New`,
        });
      }
      if (
        exactChain &&
        hasCall(parseExpression, "Funcs") &&
        !capabilities.some(
          (propagator) => propagator.kind === "go-template-function-map",
        )
      ) {
        capabilities.push({
          kind: "go-template-function-map",
          line,
          symbol: "Funcs",
        });
      }
      const parsed: TemplateState = {
        source,
        propagators: [
          ...capabilities,
          ...source.propagators,
          {
            kind: "go-template-source-parse",
            line,
            symbol: `${receiver ?? alias}.Parse[0] template source`,
          },
        ],
      };
      const result = assignment?.names[0] ?? receiver;
      if (result !== undefined) templates.set(result, parsed);
      if (receiver !== undefined) templates.set(receiver, parsed);
      directParsed = parsed;
    }

    for (const call of calls) {
      const executeReceiver = callReceiver(call, "Execute");
      const executeTemplateReceiver = callReceiver(call, "ExecuteTemplate");
      const kind: GoTemplateSinkKind | undefined =
        executeReceiver !== undefined || call.name === "Execute"
          ? "go-text-template-execution"
          : executeTemplateReceiver !== undefined ||
              call.name === "ExecuteTemplate"
            ? "go-text-template-named-execution"
            : undefined;
      if (kind === undefined) continue;
      const receiver = executeReceiver ?? executeTemplateReceiver;
      const parsed =
        receiver === undefined ? directParsed : templates.get(receiver);
      if (parsed === undefined) continue;
      const dataIndex = kind === "go-text-template-execution" ? 1 : 2;
      const data = call.rawArguments[dataIndex]?.trim();
      sinks.push({
        kind,
        line,
        source: parsed.source,
        propagators: [
          ...parsed.propagators,
          ...(data !== undefined && data !== "nil"
            ? [
                {
                  kind: "go-template-execution-data",
                  line,
                  symbol: `${call.name}[${dataIndex}]`,
                },
              ]
            : []),
          {
            kind: "go-template-execution",
            line,
            symbol: call.name,
          },
        ],
      });
    }
  }
  return sinks;
}

function callerSourceForArgument(
  function_: GoFunction,
  callLine: number,
  argument: string,
): GoTaint | undefined {
  const requests = requestParameters(function_);
  if (requests.length === 0) return undefined;
  const direct = requestSource(argument, requests, callLine);
  if (direct !== undefined) return direct;
  const taints = new Map<string, GoTaint>();
  const maps = fixedMapNames(function_);
  for (let line = function_.bodyStartLine; line < callLine; line += 1) {
    const assignment = goAssignment(function_.structuralLines[line - 1] ?? "");
    if (assignment === undefined) continue;
    const primary = assignment.names[0]!;
    const source = requestSource(assignment.value, requests, line);
    const prior = referencedTaint(assignment.value, taints);
    const fixedSelection = fixedTemplateSelection(
      assignment.value,
      line,
      requests,
      maps,
      taints,
    );
    for (const name of assignment.names) taints.delete(name);
    if (!fixedSelection && source !== undefined) taints.set(primary, source);
    else if (!fixedSelection && prior !== undefined) {
      taints.set(primary, withAssignment(prior.taint, line, primary));
    }
  }
  return referencedTaint(argument, taints)?.taint;
}

function excerpt(
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
  sourceFile: GoHttpSourceFile,
  sinkFile: GoHttpSourceFile,
  scope: "same-file" | "cross-file-wrapper",
  source: GoTaint,
  sink: TemplateSink,
  propagators: GoPropagator[],
): GoTemplateInjectionRecord {
  const startLine = Math.max(1, sink.line - CONTEXT_LINES_BEFORE);
  const endLine = Math.min(
    sinkFile.lines.length,
    sink.line + CONTEXT_LINES_AFTER,
  );
  const sourceStart = Math.max(1, source.line - 2);
  const sourceEnd = Math.min(sourceFile.lines.length, source.line + 2);
  return {
    path: sinkFile.path,
    line: sink.line,
    categories: [
      "framework-dataflow:go-http-template-injection",
      `modeled-source:${source.kind}`,
      `modeled-sink:${sink.kind}`,
    ],
    priority: 128,
    startLine,
    endLine,
    excerpt: excerpt(sinkFile.lines, startLine, endLine),
    sourceExcerpt: excerpt(sourceFile.lines, sourceStart, sourceEnd),
    frameworkModel: {
      schemaVersion: "1.2",
      id: "go-http-template-injection",
      language: "go",
      scope,
      source: { kind: source.kind, path: sourceFile.path, line: source.line },
      sink: {
        kind: sink.kind,
        path: sinkFile.path,
        line: sink.line,
        cweIds: ["CWE-1336"],
      },
      propagators: propagators.map((propagator) => ({
        ...propagator,
        path:
          propagator.kind === "go-function-argument"
            ? sourceFile.path
            : sinkFile.path,
      })),
      candidateControls: [],
    },
  };
}

export function goTemplateInjectionRecords(
  files: readonly GoHttpSourceFile[],
): GoTemplateInjectionRecord[] {
  const functions = files
    .filter((file) => file.extension === ".go")
    .flatMap(goFunctions);
  const records: GoTemplateInjectionRecord[] = [];
  const emitted = new Set<string>();

  for (const function_ of functions) {
    if (requestParameters(function_).length === 0) continue;
    for (const sink of analyzeFunction(function_)) {
      const identity = `${function_.file.path}:${sink.line}:${sink.kind}`;
      if (emitted.has(identity)) continue;
      emitted.add(identity);
      records.push(
        record(
          function_.file,
          function_.file,
          "same-file",
          sink.source,
          sink,
          sink.propagators,
        ),
      );
      if (records.length >= MAX_RECORDS) return records;
    }
  }

  const summaries: WrapperSummary[] = [];
  for (const function_ of functions) {
    if (function_.receiver !== undefined) continue;
    function_.parameters.forEach((parameter, parameterIndex) => {
      if (parameter.type.replace(/\s+/gu, "") !== "string") return;
      const initial = new Map<string, GoTaint>([
        [
          parameter.name,
          {
            kind: "go-string-parameter",
            line: function_.startLine,
            propagators: [],
          },
        ],
      ]);
      for (const sink of analyzeFunction(function_, initial)) {
        summaries.push({
          file: function_.file,
          packageName: function_.packageName,
          functionName: function_.name,
          parameterName: parameter.name,
          parameterIndex,
          parameterLine: function_.startLine,
          sink,
        });
      }
    });
  }

  const functionCounts = new Map<string, number>();
  for (const function_ of functions) {
    if (function_.receiver !== undefined) continue;
    const key = `${posix.dirname(function_.file.path)}\0${function_.packageName}\0${function_.name}`;
    functionCounts.set(key, (functionCounts.get(key) ?? 0) + 1);
  }
  for (const caller of functions) {
    const calls = goCalls(caller);
    for (const summary of summaries) {
      if (
        posix.dirname(summary.file.path) !== posix.dirname(caller.file.path) ||
        summary.packageName !== caller.packageName
      ) {
        continue;
      }
      const key = `${posix.dirname(summary.file.path)}\0${summary.packageName}\0${summary.functionName}`;
      if (functionCounts.get(key) !== 1) continue;
      for (const call of calls.filter(
        (candidate) => candidate.name === summary.functionName,
      )) {
        const argument = call.arguments[summary.parameterIndex];
        if (argument === undefined) continue;
        const source = callerSourceForArgument(caller, call.line, argument);
        if (source === undefined) continue;
        const identity = `${caller.file.path}:${call.line}:${summary.file.path}:${summary.sink.line}:${summary.parameterIndex}`;
        if (emitted.has(identity)) continue;
        emitted.add(identity);
        records.push(
          record(
            caller.file,
            summary.file,
            summary.file.path === caller.file.path
              ? "same-file"
              : "cross-file-wrapper",
            source,
            summary.sink,
            [
              ...source.propagators,
              {
                kind: "go-function-argument",
                line: call.line,
                symbol: `${summary.functionName}[${summary.parameterIndex}]`,
              },
              {
                kind: "go-string-parameter",
                line: summary.parameterLine,
                symbol: summary.parameterName,
              },
              ...summary.sink.propagators,
            ],
          ),
        );
        if (records.length >= MAX_RECORDS) return records;
      }
    }
  }
  return records;
}
