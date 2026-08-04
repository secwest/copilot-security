import { posix } from "node:path";
import {
  assignedCallResult,
  escapeRegularExpression,
  fixedMapNames,
  fixedMapSelection,
  goAssignment,
  goCalls,
  goFunctions,
  goHttpRequestParameters,
  goImportAlias,
  goTypedReceiverNames,
  referencedTaint,
  requestSource,
  type GoCall,
  type GoFunction,
  type GoHttpSourceFile,
  type GoPropagator,
  type GoTaint,
} from "./go-http-risk.js";

const CONTEXT_LINES_BEFORE = 4;
const CONTEXT_LINES_AFTER = 6;
const MAX_RECORDS = 64;
const GORM_IMPORT = "gorm.io/gorm";

type GormSinkKind =
  | "go-gorm-raw-sql-execution"
  | "go-gorm-query-clause-execution"
  | "go-gorm-inline-condition-execution"
  | "go-gorm-expression-sql-execution";

export interface GoGormSqlInjectionRecord {
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
    id: "go-gorm-sql-injection";
    language: "go";
    scope: "same-file" | "cross-file-wrapper";
    source: { kind: string; path: string; line: number };
    sink: {
      kind: GormSinkKind;
      path: string;
      line: number;
      cweIds: readonly ["CWE-89"];
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

interface GormSink {
  kind: GormSinkKind;
  line: number;
  source: GoTaint;
  controls: Array<{ kind: string; line: number }>;
}

interface GormRisk {
  kind: GormSinkKind;
  source: GoTaint;
  controls: Array<{ kind: string; line: number }>;
}

interface WrapperSummary {
  file: GoHttpSourceFile;
  packageName: string;
  functionName: string;
  parameterName: string;
  parameterIndex: number;
  parameterLine: number;
  sink: GormSink;
}

interface ParsedCall extends GoCall {
  endOffset: number;
}

interface FluentChain {
  endOffset: number;
  result?: string;
  risk?: GormRisk;
}

const CHAIN_GRAMMAR_METHODS = new Set([
  "Distinct",
  "Group",
  "Having",
  "InnerJoins",
  "Joins",
  "Not",
  "Or",
  "Order",
  "Raw",
  "Select",
  "Table",
  "Where",
]);

const CHAIN_DERIVER_METHODS = new Set([
  "Assign",
  "Attrs",
  "Clauses",
  "Debug",
  "InstanceSet",
  "Limit",
  "Model",
  "Offset",
  "Omit",
  "Preload",
  "Scopes",
  "Session",
  "Set",
  "Unscoped",
  "WithContext",
]);

const FINISHER_METHODS = new Set([
  "Count",
  "Create",
  "CreateInBatches",
  "Delete",
  "Find",
  "FindInBatches",
  "First",
  "FirstOrCreate",
  "FirstOrInit",
  "Last",
  "Pluck",
  "Row",
  "Rows",
  "Save",
  "Scan",
  "Take",
  "Update",
  "UpdateColumn",
  "UpdateColumns",
  "Updates",
]);

const INLINE_CONDITION_METHODS = new Set([
  "Delete",
  "Find",
  "First",
  "FirstOrCreate",
  "FirstOrInit",
  "Last",
  "Take",
]);

const BOUND_CONDITION_METHODS = new Set(["Having", "Not", "Or", "Where"]);
const MULTI_COLUMN_METHODS = new Set(["Distinct", "Select"]);
const EXPRESSION_VALUE_FINISHERS = new Set([
  "Create",
  "CreateInBatches",
  "Save",
  "Update",
  "UpdateColumn",
  "UpdateColumns",
  "Updates",
]);

function gormAlias(function_: GoFunction): string | undefined {
  return goImportAlias(function_.file.lines, GORM_IMPORT, "gorm");
}

function requestParameters(function_: GoFunction): string[] {
  return goHttpRequestParameters(function_);
}

function receiverDeclarationNames(
  function_: GoFunction,
  alias: string,
): Set<string> {
  return goTypedReceiverNames(function_, [{ alias, typeNames: ["DB"] }]);
}

function addControl(
  controls: Array<{ kind: string; line: number }>,
  kind: string,
  line: number,
): void {
  if (!controls.some((item) => item.kind === kind && item.line === line)) {
    controls.push({ kind, line });
  }
}

function functionControls(
  function_: GoFunction,
): Array<{ kind: string; line: number }> {
  const controls: Array<{ kind: string; line: number }> = [];
  for (let line = function_.startLine; line <= function_.endLine; line += 1) {
    const structural = function_.structuralLines[line - 1] ?? "";
    const original = function_.file.lines[line - 1] ?? "";
    if (
      /\b(?:strings\.)?Replace(?:All)?\s*\(/u.test(structural) &&
      /['"]/u.test(original)
    ) {
      addControl(controls, "manual-sql-escaping", line);
    }
    if (
      /\bregexp\.(?:MustCompile|Compile|MatchString)\s*\(/u.test(structural)
    ) {
      addControl(controls, "query-fragment-allowlist", line);
    }
    if (/\bcontext\.WithTimeout\s*\(/u.test(structural)) {
      addControl(controls, "query-deadline", line);
    }
    if (/\bDryRun\s*:\s*true\b/u.test(structural)) {
      addControl(controls, "gorm-dry-run-session", line);
    }
    if (/\bPrepareStmt\s*:\s*true\b/u.test(structural)) {
      addControl(controls, "gorm-prepared-statement-mode", line);
    }
    if (/\bAllowGlobalUpdate\s*:\s*false\b/u.test(structural)) {
      addControl(controls, "gorm-global-update-guard", line);
    }
  }
  return controls.slice(0, 8);
}

function matchingParenthesis(value: string, open: number): number {
  let depth = 0;
  for (let index = open; index < value.length; index += 1) {
    if (value[index] === "(") depth += 1;
    else if (value[index] === ")") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function parsedCalls(function_: GoFunction): {
  calls: ParsedCall[];
  structural: string;
} {
  const structural = function_.structuralLines
    .slice(function_.bodyStartLine - 1, function_.endLine)
    .join("\n");
  const calls = goCalls(function_).map((call): ParsedCall => {
    const open = structural.indexOf("(", call.offset + call.name.length);
    const close = open < 0 ? -1 : matchingParenthesis(structural, open);
    return { ...call, endOffset: close < 0 ? call.offset : close + 1 };
  });
  return { calls, structural };
}

function querySource(
  query: string,
  requests: readonly string[],
  taints: ReadonlyMap<string, GoTaint>,
  line: number,
): GoTaint | undefined {
  return (
    requestSource(query, requests, line) ??
    referencedTaint(query, taints)?.taint
  );
}

function boundConditionValue(
  expression: string,
  valueContainers: ReadonlySet<string>,
): boolean {
  const trimmed = expression.trim();
  if (/^[A-Za-z_]\w*$/u.test(trimmed) && valueContainers.has(trimmed)) {
    return true;
  }
  return /^(?:&\s*)?(?:map\s*\[[^\]]+\]\s*[A-Za-z_][\w.]*|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\{/u.test(
    trimmed,
  );
}

function risk(
  kind: GormSinkKind,
  source: GoTaint,
  controls: Array<{ kind: string; line: number }>,
  line: number,
  method: string,
): GormRisk {
  return {
    kind,
    source: {
      ...source,
      propagators: [
        ...source.propagators,
        { kind: "go-gorm-query-construction", line, symbol: method },
      ],
    },
    controls,
  };
}

function chainRisk(
  call: ParsedCall,
  method: string,
  requests: readonly string[],
  taints: ReadonlyMap<string, GoTaint>,
  valueContainers: ReadonlySet<string>,
  controls: Array<{ kind: string; line: number }>,
): GormRisk | undefined {
  const query = call.arguments[0];
  if (query === undefined) return undefined;
  const rawQuery = call.rawArguments[0] ?? query;
  if (
    BOUND_CONDITION_METHODS.has(method) &&
    boundConditionValue(query, valueContainers)
  ) {
    return undefined;
  }
  let source = querySource(query, requests, taints, call.line);
  let sourceArgument = 0;
  if (
    source === undefined &&
    MULTI_COLUMN_METHODS.has(method) &&
    call.arguments.length > 1
  ) {
    const placeholderCount = [...rawQuery].filter(
      (character) => character === "?",
    ).length;
    const laterArgumentsAreValues =
      placeholderCount >= call.arguments.length - 1 || rawQuery.includes("@");
    if (!laterArgumentsAreValues) {
      for (let index = 1; index < call.arguments.length; index += 1) {
        source = querySource(
          call.arguments[index]!,
          requests,
          taints,
          call.line,
        );
        if (source !== undefined) {
          sourceArgument = index;
          break;
        }
      }
    }
  }
  if (source === undefined) return undefined;
  const queryControls = [...controls];
  if (
    call.arguments.length > 1 &&
    sourceArgument === 0 &&
    (!MULTI_COLUMN_METHODS.has(method) ||
      rawQuery.includes("?") ||
      rawQuery.includes("@"))
  ) {
    addControl(queryControls, "gorm-bound-arguments-present", call.line);
  }
  return risk(
    method === "Raw"
      ? "go-gorm-raw-sql-execution"
      : "go-gorm-query-clause-execution",
    source,
    queryControls.slice(0, 8),
    call.line,
    method,
  );
}

function inlineConditionRisk(
  call: ParsedCall,
  method: string,
  requests: readonly string[],
  taints: ReadonlyMap<string, GoTaint>,
  valueContainers: ReadonlySet<string>,
  controls: Array<{ kind: string; line: number }>,
): GormRisk | undefined {
  const condition = call.arguments[1];
  if (condition === undefined) return undefined;
  if (boundConditionValue(condition, valueContainers)) return undefined;
  const source = querySource(condition, requests, taints, call.line);
  if (source === undefined) return undefined;
  const queryControls = [...controls];
  if (call.arguments.length > 2) {
    addControl(queryControls, "gorm-bound-arguments-present", call.line);
  }
  return risk(
    "go-gorm-inline-condition-execution",
    source,
    queryControls.slice(0, 8),
    call.line,
    method,
  );
}

function expressionRisk(
  call: ParsedCall,
  calls: readonly ParsedCall[],
  alias: string,
  requests: readonly string[],
  taints: ReadonlyMap<string, GoTaint>,
  expressions: ReadonlyMap<string, GoTaint>,
  controls: Array<{ kind: string; line: number }>,
  argumentStart = 1,
): GormRisk | undefined {
  for (const argument of call.arguments.slice(argumentStart)) {
    for (const [name, source] of expressions) {
      if (
        new RegExp(`\\b${escapeRegularExpression(name)}\\b`, "u").test(argument)
      ) {
        const queryControls = [...controls];
        addControl(queryControls, "gorm-expression-used-as-value", call.line);
        return risk(
          "go-gorm-expression-sql-execution",
          source,
          queryControls.slice(0, 8),
          call.line,
          "Expr",
        );
      }
    }
  }
  for (const nested of calls) {
    if (
      nested.offset <= call.offset ||
      nested.offset >= call.endOffset ||
      nested.name !== `${alias}.Expr`
    ) {
      continue;
    }
    const query = nested.arguments[0];
    if (query === undefined) continue;
    const source = querySource(query, requests, taints, nested.line);
    if (source === undefined) continue;
    const queryControls = [...controls];
    addControl(queryControls, "gorm-expression-used-as-value", call.line);
    return risk(
      "go-gorm-expression-sql-execution",
      source,
      queryControls.slice(0, 8),
      nested.line,
      "Expr",
    );
  }
  return undefined;
}

function sinksForRisk(risk_: GormRisk, line: number): GormSink {
  return {
    kind: risk_.kind,
    line,
    source: risk_.source,
    controls: risk_.controls,
  };
}

function analyzeFunction(
  function_: GoFunction,
  initialTaints: ReadonlyMap<string, GoTaint> = new Map(),
): GormSink[] {
  const alias = gormAlias(function_);
  if (alias === undefined) return [];
  const requests = requestParameters(function_);
  const staticReceivers = receiverDeclarationNames(function_, alias);
  const inferredReceivers = new Set<string>();
  const taints = new Map(initialTaints);
  const builders = new Map<string, GormRisk>();
  const expressions = new Map<string, GoTaint>();
  const valueContainers = new Set<string>();
  const maps = fixedMapNames(function_);
  const controls = functionControls(function_);
  const parsed = parsedCalls(function_);
  const callsByLine = new Map<number, ParsedCall[]>();
  for (const call of parsed.calls) {
    const existing = callsByLine.get(call.line) ?? [];
    existing.push(call);
    callsByLine.set(call.line, existing);
  }
  const sinks: GormSink[] = [];
  let pending: FluentChain | undefined;

  for (
    let line = function_.bodyStartLine;
    line <= function_.endLine;
    line += 1
  ) {
    const buildersBefore = new Map(builders);
    const receiversBefore = new Set(inferredReceivers);
    const structuralLine = function_.structuralLines[line - 1] ?? "";
    const assigned = goAssignment(structuralLine);
    const lineCalls = callsByLine.get(line) ?? [];
    const exactExpr = lineCalls.find((call) => call.name === `${alias}.Expr`);
    if (assigned !== undefined) {
      const primary = assigned.names[0]!;
      const transformedSource =
        exactExpr?.arguments[0] === undefined
          ? undefined
          : querySource(exactExpr.arguments[0], requests, taints, line);
      const source =
        exactExpr === undefined
          ? requestSource(assigned.value, requests, line)
          : transformedSource;
      const prior =
        exactExpr === undefined
          ? referencedTaint(assigned.value, taints)
          : transformedSource === undefined
            ? undefined
            : { name: primary, taint: transformedSource };
      const fixedSelection = fixedMapSelection(assigned.value, maps, taints);
      const isValueContainer = boundConditionValue(
        assigned.value,
        valueContainers,
      );
      for (const name of assigned.names) {
        taints.delete(name);
        builders.delete(name);
        expressions.delete(name);
        valueContainers.delete(name);
        inferredReceivers.delete(name);
      }
      if (isValueContainer) valueContainers.add(primary);
      if (!fixedSelection && source !== undefined) {
        taints.set(primary, source);
      } else if (!fixedSelection && prior !== undefined) {
        taints.set(primary, {
          ...prior.taint,
          propagators: [
            ...prior.taint.propagators,
            { kind: "go-string-assignment", line, symbol: primary },
          ],
        });
      }
    }

    const receiverIsTyped = (receiver: string): boolean =>
      staticReceivers.has(receiver) ||
      inferredReceivers.has(receiver) ||
      receiversBefore.has(receiver);
    const builderFor = (receiver: string): GormRisk | undefined =>
      builders.get(receiver) ?? buildersBefore.get(receiver);

    for (const call of lineCalls) {
      if (pending !== undefined && call.offset < pending.endOffset) {
        continue;
      }

      if (pending !== undefined) {
        const bridge = parsed.structural.slice(pending.endOffset, call.offset);
        const continuation =
          /^\s*\.\s*$/u.test(bridge) && /^[A-Za-z_]\w*$/u.test(call.name);
        if (continuation) {
          const method = call.name;
          if (CHAIN_GRAMMAR_METHODS.has(method)) {
            pending.risk =
              chainRisk(
                call,
                method,
                requests,
                taints,
                valueContainers,
                controls,
              ) ?? pending.risk;
            pending.endOffset = call.endOffset;
            if (pending.result !== undefined) {
              inferredReceivers.add(pending.result);
              if (pending.risk === undefined) builders.delete(pending.result);
              else builders.set(pending.result, pending.risk);
            }
            continue;
          }
          if (CHAIN_DERIVER_METHODS.has(method)) {
            pending.endOffset = call.endOffset;
            if (pending.result !== undefined) {
              inferredReceivers.add(pending.result);
              if (pending.risk !== undefined)
                builders.set(pending.result, pending.risk);
            }
            continue;
          }
          if (method === "Exec") {
            const direct = chainRisk(
              call,
              method,
              requests,
              taints,
              valueContainers,
              controls,
            );
            if (direct !== undefined) {
              direct.kind = "go-gorm-raw-sql-execution";
              sinks.push(sinksForRisk(direct, call.line));
            }
            const expression = expressionRisk(
              call,
              parsed.calls,
              alias,
              requests,
              taints,
              expressions,
              controls,
            );
            if (expression !== undefined)
              sinks.push(sinksForRisk(expression, call.line));
            if (pending.result !== undefined) builders.delete(pending.result);
            pending = undefined;
            continue;
          }
          if (FINISHER_METHODS.has(method)) {
            if (pending.risk !== undefined) {
              sinks.push(sinksForRisk(pending.risk, call.line));
            }
            if (INLINE_CONDITION_METHODS.has(method)) {
              const inline = inlineConditionRisk(
                call,
                method,
                requests,
                taints,
                valueContainers,
                controls,
              );
              if (inline !== undefined)
                sinks.push(sinksForRisk(inline, call.line));
            }
            if (method === "Pluck") {
              const pluck = chainRisk(
                call,
                method,
                requests,
                taints,
                valueContainers,
                controls,
              );
              if (pluck !== undefined)
                sinks.push(sinksForRisk(pluck, call.line));
            }
            if (EXPRESSION_VALUE_FINISHERS.has(method)) {
              const expression = expressionRisk(
                call,
                parsed.calls,
                alias,
                requests,
                taints,
                expressions,
                controls,
                0,
              );
              if (expression !== undefined) {
                sinks.push(sinksForRisk(expression, call.line));
              }
            }
            if (pending.result !== undefined) {
              inferredReceivers.add(pending.result);
              builders.delete(pending.result);
            }
            pending = undefined;
            continue;
          }
        }
        pending = undefined;
      }

      const result = assignedCallResult(call);
      if (call.name === `${alias}.Open` && result !== undefined) {
        inferredReceivers.add(result);
        continue;
      }
      if (call.name === `${alias}.Expr`) {
        if (result !== undefined && call.arguments[0] !== undefined) {
          const source = querySource(
            call.arguments[0],
            requests,
            taints,
            call.line,
          );
          if (source !== undefined) expressions.set(result, source);
        }
        continue;
      }

      const receiverCall =
        /^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.([A-Za-z_]\w*)$/u.exec(call.name);
      if (receiverCall === null) continue;
      const receiver = receiverCall[1]!;
      const method = receiverCall[2]!;
      if (!receiverIsTyped(receiver)) continue;
      const inherited = builderFor(receiver);

      if (method === "Exec") {
        const direct = chainRisk(
          call,
          method,
          requests,
          taints,
          valueContainers,
          controls,
        );
        if (direct !== undefined) {
          direct.kind = "go-gorm-raw-sql-execution";
          sinks.push(sinksForRisk(direct, call.line));
        }
        const expression = expressionRisk(
          call,
          parsed.calls,
          alias,
          requests,
          taints,
          expressions,
          controls,
        );
        if (expression !== undefined)
          sinks.push(sinksForRisk(expression, call.line));
        if (result !== undefined) inferredReceivers.add(result);
        continue;
      }

      if (FINISHER_METHODS.has(method)) {
        if (inherited !== undefined)
          sinks.push(sinksForRisk(inherited, call.line));
        if (INLINE_CONDITION_METHODS.has(method)) {
          const inline = inlineConditionRisk(
            call,
            method,
            requests,
            taints,
            valueContainers,
            controls,
          );
          if (inline !== undefined) sinks.push(sinksForRisk(inline, call.line));
        }
        if (method === "Pluck") {
          const pluck = chainRisk(
            call,
            method,
            requests,
            taints,
            valueContainers,
            controls,
          );
          if (pluck !== undefined) sinks.push(sinksForRisk(pluck, call.line));
        }
        if (EXPRESSION_VALUE_FINISHERS.has(method)) {
          const expression = expressionRisk(
            call,
            parsed.calls,
            alias,
            requests,
            taints,
            expressions,
            controls,
            0,
          );
          if (expression !== undefined) {
            sinks.push(sinksForRisk(expression, call.line));
          }
        }
        if (result !== undefined) inferredReceivers.add(result);
        continue;
      }

      if (CHAIN_GRAMMAR_METHODS.has(method)) {
        const nextRisk =
          chainRisk(
            call,
            method,
            requests,
            taints,
            valueContainers,
            controls,
          ) ?? inherited;
        if (result !== undefined) {
          inferredReceivers.add(result);
          if (nextRisk !== undefined) builders.set(result, nextRisk);
        }
        pending = {
          endOffset: call.endOffset,
          ...(result === undefined ? {} : { result }),
          ...(nextRisk === undefined ? {} : { risk: nextRisk }),
        };
        continue;
      }

      if (CHAIN_DERIVER_METHODS.has(method) || method === "Begin") {
        if (result !== undefined) {
          inferredReceivers.add(result);
          if (inherited !== undefined) builders.set(result, inherited);
        }
        pending = {
          endOffset: call.endOffset,
          ...(result === undefined ? {} : { result }),
          ...(inherited === undefined ? {} : { risk: inherited }),
        };
      }
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
    const assigned = goAssignment(function_.structuralLines[line - 1] ?? "");
    if (assigned === undefined) continue;
    const primary = assigned.names[0]!;
    const source = requestSource(assigned.value, requests, line);
    const prior = referencedTaint(assigned.value, taints);
    const fixedSelection = fixedMapSelection(assigned.value, maps, taints);
    for (const name of assigned.names) taints.delete(name);
    if (!fixedSelection && source !== undefined) taints.set(primary, source);
    else if (!fixedSelection && prior !== undefined) {
      taints.set(primary, {
        ...prior.taint,
        propagators: [
          ...prior.taint.propagators,
          { kind: "go-string-assignment", line, symbol: primary },
        ],
      });
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
  sink: GormSink,
  propagators: GoPropagator[],
): GoGormSqlInjectionRecord {
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
      "framework-dataflow:go-gorm-sql-injection",
      `modeled-source:${source.kind}`,
      `modeled-sink:${sink.kind}`,
      ...sink.controls.map((control) => `candidate-control:${control.kind}`),
    ],
    priority: 123,
    startLine,
    endLine,
    excerpt: excerpt(sinkFile.lines, startLine, endLine),
    sourceExcerpt: excerpt(sourceFile.lines, sourceStart, sourceEnd),
    frameworkModel: {
      schemaVersion: "1.2",
      id: "go-gorm-sql-injection",
      language: "go",
      scope,
      source: { kind: source.kind, path: sourceFile.path, line: source.line },
      sink: {
        kind: sink.kind,
        path: sinkFile.path,
        line: sink.line,
        cweIds: ["CWE-89"],
      },
      propagators: propagators.map((propagator) => ({
        ...propagator,
        path:
          propagator.kind === "go-function-argument"
            ? sourceFile.path
            : sinkFile.path,
      })),
      candidateControls: sink.controls.map((control) => ({
        ...control,
        path: sinkFile.path,
      })),
    },
  };
}

export function goGormSqlInjectionRecords(
  files: readonly GoHttpSourceFile[],
): GoGormSqlInjectionRecord[] {
  const functions = files
    .filter((file) => file.extension === ".go")
    .flatMap(goFunctions);
  const records: GoGormSqlInjectionRecord[] = [];
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
          sink.source.propagators,
        ),
      );
      if (records.length >= MAX_RECORDS) return records;
    }
  }

  const summaries: WrapperSummary[] = [];
  for (const function_ of functions) {
    if (function_.receiver !== undefined || gormAlias(function_) === undefined)
      continue;
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
              ...summary.sink.source.propagators,
            ],
          ),
        );
        if (records.length >= MAX_RECORDS) return records;
      }
    }
  }
  return records;
}
