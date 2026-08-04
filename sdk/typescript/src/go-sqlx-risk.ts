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
  referencedTaint,
  requestSource,
  goTypedReceiverNames,
  type GoFunction,
  type GoHttpSourceFile,
  type GoPropagator,
  type GoTaint,
} from "./go-http-risk.js";

const CONTEXT_LINES_BEFORE = 4;
const CONTEXT_LINES_AFTER = 6;
const MAX_RECORDS = 64;
const SQLX_IMPORT = "github.com/jmoiron/sqlx";

export interface GoSqlxSqlInjectionRecord {
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
    id: "go-sqlx-sql-injection";
    language: "go";
    scope: "same-file" | "cross-file-wrapper";
    source: { kind: string; path: string; line: number };
    sink: {
      kind: "go-sqlx-query-text" | "go-sqlx-prepared-query-execution";
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

interface SqlxSink {
  kind: "go-sqlx-query-text" | "go-sqlx-prepared-query-execution";
  line: number;
  source: GoTaint;
  controls: Array<{ kind: string; line: number }>;
}

interface PreparedQuery {
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
  sink: SqlxSink;
}

interface CallSignature {
  query: number;
  receiver?: number;
  prepare?: boolean;
}

function sqlxAlias(function_: GoFunction): string | undefined {
  return goImportAlias(function_.file.lines, SQLX_IMPORT, "sqlx");
}

function requestParameters(function_: GoFunction): string[] {
  return goHttpRequestParameters(function_);
}

function receiverDeclarationNames(
  function_: GoFunction,
  alias: string,
): Set<string> {
  return goTypedReceiverNames(function_, [
    { alias, typeNames: ["DB", "Tx", "Conn"] },
  ]);
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
  alias: string,
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
    if (/\bReadOnly\s*:\s*true\b/u.test(structural)) {
      addControl(controls, "read-only-transaction", line);
    }
    if (
      new RegExp(
        `(?:\\b${escapeRegularExpression(alias)}\\.(?:Rebind|BindNamed|Named)|\\b[A-Za-z_]\\w*(?:\\.[A-Za-z_]\\w*)*\\.(?:Rebind|BindNamed))\\s*\\(`,
        "u",
      ).test(structural)
    ) {
      addControl(controls, "sqlx-placeholder-rebinding", line);
    }
  }
  return controls.slice(0, 8);
}

function receiverSignature(method: string): CallSignature | undefined {
  if (
    /^(?:Exec|Query|QueryRow|Queryx|QueryRowx|MustExec|NamedExec|NamedQuery)$/u.test(
      method,
    )
  ) {
    return { query: 0 };
  }
  if (
    /^(?:ExecContext|QueryContext|QueryRowContext|QueryxContext|QueryRowxContext|MustExecContext|NamedExecContext|NamedQueryContext)$/u.test(
      method,
    )
  ) {
    return { query: 1 };
  }
  if (/^(?:Select|Get)$/u.test(method)) return { query: 1 };
  if (/^(?:SelectContext|GetContext)$/u.test(method)) return { query: 2 };
  if (/^(?:Prepare|Preparex|PrepareNamed)$/u.test(method)) {
    return { query: 0, prepare: true };
  }
  if (
    /^(?:PrepareContext|PreparexContext|PrepareNamedContext)$/u.test(method)
  ) {
    return { query: 1, prepare: true };
  }
  return undefined;
}

function packageSignature(functionName: string): CallSignature | undefined {
  if (/^(?:Select|Get)$/u.test(functionName)) {
    return { receiver: 0, query: 2 };
  }
  if (/^(?:MustExec|NamedExec|NamedQuery)$/u.test(functionName)) {
    return { receiver: 0, query: 1 };
  }
  if (/^(?:SelectContext|GetContext)$/u.test(functionName)) {
    return { receiver: 1, query: 3 };
  }
  if (
    /^(?:MustExecContext|NamedExecContext|NamedQueryContext)$/u.test(
      functionName,
    )
  ) {
    return { receiver: 1, query: 2 };
  }
  if (/^(?:Preparex|PrepareNamed)$/u.test(functionName)) {
    return { receiver: 0, query: 1, prepare: true };
  }
  if (/^(?:PreparexContext|PrepareNamedContext)$/u.test(functionName)) {
    return { receiver: 1, query: 2, prepare: true };
  }
  return undefined;
}

function statementExecutes(method: string): boolean {
  return /^(?:Exec|ExecContext|MustExec|MustExecContext|Query|QueryContext|QueryRow|QueryRowContext|Queryx|QueryxContext|QueryRowx|QueryRowxContext|Select|SelectContext|Get|GetContext)$/u.test(
    method,
  );
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

function preparedQuery(
  source: GoTaint,
  controls: Array<{ kind: string; line: number }>,
  line: number,
  symbol: string,
): PreparedQuery {
  return {
    source: {
      ...source,
      propagators: [
        ...source.propagators,
        { kind: "go-sqlx-statement-preparation", line, symbol },
      ],
    },
    controls,
  };
}

function analyzeFunction(
  function_: GoFunction,
  initialTaints: ReadonlyMap<string, GoTaint> = new Map(),
): SqlxSink[] {
  const alias = sqlxAlias(function_);
  if (alias === undefined) return [];
  const requests = requestParameters(function_);
  const staticReceivers = receiverDeclarationNames(function_, alias);
  const inferredReceivers = new Set<string>();
  const taints = new Map(initialTaints);
  const statements = new Map<string, PreparedQuery>();
  const maps = fixedMapNames(function_);
  const controls = functionControls(function_, alias);
  const callsByLine = new Map<number, ReturnType<typeof goCalls>>();
  for (const call of goCalls(function_)) {
    const existing = callsByLine.get(call.line) ?? [];
    existing.push(call);
    callsByLine.set(call.line, existing);
  }
  const sinks: SqlxSink[] = [];
  const receiverIsTyped = (receiver: string): boolean =>
    staticReceivers.has(receiver) || inferredReceivers.has(receiver);

  for (
    let line = function_.bodyStartLine;
    line <= function_.endLine;
    line += 1
  ) {
    const structural = function_.structuralLines[line - 1] ?? "";
    const assigned = goAssignment(structural);
    if (assigned !== undefined) {
      const primary = assigned.names[0]!;
      const namedTransform = (callsByLine.get(line) ?? []).find((call) => {
        if (
          new RegExp(
            `^${escapeRegularExpression(alias)}\\.(?:Named|BindNamed)$`,
            "u",
          ).test(call.name)
        ) {
          return true;
        }
        const receiverCall =
          /^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.BindNamed$/u.exec(call.name);
        return receiverCall !== null && receiverIsTyped(receiverCall[1]!);
      });
      const transformQueryIndex =
        namedTransform?.name === `${alias}.BindNamed` ? 1 : 0;
      const transformedSource =
        namedTransform === undefined ||
        namedTransform.arguments[transformQueryIndex] === undefined
          ? undefined
          : querySource(
              namedTransform.arguments[transformQueryIndex],
              requests,
              taints,
              line,
            );
      const source =
        namedTransform === undefined
          ? requestSource(assigned.value, requests, line)
          : transformedSource;
      const prior =
        namedTransform === undefined
          ? referencedTaint(assigned.value, taints)
          : transformedSource === undefined
            ? undefined
            : { name: primary, taint: transformedSource };
      const fixedSelection = fixedMapSelection(assigned.value, maps, taints);
      for (const name of assigned.names) {
        taints.delete(name);
        statements.delete(name);
        inferredReceivers.delete(name);
      }
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

    for (const call of callsByLine.get(line) ?? []) {
      const result = assignedCallResult(call);
      const packageCall = new RegExp(
        `^${escapeRegularExpression(alias)}\\.([A-Za-z_]\\w*)$`,
        "u",
      ).exec(call.name);
      if (packageCall !== null) {
        const functionName = packageCall[1]!;
        if (
          result !== undefined &&
          /^(?:Open|MustOpen|Connect|ConnectContext|MustConnect|MustConnectContext|NewDb)$/u.test(
            functionName,
          )
        ) {
          inferredReceivers.add(result);
          continue;
        }
        const signature = packageSignature(functionName);
        if (signature === undefined || signature.receiver === undefined)
          continue;
        const receiver = call.arguments[signature.receiver];
        if (receiver === undefined || !receiverIsTyped(receiver.trim()))
          continue;
        const query = call.arguments[signature.query];
        if (query === undefined) continue;
        const source = querySource(query, requests, taints, line);
        if (source === undefined) continue;
        const queryControls = [...controls];
        if (call.arguments.length > signature.query + 1) {
          addControl(queryControls, "separate-query-arguments-present", line);
        }
        if (signature.prepare) {
          if (result !== undefined) {
            statements.set(
              result,
              preparedQuery(source, queryControls.slice(0, 8), line, result),
            );
          }
          continue;
        }
        sinks.push({
          kind: "go-sqlx-query-text",
          line,
          source,
          controls: queryControls.slice(0, 8),
        });
        continue;
      }

      const receiverCall =
        /^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.([A-Za-z_]\w*)$/u.exec(call.name);
      if (receiverCall === null) continue;
      const receiver = receiverCall[1]!;
      const method = receiverCall[2]!;

      if (statements.has(receiver) && statementExecutes(method)) {
        const prepared = statements.get(receiver)!;
        sinks.push({
          kind: "go-sqlx-prepared-query-execution",
          line,
          source: prepared.source,
          controls: prepared.controls,
        });
        continue;
      }

      if (
        result !== undefined &&
        receiverIsTyped(receiver) &&
        /^(?:Beginx|BeginTxx|MustBegin|MustBeginTx|Connx|Unsafe)$/u.test(method)
      ) {
        inferredReceivers.add(result);
        continue;
      }

      if (
        result !== undefined &&
        receiverIsTyped(receiver) &&
        /^(?:Stmtx|NamedStmt|StmtxContext)$/u.test(method)
      ) {
        const sourceIndex = method === "StmtxContext" ? 1 : 0;
        const sourceStatement = call.arguments[sourceIndex]?.trim();
        if (sourceStatement !== undefined && statements.has(sourceStatement)) {
          const existing = statements.get(sourceStatement)!;
          statements.set(result, {
            ...existing,
            source: {
              ...existing.source,
              propagators: [
                ...existing.source.propagators,
                { kind: "go-sqlx-statement-transfer", line, symbol: result },
              ],
            },
          });
        }
        continue;
      }

      if (!receiverIsTyped(receiver)) continue;
      const signature = receiverSignature(method);
      if (signature === undefined) continue;
      const query = call.arguments[signature.query];
      if (query === undefined) continue;
      const source = querySource(query, requests, taints, line);
      if (source === undefined) continue;
      const queryControls = [...controls];
      if (call.arguments.length > signature.query + 1) {
        addControl(queryControls, "separate-query-arguments-present", line);
      }
      if (signature.prepare) {
        if (result !== undefined) {
          statements.set(
            result,
            preparedQuery(source, queryControls.slice(0, 8), line, result),
          );
        }
        continue;
      }
      sinks.push({
        kind: "go-sqlx-query-text",
        line,
        source,
        controls: queryControls.slice(0, 8),
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
  sink: SqlxSink,
  propagators: GoPropagator[],
): GoSqlxSqlInjectionRecord {
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
      "framework-dataflow:go-sqlx-sql-injection",
      `modeled-source:${source.kind}`,
      `modeled-sink:${sink.kind}`,
      ...sink.controls.map((control) => `candidate-control:${control.kind}`),
    ],
    priority: 122,
    startLine,
    endLine,
    excerpt: excerpt(sinkFile.lines, startLine, endLine),
    sourceExcerpt: excerpt(sourceFile.lines, sourceStart, sourceEnd),
    frameworkModel: {
      schemaVersion: "1.2",
      id: "go-sqlx-sql-injection",
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

export function goSqlxSqlInjectionRecords(
  files: readonly GoHttpSourceFile[],
): GoSqlxSqlInjectionRecord[] {
  const functions = files
    .filter((file) => file.extension === ".go")
    .flatMap(goFunctions);
  const records: GoSqlxSqlInjectionRecord[] = [];
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
    if (function_.receiver !== undefined || sqlxAlias(function_) === undefined)
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
