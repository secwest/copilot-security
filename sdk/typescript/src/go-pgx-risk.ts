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
  maskGoLines,
  referencedTaint,
  requestSource,
  type GoCall,
  type GoFunction,
  type GoHttpSourceFile,
  type GoPropagator,
  type GoReceiverTypeSpecification,
  type GoTaint,
} from "./go-http-risk.js";

const CONTEXT_LINES_BEFORE = 4;
const CONTEXT_LINES_AFTER = 6;
const MAX_RECORDS = 64;
const PGX_IMPORT = "github.com/jackc/pgx/v5";
const PGXPOOL_IMPORT = "github.com/jackc/pgx/v5/pgxpool";

export interface GoPgxSqlInjectionRecord {
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
    id: "go-pgx-sql-injection";
    language: "go";
    scope: "same-file" | "cross-file-wrapper";
    source: { kind: string; path: string; line: number };
    sink: {
      kind:
        | "go-pgx-query-text"
        | "go-pgx-prepared-query-execution"
        | "go-pgx-batch-query-dispatch";
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

interface PgxAliases {
  pgx?: string;
  pgxpool?: string;
}

interface PgxSink {
  kind:
    | "go-pgx-query-text"
    | "go-pgx-prepared-query-execution"
    | "go-pgx-batch-query-dispatch";
  line: number;
  source: GoTaint;
  controls: Array<{ kind: string; line: number }>;
}

interface PgxPropagator extends GoPropagator {
  path?: string;
}

interface PreparedQuery {
  source: GoTaint;
  controls: Array<{ kind: string; line: number }>;
}

interface PendingBatchQuery {
  source?: GoTaint;
  preparedName?: string;
  line: number;
  controls: Array<{ kind: string; line: number }>;
}

interface WrapperSummary {
  file: GoHttpSourceFile;
  packageName: string;
  functionName: string;
  parameterName: string;
  parameterIndex: number;
  parameterLine: number;
  sink: PgxSink;
}

function pgxAliases(function_: GoFunction): PgxAliases {
  const pgx = goImportAlias(function_.file.lines, PGX_IMPORT, "pgx");
  const pgxpool = goImportAlias(
    function_.file.lines,
    PGXPOOL_IMPORT,
    "pgxpool",
  );
  return {
    ...(pgx === undefined ? {} : { pgx }),
    ...(pgxpool === undefined ? {} : { pgxpool }),
  };
}

function receiverSpecifications(
  aliases: PgxAliases,
): GoReceiverTypeSpecification[] {
  const specifications: GoReceiverTypeSpecification[] = [];
  if (aliases.pgx !== undefined) {
    specifications.push({ alias: aliases.pgx, typeNames: ["Conn", "Tx"] });
  }
  if (aliases.pgxpool !== undefined) {
    specifications.push({
      alias: aliases.pgxpool,
      typeNames: ["Pool", "Conn", "Tx"],
    });
  }
  return specifications;
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
  aliases: PgxAliases,
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
    if (
      aliases.pgx !== undefined &&
      new RegExp(
        `\\bAccessMode\\s*:\\s*${escapeRegularExpression(aliases.pgx)}\\.ReadOnly\\b`,
        "u",
      ).test(structural)
    ) {
      addControl(controls, "read-only-transaction", line);
    }
    if (
      aliases.pgx !== undefined &&
      new RegExp(
        `\\b${escapeRegularExpression(aliases.pgx)}\\.Identifier\\b[\\s\\S]*?\\.Sanitize\\s*\\(`,
        "u",
      ).test(structural)
    ) {
      addControl(controls, "pgx-identifier-sanitization", line);
    }
    if (
      aliases.pgx !== undefined &&
      new RegExp(
        `\\b${escapeRegularExpression(aliases.pgx)}\\.QueryExecModeSimpleProtocol\\b`,
        "u",
      ).test(structural)
    ) {
      addControl(controls, "pgx-simple-protocol-review", line);
    }
  }
  return controls.slice(0, 8);
}

function queryControls(
  base: readonly { kind: string; line: number }[],
  call: GoCall,
  queryPosition: number,
  aliases: PgxAliases,
): Array<{ kind: string; line: number }> {
  const controls = [...base];
  const pgxAlias = aliases.pgx;
  if (call.arguments.length > queryPosition + 1) {
    addControl(controls, "separate-query-arguments-present", call.line);
  }
  if (
    pgxAlias !== undefined &&
    call.rawArguments
      .slice(queryPosition + 1)
      .some((argument) =>
        new RegExp(
          `\\b${escapeRegularExpression(pgxAlias)}\\.(?:NamedArgs|StrictNamedArgs|StructArgs|StrictStructArgs)\\b`,
          "u",
        ).test(argument),
      )
  ) {
    addControl(controls, "pgx-parameter-rewriter-present", call.line);
  }
  return controls.slice(0, 8);
}

function goStringLiteralKey(expression: string): string | undefined {
  const trimmed = expression.trim();
  const interpreted = /^"([^"\\]*)"$/u.exec(trimmed);
  if (interpreted !== null) return `value:${interpreted[1]!}`;
  const raw = /^`([^`]*)`$/u.exec(trimmed);
  if (raw !== null) return `value:${raw[1]!}`;
  if (/^"(?:\\.|[^"\\])*"$/u.test(trimmed)) {
    return `literal:${trimmed}`;
  }
  return undefined;
}

function fixedStringAssignment(
  line: string,
): { name: string; value: string } | undefined {
  const match =
    /^\s*(?:const\s+|var\s+)?([A-Za-z_]\w*)(?:\s+string)?\s*(?::=|=)\s*((?:"(?:\\.|[^"\\])*"|`[^`]*`))\s*;?\s*$/u.exec(
      line,
    );
  if (match === null) return undefined;
  return { name: match[1]!, value: match[2]! };
}

function fixedStringKey(
  expression: string | undefined,
  fixedStrings: ReadonlyMap<string, string>,
): string | undefined {
  if (expression === undefined) return undefined;
  const literal = goStringLiteralKey(expression);
  if (literal !== undefined) return literal;
  const identifier = /^\s*([A-Za-z_]\w*)\s*$/u.exec(expression);
  return identifier === null ? undefined : fixedStrings.get(identifier[1]!);
}

function constructorCall(call: GoCall, aliases: PgxAliases): boolean {
  return (
    (aliases.pgx !== undefined &&
      new RegExp(
        `^${escapeRegularExpression(aliases.pgx)}\\.(?:Connect|ConnectConfig|ConnectWithOptions)$`,
        "u",
      ).test(call.name)) ||
    (aliases.pgxpool !== undefined &&
      new RegExp(
        `^${escapeRegularExpression(aliases.pgxpool)}\\.(?:New|NewWithConfig)$`,
        "u",
      ).test(call.name))
  );
}

function normalizeBatchArgument(
  expression: string | undefined,
): string | undefined {
  if (expression === undefined) return undefined;
  return /^\s*&?\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*$/u.exec(
    expression,
  )?.[1];
}

function analyzeFunction(
  function_: GoFunction,
  initialTaints: ReadonlyMap<string, GoTaint> = new Map(),
): PgxSink[] {
  const aliases = pgxAliases(function_);
  const specifications = receiverSpecifications(aliases);
  if (specifications.length === 0) return [];
  const requests = goHttpRequestParameters(function_);
  const staticReceivers = goTypedReceiverNames(function_, specifications);
  const batchSpecifications: GoReceiverTypeSpecification[] =
    aliases.pgx === undefined
      ? []
      : [{ alias: aliases.pgx, typeNames: ["Batch"] }];
  const staticBatches = goTypedReceiverNames(function_, batchSpecifications);
  const inferredReceivers = new Set<string>();
  const inferredBatches = new Set<string>();
  const taints = new Map(initialTaints);
  const fixedStrings = new Map<string, string>();
  const preparedQueries = new Map<string, PreparedQuery>();
  const pendingBatches = new Map<string, PendingBatchQuery[]>();
  const maps = fixedMapNames(function_);
  const controls = functionControls(function_, aliases);
  const rawLines = maskGoLines(function_.file.lines, false);
  const callsByLine = new Map<number, ReturnType<typeof goCalls>>();
  for (const call of goCalls(function_)) {
    const existing = callsByLine.get(call.line) ?? [];
    existing.push(call);
    callsByLine.set(call.line, existing);
  }
  const sinks: PgxSink[] = [];
  const receiverIsTyped = (receiver: string): boolean =>
    staticReceivers.has(receiver) || inferredReceivers.has(receiver);
  const batchIsTyped = (batch: string): boolean =>
    staticBatches.has(batch) || inferredBatches.has(batch);
  const clearPreparedReceiver = (receiver: string): void => {
    const prefix = `${receiver}\0`;
    for (const key of [...preparedQueries.keys()]) {
      if (key.startsWith(prefix)) preparedQueries.delete(key);
    }
  };

  for (
    let line = function_.bodyStartLine;
    line <= function_.endLine;
    line += 1
  ) {
    const structural = function_.structuralLines[line - 1] ?? "";
    const raw = rawLines[line - 1] ?? "";
    const assigned = goAssignment(structural);
    const rawAssigned = goAssignment(raw);
    const assignedNames = assigned?.names ?? rawAssigned?.names ?? [];
    if (assignedNames.length > 0) {
      const primary = assignedNames[0]!;
      const value = assigned?.value ?? rawAssigned?.value ?? "";
      const source = requestSource(value, requests, line);
      const prior = referencedTaint(value, taints);
      const fixedSelection = fixedMapSelection(value, maps, taints);
      for (const name of assignedNames) {
        taints.delete(name);
        fixedStrings.delete(name);
        inferredReceivers.delete(name);
        inferredBatches.delete(name);
        pendingBatches.delete(name);
        clearPreparedReceiver(name);
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
      if (
        aliases.pgx !== undefined &&
        new RegExp(
          `(?:&\\s*)?${escapeRegularExpression(aliases.pgx)}\\.Batch\\s*\\{|new\\s*\\(\\s*${escapeRegularExpression(aliases.pgx)}\\.Batch\\s*\\)`,
          "u",
        ).test(value)
      ) {
        inferredBatches.add(primary);
      }
    }
    const fixed = fixedStringAssignment(raw);
    if (fixed !== undefined) {
      const key = goStringLiteralKey(fixed.value);
      if (key !== undefined) fixedStrings.set(fixed.name, key);
    }

    for (const call of callsByLine.get(line) ?? []) {
      const result = assignedCallResult(call);
      if (constructorCall(call, aliases) && result !== undefined) {
        inferredReceivers.add(result);
        continue;
      }

      const receiverCall =
        /^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.([A-Za-z_]\w*)$/u.exec(call.name);
      if (receiverCall === null) continue;
      const receiver = receiverCall[1]!;
      const method = receiverCall[2]!;

      if (
        result !== undefined &&
        receiverIsTyped(receiver) &&
        /^(?:Acquire|Begin|BeginTx|Conn)$/u.test(method)
      ) {
        inferredReceivers.add(result);
        continue;
      }

      if (batchIsTyped(receiver) && method === "Queue") {
        const query = call.arguments[0];
        const source =
          query === undefined
            ? undefined
            : requestSource(query, requests, line) ??
              referencedTaint(query, taints)?.taint;
        const preparedName = fixedStringKey(call.rawArguments[0], fixedStrings);
        if (source !== undefined || preparedName !== undefined) {
          const queued = pendingBatches.get(receiver) ?? [];
          queued.push({
            ...(source === undefined ? {} : { source }),
            ...(preparedName === undefined ? {} : { preparedName }),
            line,
            controls: queryControls(controls, call, 0, aliases),
          });
          pendingBatches.set(receiver, queued);
        }
        continue;
      }

      if (!receiverIsTyped(receiver)) continue;
      if (method === "SendBatch") {
        const batch = normalizeBatchArgument(call.arguments[1]);
        if (batch === undefined || !batchIsTyped(batch)) continue;
        for (const pending of pendingBatches.get(batch) ?? []) {
          const prepared =
            pending.preparedName === undefined
              ? undefined
              : preparedQueries.get(`${receiver}\0${pending.preparedName}`);
          const source = pending.source ?? prepared?.source;
          if (source === undefined) continue;
          sinks.push({
            kind: "go-pgx-batch-query-dispatch",
            line,
            source: {
              ...source,
              propagators: [
                ...source.propagators,
                {
                  kind: "go-pgx-batch-queue",
                  line: pending.line,
                  symbol: batch,
                },
              ],
            },
            controls: [...(prepared?.controls ?? []), ...pending.controls]
              .filter(
                (control, index, all) =>
                  all.findIndex(
                    (candidate) =>
                      candidate.kind === control.kind &&
                      candidate.line === control.line,
                  ) === index,
              )
              .slice(0, 8),
          });
        }
        continue;
      }

      if (method === "Prepare") {
        const query = call.arguments[2];
        const source =
          query === undefined
            ? undefined
            : requestSource(query, requests, line) ??
              referencedTaint(query, taints)?.taint;
        const name = fixedStringKey(call.rawArguments[1], fixedStrings);
        if (source !== undefined && name !== undefined) {
          preparedQueries.set(`${receiver}\0${name}`, {
            source: {
              ...source,
              propagators: [
                ...source.propagators,
                {
                  kind: "go-pgx-statement-preparation",
                  line,
                  symbol: call.rawArguments[1]?.trim(),
                },
              ],
            },
            controls,
          });
        }
        continue;
      }

      if (!/^(?:Exec|Query|QueryRow)$/u.test(method)) continue;
      const query = call.arguments[1];
      if (query === undefined) continue;
      const directSource =
        requestSource(query, requests, line) ??
        referencedTaint(query, taints)?.taint;
      const preparedName = fixedStringKey(call.rawArguments[1], fixedStrings);
      const prepared =
        preparedName === undefined
          ? undefined
          : preparedQueries.get(`${receiver}\0${preparedName}`);
      const source = directSource ?? prepared?.source;
      if (source === undefined) continue;
      sinks.push({
        kind:
          directSource === undefined
            ? "go-pgx-prepared-query-execution"
            : "go-pgx-query-text",
        line,
        source,
        controls: queryControls(
          prepared?.controls ?? controls,
          call,
          1,
          aliases,
        ),
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
  const requests = goHttpRequestParameters(function_);
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
  sink: PgxSink,
  propagators: PgxPropagator[],
): GoPgxSqlInjectionRecord {
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
      "framework-dataflow:go-pgx-sql-injection",
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
      id: "go-pgx-sql-injection",
      language: "go",
      scope,
      source: { kind: source.kind, path: sourceFile.path, line: source.line },
      sink: {
        kind: sink.kind,
        path: sinkFile.path,
        line: sink.line,
        cweIds: ["CWE-89"],
      },
      propagators: propagators.map(({ path, ...propagator }) => ({
        ...propagator,
        path:
          path ??
          (propagator.kind === "go-function-argument"
            ? sourceFile.path
            : sinkFile.path),
      })),
      candidateControls: sink.controls.map((control) => ({
        ...control,
        path: sinkFile.path,
      })),
    },
  };
}

function supportsPgx(function_: GoFunction): boolean {
  const aliases = pgxAliases(function_);
  return aliases.pgx !== undefined || aliases.pgxpool !== undefined;
}

export function goPgxSqlInjectionRecords(
  files: readonly GoHttpSourceFile[],
): GoPgxSqlInjectionRecord[] {
  const functions = files
    .filter((file) => file.extension === ".go")
    .flatMap(goFunctions);
  const records: GoPgxSqlInjectionRecord[] = [];
  const emitted = new Set<string>();

  for (const function_ of functions) {
    if (goHttpRequestParameters(function_).length === 0) continue;
    for (const sink of analyzeFunction(function_)) {
      const identity = `${function_.file.path}:${sink.line}:${sink.kind}:${sink.source.line}:${sink.source.propagators
        .map((propagator) => `${propagator.kind}:${propagator.line}`)
        .join(",")}`;
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
    if (function_.receiver !== undefined || !supportsPgx(function_)) continue;
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
        const identity = `${caller.file.path}:${call.line}:${summary.file.path}:${summary.sink.line}:${summary.parameterIndex}:${summary.sink.kind}:${summary.sink.source.propagators
          .map((propagator) => `${propagator.kind}:${propagator.line}`)
          .join(",")}`;
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
              ...source.propagators.map((propagator) => ({
                ...propagator,
                path: caller.file.path,
              })),
              {
                kind: "go-function-argument",
                line: call.line,
                symbol: `${summary.functionName}[${summary.parameterIndex}]`,
                path: caller.file.path,
              },
              {
                kind: "go-string-parameter",
                line: summary.parameterLine,
                symbol: summary.parameterName,
                path: summary.file.path,
              },
              ...summary.sink.source.propagators.map((propagator) => ({
                ...propagator,
                path: summary.file.path,
              })),
            ],
          ),
        );
        if (records.length >= MAX_RECORDS) return records;
      }
    }
  }
  return records;
}
