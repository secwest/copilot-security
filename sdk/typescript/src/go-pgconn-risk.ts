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
const PGCONN_IMPORT = "github.com/jackc/pgx/v5/pgconn";
const PGX_IMPORT = "github.com/jackc/pgx/v5";
const PGXPOOL_IMPORT = "github.com/jackc/pgx/v5/pgxpool";

type PgconnSinkKind =
  | "go-pgconn-query-text"
  | "go-pgconn-copy-command"
  | "go-pgconn-prepared-query-execution"
  | "go-pgconn-batch-query-dispatch"
  | "go-pgconn-pipeline-query-dispatch";

export interface GoPgconnSqlInjectionRecord {
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
    id: "go-pgconn-sql-injection";
    language: "go";
    scope: "same-file" | "cross-file-wrapper";
    source: { kind: string; path: string; line: number };
    sink: {
      kind: PgconnSinkKind;
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

interface PgconnAliases {
  pgconn?: string;
  pgx?: string;
  pgxpool?: string;
}

interface PgconnSink {
  kind: PgconnSinkKind;
  line: number;
  source: GoTaint;
  controls: Array<{ kind: string; line: number }>;
}

interface PgconnPropagator extends GoPropagator {
  path?: string;
}

interface PreparedQuery {
  source: GoTaint;
  controls: Array<{ kind: string; line: number }>;
}

interface PendingQuery {
  source?: GoTaint;
  preparedName?: string;
  statementName?: string;
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
  sink: PgconnSink;
}

function pgconnAliases(function_: GoFunction): PgconnAliases {
  const pgconn = goImportAlias(function_.file.lines, PGCONN_IMPORT, "pgconn");
  const pgx = goImportAlias(function_.file.lines, PGX_IMPORT, "pgx");
  const pgxpool = goImportAlias(
    function_.file.lines,
    PGXPOOL_IMPORT,
    "pgxpool",
  );
  return {
    ...(pgconn === undefined ? {} : { pgconn }),
    ...(pgx === undefined ? {} : { pgx }),
    ...(pgxpool === undefined ? {} : { pgxpool }),
  };
}

function lowReceiverSpecifications(
  aliases: PgconnAliases,
): GoReceiverTypeSpecification[] {
  return aliases.pgconn === undefined
    ? []
    : [{ alias: aliases.pgconn, typeNames: ["PgConn"] }];
}

function pgxConnectionSpecifications(
  aliases: PgconnAliases,
): GoReceiverTypeSpecification[] {
  return aliases.pgx === undefined
    ? []
    : [{ alias: aliases.pgx, typeNames: ["Conn"] }];
}

function poolSpecifications(
  aliases: PgconnAliases,
): GoReceiverTypeSpecification[] {
  return aliases.pgxpool === undefined
    ? []
    : [{ alias: aliases.pgxpool, typeNames: ["Pool"] }];
}

function poolConnectionSpecifications(
  aliases: PgconnAliases,
): GoReceiverTypeSpecification[] {
  return aliases.pgxpool === undefined
    ? []
    : [{ alias: aliases.pgxpool, typeNames: ["Conn"] }];
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
    if (/\.[\s]*EscapeString\s*\(/u.test(structural)) {
      addControl(controls, "pgconn-escape-string", line);
    }
  }
  return controls.slice(0, 8);
}

function queryControls(
  base: readonly { kind: string; line: number }[],
  call: GoCall,
  queryPosition: number,
  parameterized: boolean,
): Array<{ kind: string; line: number }> {
  const controls = [...base];
  if (parameterized && call.arguments.length > queryPosition + 1) {
    addControl(controls, "separate-pgconn-parameter-bytes", call.line);
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

function normalizeIdentifier(
  expression: string | undefined,
): string | undefined {
  if (expression === undefined) return undefined;
  return /^\s*&?\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*$/u.exec(
    expression,
  )?.[1];
}

function lowConstructor(call: GoCall, aliases: PgconnAliases): boolean {
  return (
    aliases.pgconn !== undefined &&
    new RegExp(
      `^${escapeRegularExpression(aliases.pgconn)}\\.(?:Connect|ConnectConfig|ConnectWithOptions|Construct)$`,
      "u",
    ).test(call.name)
  );
}

function pgxConstructor(call: GoCall, aliases: PgconnAliases): boolean {
  return (
    aliases.pgx !== undefined &&
    new RegExp(
      `^${escapeRegularExpression(aliases.pgx)}\\.(?:Connect|ConnectConfig|ConnectWithOptions)$`,
      "u",
    ).test(call.name)
  );
}

function poolConstructor(call: GoCall, aliases: PgconnAliases): boolean {
  return (
    aliases.pgxpool !== undefined &&
    new RegExp(
      `^${escapeRegularExpression(aliases.pgxpool)}\\.(?:New|NewWithConfig)$`,
      "u",
    ).test(call.name)
  );
}

function analyzeFunction(
  function_: GoFunction,
  initialTaints: ReadonlyMap<string, GoTaint> = new Map(),
): PgconnSink[] {
  const aliases = pgconnAliases(function_);
  const lowSpecifications = lowReceiverSpecifications(aliases);
  const pgxConnectionTypes = pgxConnectionSpecifications(aliases);
  const poolTypes = poolSpecifications(aliases);
  const poolConnectionTypes = poolConnectionSpecifications(aliases);
  if (
    lowSpecifications.length === 0 &&
    pgxConnectionTypes.length === 0 &&
    poolTypes.length === 0 &&
    poolConnectionTypes.length === 0
  ) {
    return [];
  }

  const requests = goHttpRequestParameters(function_);
  const staticLowReceivers = goTypedReceiverNames(function_, lowSpecifications);
  const staticPgxConnections = goTypedReceiverNames(
    function_,
    pgxConnectionTypes,
  );
  const staticPools = goTypedReceiverNames(function_, poolTypes);
  const staticPoolConnections = goTypedReceiverNames(
    function_,
    poolConnectionTypes,
  );
  const batchSpecifications: GoReceiverTypeSpecification[] =
    aliases.pgconn === undefined
      ? []
      : [{ alias: aliases.pgconn, typeNames: ["Batch"] }];
  const pipelineSpecifications: GoReceiverTypeSpecification[] =
    aliases.pgconn === undefined
      ? []
      : [{ alias: aliases.pgconn, typeNames: ["Pipeline"] }];
  const statementSpecifications: GoReceiverTypeSpecification[] =
    aliases.pgconn === undefined
      ? []
      : [{ alias: aliases.pgconn, typeNames: ["StatementDescription"] }];
  const staticBatches = goTypedReceiverNames(function_, batchSpecifications);
  const staticPipelines = goTypedReceiverNames(
    function_,
    pipelineSpecifications,
  );
  const staticStatements = goTypedReceiverNames(
    function_,
    statementSpecifications,
  );
  const inferredLowReceivers = new Set<string>();
  const inferredPgxConnections = new Set<string>();
  const inferredPools = new Set<string>();
  const inferredPoolConnections = new Set<string>();
  const inferredBatches = new Set<string>();
  const inferredPipelines = new Set<string>();
  const inferredStatements = new Set<string>();
  const closedPipelines = new Set<string>();
  const pipelineOrigins = new Map<string, string>();
  const taints = new Map(initialTaints);
  const fixedStrings = new Map<string, string>();
  const preparedQueries = new Map<string, PreparedQuery>();
  const statementQueries = new Map<string, PreparedQuery>();
  const pendingBatches = new Map<string, PendingQuery[]>();
  const pendingPipelines = new Map<string, PendingQuery[]>();
  const maps = fixedMapNames(function_);
  const controls = functionControls(function_);
  const rawLines = maskGoLines(function_.file.lines, false);
  const callsByLine = new Map<number, ReturnType<typeof goCalls>>();
  for (const call of goCalls(function_)) {
    const existing = callsByLine.get(call.line) ?? [];
    existing.push(call);
    callsByLine.set(call.line, existing);
  }
  const sinks: PgconnSink[] = [];
  const lowReceiverIsTyped = (receiver: string): boolean =>
    staticLowReceivers.has(receiver) || inferredLowReceivers.has(receiver);
  const pgxConnectionIsTyped = (receiver: string): boolean =>
    staticPgxConnections.has(receiver) || inferredPgxConnections.has(receiver);
  const poolIsTyped = (receiver: string): boolean =>
    staticPools.has(receiver) || inferredPools.has(receiver);
  const poolConnectionIsTyped = (receiver: string): boolean =>
    staticPoolConnections.has(receiver) ||
    inferredPoolConnections.has(receiver);
  const batchIsTyped = (batch: string): boolean =>
    staticBatches.has(batch) || inferredBatches.has(batch);
  const pipelineIsTyped = (pipeline: string): boolean =>
    staticPipelines.has(pipeline) || inferredPipelines.has(pipeline);
  const statementIsTyped = (statement: string): boolean =>
    staticStatements.has(statement) || inferredStatements.has(statement);
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
        inferredLowReceivers.delete(name);
        inferredPgxConnections.delete(name);
        inferredPools.delete(name);
        inferredPoolConnections.delete(name);
        inferredBatches.delete(name);
        inferredPipelines.delete(name);
        inferredStatements.delete(name);
        closedPipelines.delete(name);
        pipelineOrigins.delete(name);
        statementQueries.delete(name);
        pendingBatches.delete(name);
        pendingPipelines.delete(name);
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
        aliases.pgconn !== undefined &&
        new RegExp(
          `(?:&\\s*)?${escapeRegularExpression(aliases.pgconn)}\\.Batch\\s*\\{|new\\s*\\(\\s*${escapeRegularExpression(aliases.pgconn)}\\.Batch\\s*\\)`,
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
      if (lowConstructor(call, aliases) && result !== undefined) {
        inferredLowReceivers.add(result);
        continue;
      }
      if (pgxConstructor(call, aliases) && result !== undefined) {
        inferredPgxConnections.add(result);
        continue;
      }
      if (poolConstructor(call, aliases) && result !== undefined) {
        inferredPools.add(result);
        continue;
      }

      const receiverCall =
        /^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.([A-Za-z_]\w*)$/u.exec(call.name);
      if (receiverCall === null) continue;
      const receiver = receiverCall[1]!;
      const method = receiverCall[2]!;

      if (
        result !== undefined &&
        poolIsTyped(receiver) &&
        method === "Acquire"
      ) {
        inferredPoolConnections.add(result);
        continue;
      }
      if (
        result !== undefined &&
        poolConnectionIsTyped(receiver) &&
        method === "Conn"
      ) {
        inferredPgxConnections.add(result);
        continue;
      }
      if (
        result !== undefined &&
        pgxConnectionIsTyped(receiver) &&
        method === "PgConn"
      ) {
        inferredLowReceivers.add(result);
        continue;
      }
      if (
        result !== undefined &&
        lowReceiverIsTyped(receiver) &&
        method === "StartPipeline"
      ) {
        inferredPipelines.add(result);
        pipelineOrigins.set(result, receiver);
        continue;
      }

      if (batchIsTyped(receiver)) {
        if (method === "ExecParams") {
          const query = call.arguments[0];
          const source =
            query === undefined
              ? undefined
              : requestSource(query, requests, line) ??
                referencedTaint(query, taints)?.taint;
          if (source !== undefined) {
            const queued = pendingBatches.get(receiver) ?? [];
            queued.push({
              source,
              line,
              controls: queryControls(controls, call, 0, true),
            });
            pendingBatches.set(receiver, queued);
          }
        } else if (method === "ExecPrepared") {
          const preparedName = fixedStringKey(
            call.rawArguments[0],
            fixedStrings,
          );
          if (preparedName !== undefined) {
            const queued = pendingBatches.get(receiver) ?? [];
            queued.push({ preparedName, line, controls });
            pendingBatches.set(receiver, queued);
          }
        } else if (method === "ExecStatement") {
          const statementName = normalizeIdentifier(call.arguments[0]);
          if (statementName !== undefined && statementIsTyped(statementName)) {
            const queued = pendingBatches.get(receiver) ?? [];
            queued.push({ statementName, line, controls });
            pendingBatches.set(receiver, queued);
          }
        }
        continue;
      }

      if (pipelineIsTyped(receiver)) {
        if (method === "Close") {
          pendingPipelines.delete(receiver);
          clearPreparedReceiver(receiver);
          closedPipelines.add(receiver);
        } else if (closedPipelines.has(receiver)) {
          continue;
        } else if (method === "SendPrepare") {
          const query = call.arguments[1];
          const source =
            query === undefined
              ? undefined
              : requestSource(query, requests, line) ??
                referencedTaint(query, taints)?.taint;
          const name = fixedStringKey(call.rawArguments[0], fixedStrings);
          if (source !== undefined && name !== undefined) {
            preparedQueries.set(`${receiver}\0${name}`, {
              source: {
                ...source,
                propagators: [
                  ...source.propagators,
                  {
                    kind: "go-pgconn-pipeline-statement-preparation",
                    line,
                    symbol: call.rawArguments[0]?.trim(),
                  },
                ],
              },
              controls,
            });
          }
        } else if (method === "SendQueryParams") {
          const query = call.arguments[0];
          const source =
            query === undefined
              ? undefined
              : requestSource(query, requests, line) ??
                referencedTaint(query, taints)?.taint;
          if (source !== undefined) {
            const queued = pendingPipelines.get(receiver) ?? [];
            queued.push({
              source,
              line,
              controls: queryControls(controls, call, 0, true),
            });
            pendingPipelines.set(receiver, queued);
          }
        } else if (method === "SendQueryPrepared") {
          const preparedName = fixedStringKey(
            call.rawArguments[0],
            fixedStrings,
          );
          if (preparedName !== undefined) {
            const queued = pendingPipelines.get(receiver) ?? [];
            queued.push({ preparedName, line, controls });
            pendingPipelines.set(receiver, queued);
          }
        } else if (method === "SendQueryStatement") {
          const statementName = normalizeIdentifier(call.arguments[0]);
          if (statementName !== undefined && statementIsTyped(statementName)) {
            const queued = pendingPipelines.get(receiver) ?? [];
            queued.push({ statementName, line, controls });
            pendingPipelines.set(receiver, queued);
          }
        } else if (/^(?:Flush|Sync)$/u.test(method)) {
          for (const pending of pendingPipelines.get(receiver) ?? []) {
            const origin = pipelineOrigins.get(receiver);
            const prepared =
              pending.preparedName === undefined
                ? undefined
                : preparedQueries.get(`${receiver}\0${pending.preparedName}`) ??
                  (origin === undefined
                    ? undefined
                    : preparedQueries.get(
                        `${origin}\0${pending.preparedName}`,
                      ));
            const statement =
              pending.statementName === undefined
                ? undefined
                : statementQueries.get(pending.statementName);
            const source =
              pending.source ?? prepared?.source ?? statement?.source;
            if (source === undefined) continue;
            sinks.push({
              kind: "go-pgconn-pipeline-query-dispatch",
              line,
              source: {
                ...source,
                propagators: [
                  ...source.propagators,
                  {
                    kind: "go-pgconn-pipeline-query-queue",
                    line: pending.line,
                    symbol: receiver,
                  },
                ],
              },
              controls: [
                ...(prepared?.controls ?? statement?.controls ?? []),
                ...pending.controls,
              ]
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
          pendingPipelines.delete(receiver);
        }
        continue;
      }

      if (!lowReceiverIsTyped(receiver)) continue;

      if (method === "Prepare") {
        const query = call.arguments[2];
        const source =
          query === undefined
            ? undefined
            : requestSource(query, requests, line) ??
              referencedTaint(query, taints)?.taint;
        const name = fixedStringKey(call.rawArguments[1], fixedStrings);
        if (source !== undefined) {
          const prepared: PreparedQuery = {
            source: {
              ...source,
              propagators: [
                ...source.propagators,
                {
                  kind: "go-pgconn-statement-preparation",
                  line,
                  symbol: call.rawArguments[1]?.trim(),
                },
              ],
            },
            controls,
          };
          if (name !== undefined) {
            preparedQueries.set(`${receiver}\0${name}`, prepared);
          }
          if (result !== undefined) {
            inferredStatements.add(result);
            statementQueries.set(result, prepared);
          }
        }
        continue;
      }

      if (method === "ExecBatch") {
        const batch = normalizeIdentifier(call.arguments[1]);
        if (batch === undefined || !batchIsTyped(batch)) continue;
        for (const pending of pendingBatches.get(batch) ?? []) {
          const prepared =
            pending.preparedName === undefined
              ? undefined
              : preparedQueries.get(`${receiver}\0${pending.preparedName}`);
          const statement =
            pending.statementName === undefined
              ? undefined
              : statementQueries.get(pending.statementName);
          const source =
            pending.source ?? prepared?.source ?? statement?.source;
          if (source === undefined) continue;
          sinks.push({
            kind: "go-pgconn-batch-query-dispatch",
            line,
            source: {
              ...source,
              propagators: [
                ...source.propagators,
                {
                  kind: "go-pgconn-batch-query-queue",
                  line: pending.line,
                  symbol: batch,
                },
              ],
            },
            controls: [
              ...(prepared?.controls ?? statement?.controls ?? []),
              ...pending.controls,
            ]
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

      if (method === "ExecPrepared") {
        const name = fixedStringKey(call.rawArguments[1], fixedStrings);
        const prepared =
          name === undefined
            ? undefined
            : preparedQueries.get(`${receiver}\0${name}`);
        if (prepared !== undefined) {
          sinks.push({
            kind: "go-pgconn-prepared-query-execution",
            line,
            source: prepared.source,
            controls: prepared.controls,
          });
        }
        continue;
      }

      if (method === "ExecStatement") {
        const statementName = normalizeIdentifier(call.arguments[1]);
        const prepared =
          statementName === undefined || !statementIsTyped(statementName)
            ? undefined
            : statementQueries.get(statementName);
        if (prepared !== undefined) {
          sinks.push({
            kind: "go-pgconn-prepared-query-execution",
            line,
            source: prepared.source,
            controls: prepared.controls,
          });
        }
        continue;
      }

      const queryPosition = /^(?:CopyFrom|CopyTo)$/u.test(method) ? 2 : 1;
      if (!/^(?:Exec|ExecParams|CopyFrom|CopyTo)$/u.test(method)) continue;
      const query = call.arguments[queryPosition];
      if (query === undefined) continue;
      const source =
        requestSource(query, requests, line) ??
        referencedTaint(query, taints)?.taint;
      if (source === undefined) continue;
      sinks.push({
        kind: /^(?:CopyFrom|CopyTo)$/u.test(method)
          ? "go-pgconn-copy-command"
          : "go-pgconn-query-text",
        line,
        source,
        controls: queryControls(
          controls,
          call,
          queryPosition,
          method === "ExecParams",
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
  sink: PgconnSink,
  propagators: PgconnPropagator[],
): GoPgconnSqlInjectionRecord {
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
      "framework-dataflow:go-pgconn-sql-injection",
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
      id: "go-pgconn-sql-injection",
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

function supportsPgconn(function_: GoFunction): boolean {
  const aliases = pgconnAliases(function_);
  return (
    aliases.pgconn !== undefined ||
    aliases.pgx !== undefined ||
    aliases.pgxpool !== undefined
  );
}

export function goPgconnSqlInjectionRecords(
  files: readonly GoHttpSourceFile[],
): GoPgconnSqlInjectionRecord[] {
  const functions = files
    .filter((file) => file.extension === ".go")
    .flatMap(goFunctions);
  const records: GoPgconnSqlInjectionRecord[] = [];
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
    if (function_.receiver !== undefined || !supportsPgconn(function_))
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
