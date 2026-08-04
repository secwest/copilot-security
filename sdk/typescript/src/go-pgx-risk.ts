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
  splitGoArguments,
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
        | "go-pgx-batch-query-dispatch"
        | "go-pgx-query-rewriter-dispatch";
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
    | "go-pgx-batch-query-dispatch"
    | "go-pgx-query-rewriter-dispatch";
  line: number;
  source: GoTaint;
  controls: Array<{ kind: string; line: number }>;
  supportingPath?: string;
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
  supportingPath?: string;
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

interface QueryRewriterReturnFlow {
  fieldName: string;
  line: number;
  propagators: PgxPropagator[];
}

interface QueryRewriterSummary {
  directory: string;
  packageName: string;
  typeName: string;
  pointerReceiver: boolean;
  methodFile: GoHttpSourceFile;
  inputSqlFlow?: { line: number; propagators: PgxPropagator[] };
  returnFlows: ReadonlyMap<string, QueryRewriterReturnFlow>;
}

interface QueryRewriterInstance {
  summary: QueryRewriterSummary;
  isPointer: boolean;
  fieldSources: Map<string, { source: GoTaint; line: number }>;
}

interface ResolvedQueryRewriter {
  instance: QueryRewriterInstance;
  source?: GoTaint;
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

function normalizedGoType(value: string): string {
  return value.replace(/\s+/gu, "");
}

function exactQueryRewriterSignature(
  function_: GoFunction,
  pgxAlias: string,
  contextAlias: string,
): boolean {
  if (function_.parameters.length !== 4) return false;
  const actual = function_.parameters.map((parameter) =>
    normalizedGoType(parameter.type),
  );
  const expected = [`${contextAlias}.Context`, `*${pgxAlias}.Conn`, "string"];
  if (
    actual.slice(0, 3).some((type, index) => type !== expected[index]) ||
    !/^(?:\[\]any|\[\]interface\{\})$/u.test(actual[3] ?? "")
  ) {
    return false;
  }
  return /^\(\s*(?:[A-Za-z_]\w*\s+)?string\s*,\s*(?:[A-Za-z_]\w*\s+)?\[\s*\](?:any|interface\s*\{\s*\})\s*,\s*(?:[A-Za-z_]\w*\s+)?error\s*\)$/u.test(
    function_.returnSignature,
  );
}

function structFieldsByType(
  files: readonly GoHttpSourceFile[],
): Map<string, { count: number; fields: Set<string> }> {
  const result = new Map<string, { count: number; fields: Set<string> }>();
  for (const file of files.filter(
    (candidate) => candidate.extension === ".go",
  )) {
    const structural = maskGoLines(file.lines, true).join("\n");
    const package_ = /^\s*package\s+([A-Za-z_]\w*)\b/mu.exec(structural)?.[1];
    if (package_ === undefined) continue;
    for (const match of structural.matchAll(
      /\btype\s+([A-Za-z_]\w*)\s+struct\s*\{([\s\S]*?)\}/gu,
    )) {
      const key = `${posix.dirname(file.path)}\0${package_}\0${match[1]!}`;
      const fields = new Set<string>();
      for (const line of match[2]!.split("\n")) {
        const field = /^\s*([A-Za-z_]\w*)\s+[^\s}]/u.exec(line)?.[1];
        if (field !== undefined) fields.add(field);
      }
      const existing = result.get(key);
      result.set(key, {
        count: (existing?.count ?? 0) + 1,
        fields: new Set([...(existing?.fields ?? []), ...fields]),
      });
    }
  }
  return result;
}

function returnValues(
  lines: readonly string[],
  startLine: number,
  endLine: number,
): string[] | undefined {
  let value = "";
  for (
    let line = startLine;
    line <= Math.min(endLine, startLine + 15);
    line += 1
  ) {
    const current = lines[line - 1] ?? "";
    if (line === startLine) {
      const match = /\breturn\s+([\s\S]+)$/u.exec(current);
      if (match === null) return undefined;
      value = match[1]!;
    } else {
      value += `\n${current}`;
    }
    const normalized = value
      .replace(/\s*;\s*$/u, "")
      .replace(/\s*\}\s*$/u, "")
      .trim();
    const values = splitGoArguments(normalized);
    if (values.length === 3) return values;
  }
  return undefined;
}

function firstReturnedSqlExpression(
  function_: GoFunction,
  line: number,
): string | undefined {
  const values = returnValues(
    function_.structuralLines,
    line,
    function_.endLine,
  );
  if (values !== undefined) return values[0];
  const structural = function_.structuralLines[line - 1] ?? "";
  if (!/\breturn\s*(?:;|\}|$)/u.test(structural)) return undefined;
  return /^\(\s*([A-Za-z_]\w*)\s+string\b/u.exec(
    function_.returnSignature,
  )?.[1];
}

function queryRewriterReturnFlows(
  function_: GoFunction,
  receiverName: string,
  fields: ReadonlySet<string>,
): Map<string, QueryRewriterReturnFlow> {
  const flows = new Map<string, QueryRewriterReturnFlow>();
  const rawLines = maskGoLines(function_.file.lines, false);
  for (const fieldName of fields) {
    const receiverField = `${receiverName}.${fieldName}`;
    const taints = new Map<string, GoTaint>([
      [
        receiverField,
        {
          kind: "go-query-rewriter-field",
          line: function_.startLine,
          propagators: [
            {
              kind: "go-pgx-query-rewriter-receiver-field",
              line: function_.startLine,
              symbol: `${function_.receiver}.${fieldName}`,
              path: function_.file.path,
            } as PgxPropagator,
          ],
        },
      ],
    ]);
    for (
      let line = function_.bodyStartLine;
      line <= function_.endLine;
      line += 1
    ) {
      const structural = function_.structuralLines[line - 1] ?? "";
      const raw = rawLines[line - 1] ?? "";
      const assigned = goAssignment(structural) ?? goAssignment(raw);
      if (assigned !== undefined) {
        const prior = referencedTaint(assigned.value, taints);
        for (const name of assigned.names) {
          taints.delete(name);
          if (name === receiverName) {
            for (const key of [...taints.keys()]) {
              if (key.startsWith(`${receiverName}.`)) taints.delete(key);
            }
          }
        }
        if (prior !== undefined) {
          taints.set(assigned.names[0]!, {
            ...prior.taint,
            propagators: [
              ...prior.taint.propagators,
              {
                kind: "go-string-assignment",
                line,
                symbol: assigned.names[0]!,
                path: function_.file.path,
              } as PgxPropagator,
            ],
          });
        }
      }
      if (
        new RegExp(
          `^\\s*${escapeRegularExpression(receiverField)}\\s*=`,
          "u",
        ).test(structural)
      ) {
        taints.delete(receiverField);
      }
      const returnedSql = firstReturnedSqlExpression(function_, line);
      if (returnedSql === undefined) continue;
      const returned = referencedTaint(returnedSql, taints);
      if (returned === undefined) continue;
      flows.set(fieldName, {
        fieldName,
        line,
        propagators: [
          ...(returned.taint.propagators as PgxPropagator[]),
          {
            kind: "go-pgx-query-rewriter-returned-sql",
            line,
            symbol: returnedSql.trim(),
            path: function_.file.path,
          },
        ],
      });
      break;
    }
  }
  return flows;
}

function queryRewriterInputSqlFlow(
  function_: GoFunction,
): { line: number; propagators: PgxPropagator[] } | undefined {
  const inputName = function_.parameters[2]?.name;
  if (inputName === undefined || inputName === "_") return undefined;
  const taints = new Map<string, GoTaint>([
    [
      inputName,
      {
        kind: "go-query-rewriter-input-sql",
        line: function_.startLine,
        propagators: [
          {
            kind: "go-pgx-query-rewriter-input-sql",
            line: function_.startLine,
            symbol: inputName,
            path: function_.file.path,
          } as PgxPropagator,
        ],
      },
    ],
  ]);
  const rawLines = maskGoLines(function_.file.lines, false);
  for (
    let line = function_.bodyStartLine;
    line <= function_.endLine;
    line += 1
  ) {
    const structural = function_.structuralLines[line - 1] ?? "";
    const raw = rawLines[line - 1] ?? "";
    const assigned = goAssignment(structural) ?? goAssignment(raw);
    if (assigned !== undefined) {
      const prior = referencedTaint(assigned.value, taints);
      for (const name of assigned.names) taints.delete(name);
      if (prior !== undefined) {
        taints.set(assigned.names[0]!, {
          ...prior.taint,
          propagators: [
            ...prior.taint.propagators,
            {
              kind: "go-string-assignment",
              line,
              symbol: assigned.names[0]!,
              path: function_.file.path,
            } as PgxPropagator,
          ],
        });
      }
    }
    const returnedSql = firstReturnedSqlExpression(function_, line);
    if (returnedSql === undefined) continue;
    const returned = referencedTaint(returnedSql, taints);
    if (returned === undefined) continue;
    return {
      line,
      propagators: [
        ...(returned.taint.propagators as PgxPropagator[]),
        {
          kind: "go-pgx-query-rewriter-returned-sql",
          line,
          symbol: returnedSql.trim(),
          path: function_.file.path,
        },
      ],
    };
  }
  return undefined;
}

function queryRewriterSummaries(
  files: readonly GoHttpSourceFile[],
  functions: readonly GoFunction[],
): QueryRewriterSummary[] {
  const structs = structFieldsByType(files);
  const candidates = new Map<string, QueryRewriterSummary[]>();
  for (const function_ of functions) {
    if (function_.name !== "RewriteQuery" || function_.receiver === undefined) {
      continue;
    }
    const receiver =
      /^\(\s*([A-Za-z_]\w*)\s+(\*)?\s*([A-Za-z_]\w*)\s*\)$/u.exec(
        function_.receiver,
      );
    if (receiver === null) continue;
    const pgxAlias = goImportAlias(function_.file.lines, PGX_IMPORT, "pgx");
    const contextAlias = goImportAlias(
      function_.file.lines,
      "context",
      "context",
    );
    if (
      pgxAlias === undefined ||
      contextAlias === undefined ||
      !exactQueryRewriterSignature(function_, pgxAlias, contextAlias)
    ) {
      continue;
    }
    const directory = posix.dirname(function_.file.path);
    const typeName = receiver[3]!;
    const key = `${directory}\0${function_.packageName}\0${typeName}`;
    const struct = structs.get(key);
    if (struct?.count !== 1) continue;
    const returnFlows = queryRewriterReturnFlows(
      function_,
      receiver[1]!,
      struct.fields,
    );
    const inputSqlFlow = queryRewriterInputSqlFlow(function_);
    const summary: QueryRewriterSummary = {
      directory,
      packageName: function_.packageName,
      typeName,
      pointerReceiver: receiver[2] === "*",
      methodFile: function_.file,
      ...(inputSqlFlow === undefined ? {} : { inputSqlFlow }),
      returnFlows,
    };
    const existing = candidates.get(key) ?? [];
    existing.push(summary);
    candidates.set(key, existing);
  }
  return [...candidates.values()]
    .filter((items) => items.length === 1)
    .map((items) => items[0]!);
}

function localQueryRewriters(
  function_: GoFunction,
  summaries: readonly QueryRewriterSummary[],
): Map<string, QueryRewriterSummary> {
  const result = new Map<string, QueryRewriterSummary>();
  for (const summary of summaries) {
    if (
      summary.directory === posix.dirname(function_.file.path) &&
      summary.packageName === function_.packageName
    ) {
      result.set(summary.typeName, summary);
    }
  }
  return result;
}

function cloneQueryRewriterInstance(
  instance: QueryRewriterInstance,
  isPointer = instance.isPointer,
): QueryRewriterInstance {
  return {
    summary: instance.summary,
    isPointer,
    fieldSources: new Map(instance.fieldSources),
  };
}

function queryRewriterComposite(
  expression: string,
  local: ReadonlyMap<string, QueryRewriterSummary>,
  requests: readonly string[],
  taints: ReadonlyMap<string, GoTaint>,
  line: number,
): QueryRewriterInstance | undefined {
  const composite = /^\s*(&)?\s*([A-Za-z_]\w*)\s*\{([\s\S]*)\}\s*$/u.exec(
    expression,
  );
  if (composite === null) return undefined;
  const summary = local.get(composite[2]!);
  if (summary === undefined) return undefined;
  const instance: QueryRewriterInstance = {
    summary,
    isPointer: composite[1] === "&",
    fieldSources: new Map(),
  };
  for (const entry of splitGoArguments(composite[3]!)) {
    const field = /^\s*([A-Za-z_]\w*)\s*:\s*([\s\S]+)$/u.exec(entry);
    if (field === null || !summary.returnFlows.has(field[1]!)) continue;
    const source =
      requestSource(field[2]!, requests, line) ??
      referencedTaint(field[2]!, taints)?.taint;
    if (source !== undefined) {
      instance.fieldSources.set(field[1]!, { source, line });
    }
  }
  return instance;
}

function queryRewriterVariable(
  expression: string,
  instances: ReadonlyMap<string, QueryRewriterInstance>,
): QueryRewriterInstance | undefined {
  const reference = /^\s*(&)?\s*([A-Za-z_]\w*)\s*$/u.exec(expression);
  if (reference === null) return undefined;
  const instance = instances.get(reference[2]!);
  if (instance === undefined) return undefined;
  return cloneQueryRewriterInstance(
    instance,
    reference[1] === "&" || instance.isPointer,
  );
}

function resolvedQueryRewriter(
  instance: QueryRewriterInstance,
): ResolvedQueryRewriter | undefined {
  if (instance.summary.pointerReceiver && !instance.isPointer) return undefined;
  for (const [fieldName, fieldSource] of instance.fieldSources) {
    const flow = instance.summary.returnFlows.get(fieldName);
    if (flow === undefined) continue;
    return {
      instance,
      source: {
        ...fieldSource.source,
        propagators: [
          ...fieldSource.source.propagators,
          {
            kind: "go-pgx-query-rewriter-field-construction",
            line: fieldSource.line,
            symbol: `${instance.summary.typeName}.${fieldName}`,
          },
          ...flow.propagators,
        ],
      },
    };
  }
  return { instance };
}

function rewrittenInputSqlSource(
  rewriter: ResolvedQueryRewriter | undefined,
  source: GoTaint | undefined,
): GoTaint | undefined {
  const flow = rewriter?.instance.summary.inputSqlFlow;
  if (flow === undefined || source === undefined) return undefined;
  return {
    ...source,
    propagators: [...source.propagators, ...flow.propagators],
  };
}

function queryOptionArgument(expression: string, aliases: PgxAliases): boolean {
  if (aliases.pgx === undefined) return false;
  return new RegExp(
    `^\\s*${escapeRegularExpression(aliases.pgx)}\\.(?:QueryExecMode[A-Za-z_]*|QueryResultFormats(?:ByOID)?)\\b`,
    "u",
  ).test(expression);
}

function queryRewriterAtCall(
  call: GoCall,
  start: number,
  aliases: PgxAliases,
  local: ReadonlyMap<string, QueryRewriterSummary>,
  instances: ReadonlyMap<string, QueryRewriterInstance>,
  requests: readonly string[],
  taints: ReadonlyMap<string, GoTaint>,
  allowOptions: boolean,
): ResolvedQueryRewriter | undefined {
  for (let index = start; index < call.arguments.length; index += 1) {
    const expression = call.rawArguments[index] ?? call.arguments[index]!;
    const instance =
      queryRewriterComposite(expression, local, requests, taints, call.line) ??
      queryRewriterVariable(expression, instances);
    if (instance !== undefined) return resolvedQueryRewriter(instance);
    if (!allowOptions || !queryOptionArgument(expression, aliases)) break;
  }
  return undefined;
}

function analyzeFunction(
  function_: GoFunction,
  initialTaints: ReadonlyMap<string, GoTaint> = new Map(),
  rewriterSummaries: readonly QueryRewriterSummary[] = [],
): PgxSink[] {
  const aliases = pgxAliases(function_);
  const specifications = receiverSpecifications(aliases);
  if (specifications.length === 0) return [];
  const requests = goHttpRequestParameters(function_);
  const localRewriters = localQueryRewriters(function_, rewriterSummaries);
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
  const rewriterInstances = new Map<string, QueryRewriterInstance>();
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
      const rawValue = rawAssigned?.value ?? value;
      const source = requestSource(value, requests, line);
      const prior = referencedTaint(value, taints);
      const fixedSelection = fixedMapSelection(value, maps, taints);
      const priorRewriter = queryRewriterVariable(rawValue, rewriterInstances);
      const compositeRewriter = queryRewriterComposite(
        rawValue,
        localRewriters,
        requests,
        taints,
        line,
      );
      for (const name of assignedNames) {
        taints.delete(name);
        fixedStrings.delete(name);
        inferredReceivers.delete(name);
        inferredBatches.delete(name);
        pendingBatches.delete(name);
        rewriterInstances.delete(name);
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
      const rewriter = compositeRewriter ?? priorRewriter;
      if (rewriter !== undefined) {
        rewriterInstances.set(primary, rewriter);
      }
    }
    const rewriterDeclaration = new RegExp(
      `^\\s*var\\s+([A-Za-z_]\\w*)\\s+(\\*)?(${[...localRewriters.keys()]
        .map(escapeRegularExpression)
        .join("|")})\\s*;?\\s*$`,
      "u",
    ).exec(structural);
    if (localRewriters.size > 0 && rewriterDeclaration !== null) {
      const summary = localRewriters.get(rewriterDeclaration[3]!);
      if (summary !== undefined) {
        rewriterInstances.set(rewriterDeclaration[1]!, {
          summary,
          isPointer: rewriterDeclaration[2] === "*",
          fieldSources: new Map(),
        });
      }
    }
    const fieldAssignment =
      /^\s*([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*=\s*([\s\S]+?)\s*;?\s*$/u.exec(raw);
    if (fieldAssignment !== null) {
      const instance = rewriterInstances.get(fieldAssignment[1]!);
      if (
        instance !== undefined &&
        instance.summary.returnFlows.has(fieldAssignment[2]!)
      ) {
        instance.fieldSources.delete(fieldAssignment[2]!);
        const source =
          requestSource(fieldAssignment[3]!, requests, line) ??
          referencedTaint(fieldAssignment[3]!, taints)?.taint;
        if (source !== undefined) {
          instance.fieldSources.set(fieldAssignment[2]!, { source, line });
        }
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
        const rewriter = queryRewriterAtCall(
          call,
          1,
          aliases,
          localRewriters,
          rewriterInstances,
          requests,
          taints,
          false,
        );
        const directSource =
          query === undefined
            ? undefined
            : requestSource(query, requests, line) ??
              referencedTaint(query, taints)?.taint;
        const source =
          rewriter?.source ??
          rewrittenInputSqlSource(rewriter, directSource) ??
          (rewriter === undefined ? directSource : undefined);
        const preparedName = fixedStringKey(call.rawArguments[0], fixedStrings);
        if (source !== undefined || preparedName !== undefined) {
          const queued = pendingBatches.get(receiver) ?? [];
          queued.push({
            ...(source === undefined ? {} : { source }),
            ...(preparedName === undefined ? {} : { preparedName }),
            ...(rewriter?.instance.summary.methodFile.path === undefined
              ? {}
              : {
                  supportingPath: rewriter.instance.summary.methodFile.path,
                }),
            line,
            controls:
              rewriter === undefined
                ? queryControls(controls, call, 0, aliases)
                : controls,
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
            ...(pending.supportingPath === undefined
              ? {}
              : { supportingPath: pending.supportingPath }),
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
      const rewriter = queryRewriterAtCall(
        call,
        2,
        aliases,
        localRewriters,
        rewriterInstances,
        requests,
        taints,
        true,
      );
      if (rewriter !== undefined) {
        const inputSource =
          requestSource(query, requests, line) ??
          referencedTaint(query, taints)?.taint;
        const rewrittenSource =
          rewriter.source ?? rewrittenInputSqlSource(rewriter, inputSource);
        if (rewrittenSource !== undefined) {
          sinks.push({
            kind: "go-pgx-query-rewriter-dispatch",
            line,
            source: rewrittenSource,
            controls,
            supportingPath: rewriter.instance.summary.methodFile.path,
          });
        }
        continue;
      }
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
  const rewriterSummaries = queryRewriterSummaries(files, functions);
  const records: GoPgxSqlInjectionRecord[] = [];
  const emitted = new Set<string>();

  for (const function_ of functions) {
    if (goHttpRequestParameters(function_).length === 0) continue;
    for (const sink of analyzeFunction(
      function_,
      new Map(),
      rewriterSummaries,
    )) {
      const identity = `${function_.file.path}:${sink.line}:${sink.kind}:${sink.source.line}:${sink.source.propagators
        .map((propagator) => `${propagator.kind}:${propagator.line}`)
        .join(",")}`;
      if (emitted.has(identity)) continue;
      emitted.add(identity);
      records.push(
        record(
          function_.file,
          function_.file,
          sink.supportingPath !== undefined &&
            sink.supportingPath !== function_.file.path
            ? "cross-file-wrapper"
            : "same-file",
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
      for (const sink of analyzeFunction(
        function_,
        initial,
        rewriterSummaries,
      )) {
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
