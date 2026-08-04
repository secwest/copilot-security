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
const SQUIRREL_IMPORT = "github.com/Masterminds/squirrel";
const SQL_IMPORT = "database/sql";

type SquirrelSinkKind =
  | "go-squirrel-builder-execution"
  | "go-squirrel-helper-execution"
  | "go-squirrel-materialized-query-execution"
  | "go-squirrel-debug-query-execution";

type BuilderKind =
  | "select"
  | "insert"
  | "update"
  | "delete"
  | "statement"
  | "case";

interface SquirrelRisk {
  source: GoTaint;
  controls: Array<{ kind: string; line: number }>;
}

interface BuilderState {
  kind: BuilderKind;
  runner: boolean;
  risk?: SquirrelRisk;
  valueTaint?: GoTaint;
}

interface MaterializedState {
  risk: SquirrelRisk;
  debug: boolean;
}

interface SquirrelSink {
  kind: SquirrelSinkKind;
  line: number;
  source: GoTaint;
  controls: Array<{ kind: string; line: number }>;
}

export interface GoSquirrelSqlInjectionRecord {
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
    id: "go-squirrel-sql-injection";
    language: "go";
    scope: "same-file" | "cross-file-wrapper";
    source: { kind: string; path: string; line: number };
    sink: {
      kind: SquirrelSinkKind;
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

interface WrapperSummary {
  file: GoHttpSourceFile;
  packageName: string;
  functionName: string;
  parameterName: string;
  parameterIndex: number;
  parameterLine: number;
  sink: SquirrelSink;
}

interface ParsedCall extends GoCall {
  endOffset: number;
}

interface FluentChain {
  endOffset: number;
  result?: string;
  state: BuilderState;
}

const BUILDER_TYPE_NAMES: ReadonlyArray<[BuilderKind, string]> = [
  ["select", "SelectBuilder"],
  ["insert", "InsertBuilder"],
  ["update", "UpdateBuilder"],
  ["delete", "DeleteBuilder"],
  ["statement", "StatementBuilderType"],
  ["case", "CaseBuilder"],
];

const RUNNER_TYPE_NAMES = [
  "BaseRunner",
  "Runner",
  "RunnerContext",
  "StdSql",
  "StdSqlCtx",
  "Execer",
  "ExecerContext",
  "Queryer",
  "QueryerContext",
  "QueryRower",
  "QueryRowerContext",
  "DBProxy",
  "DBProxyBeginner",
  "StmtCache",
];

const BUILDER_EXECUTION_METHODS = new Set([
  "Exec",
  "ExecContext",
  "Query",
  "QueryContext",
  "QueryRow",
  "QueryRowContext",
  "Scan",
  "ScanContext",
]);

const MATERIALIZATION_METHODS = new Set(["MustSql", "ToSql"]);

const PACKAGE_HELPERS = new Map<
  string,
  { runnerIndex: number; builderIndex: number }
>([
  ["ExecWith", { runnerIndex: 0, builderIndex: 1 }],
  ["QueryWith", { runnerIndex: 0, builderIndex: 1 }],
  ["QueryRowWith", { runnerIndex: 0, builderIndex: 1 }],
  ["ExecContextWith", { runnerIndex: 1, builderIndex: 2 }],
  ["QueryContextWith", { runnerIndex: 1, builderIndex: 2 }],
  ["QueryRowContextWith", { runnerIndex: 1, builderIndex: 2 }],
]);

const SQL_METHOD_QUERY_INDEX = new Map<string, number>([
  ["Exec", 0],
  ["Query", 0],
  ["QueryRow", 0],
  ["ExecContext", 1],
  ["QueryContext", 1],
  ["QueryRowContext", 1],
]);

const SAFE_CONDITION_TYPES = [
  "Eq",
  "NotEq",
  "Like",
  "NotLike",
  "ILike",
  "NotILike",
  "Lt",
  "LtOrEq",
  "Gt",
  "GtOrEq",
];

function squirrelAlias(function_: GoFunction): string | undefined {
  return goImportAlias(function_.file.lines, SQUIRREL_IMPORT, "squirrel");
}

function sqlAlias(function_: GoFunction): string | undefined {
  return goImportAlias(function_.file.lines, SQL_IMPORT, "sql");
}

function requestParameters(function_: GoFunction): string[] {
  return goHttpRequestParameters(function_);
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
    if (/\.PlaceholderFormat\s*\(/u.test(structural)) {
      addControl(controls, "squirrel-placeholder-format", line);
    }
    if (/\b(?:BeginTx|TxOptions)\b/u.test(structural)) {
      addControl(controls, "database-transaction", line);
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
  expression: string,
  requests: readonly string[],
  taints: ReadonlyMap<string, GoTaint>,
  line: number,
): GoTaint | undefined {
  return (
    requestSource(expression, requests, line) ??
    referencedTaint(expression, taints)?.taint
  );
}

function boundConditionValue(
  expression: string,
  alias: string,
  valueContainers: ReadonlySet<string>,
): boolean {
  const trimmed = expression.trim();
  if (/^[A-Za-z_]\w*$/u.test(trimmed) && valueContainers.has(trimmed)) {
    return true;
  }
  const safeType = SAFE_CONDITION_TYPES.join("|");
  if (
    new RegExp(
      `^(?:${escapeRegularExpression(alias)}\\.)?(?:${safeType})\\s*\\{`,
      "u",
    ).test(trimmed)
  ) {
    return true;
  }
  return /^(?:&\s*)?map\s*\[[^\]]+\]\s*(?:interface\s*\{\}|[A-Za-z_][\w.]*)\s*\{/u.test(
    trimmed,
  );
}

function constructionRisk(
  source: GoTaint,
  controls: Array<{ kind: string; line: number }>,
  line: number,
  method: string,
): SquirrelRisk {
  return {
    source: {
      ...source,
      propagators: [
        ...source.propagators,
        { kind: "go-squirrel-query-construction", line, symbol: method },
      ],
    },
    controls: controls.slice(0, 8),
  };
}

function firstRisk(
  expressions: readonly string[],
  method: string,
  requests: readonly string[],
  taints: ReadonlyMap<string, GoTaint>,
  controls: Array<{ kind: string; line: number }>,
  line: number,
): SquirrelRisk | undefined {
  for (const expression of expressions) {
    const source = querySource(expression, requests, taints, line);
    if (source !== undefined) {
      return constructionRisk(source, controls, line, method);
    }
  }
  return undefined;
}

function firstValueTaint(
  expressions: readonly string[],
  requests: readonly string[],
  taints: ReadonlyMap<string, GoTaint>,
  line: number,
): GoTaint | undefined {
  for (const expression of expressions) {
    const source = querySource(expression, requests, taints, line);
    if (source !== undefined) return source;
  }
  return undefined;
}

function mergeState(
  base: BuilderState,
  next: Partial<BuilderState>,
): BuilderState {
  return {
    ...base,
    ...next,
    risk: next.risk ?? base.risk,
    valueTaint: next.valueTaint ?? base.valueTaint,
  };
}

function nestedIdentityRisk(
  expressions: readonly string[],
  builders: ReadonlyMap<string, BuilderState>,
  sqlizers: ReadonlyMap<string, SquirrelRisk>,
): SquirrelRisk | undefined {
  for (const expression of expressions) {
    for (const [name, risk] of sqlizers) {
      if (
        new RegExp(`\\b${escapeRegularExpression(name)}\\b`, "u").test(
          expression,
        )
      ) {
        return risk;
      }
    }
    for (const [name, state] of builders) {
      if (
        state.risk !== undefined &&
        new RegExp(`\\b${escapeRegularExpression(name)}\\b`, "u").test(
          expression,
        )
      ) {
        return state.risk;
      }
    }
  }
  return undefined;
}

function dynamicMapKeyRisk(
  expression: string,
  method: string,
  requests: readonly string[],
  taints: ReadonlyMap<string, GoTaint>,
  controls: Array<{ kind: string; line: number }>,
  line: number,
): SquirrelRisk | undefined {
  const keyMatch = /\{\s*([^:]+?)\s*:/u.exec(expression);
  if (keyMatch === null) return undefined;
  const source = querySource(keyMatch[1]!, requests, taints, line);
  return source === undefined
    ? undefined
    : constructionRisk(source, controls, line, method);
}

function directNestedSqlizerRisk(
  outer: ParsedCall,
  calls: readonly ParsedCall[],
  alias: string,
  requests: readonly string[],
  taints: ReadonlyMap<string, GoTaint>,
  controls: Array<{ kind: string; line: number }>,
): SquirrelRisk | undefined {
  const nested = calls.filter(
    (call) => call.offset > outer.offset && call.offset < outer.endOffset,
  );
  const containsCase = nested.some((call) => call.name === `${alias}.Case`);
  for (const call of nested) {
    let expressions: readonly string[] = [];
    let method = call.name;
    if (call.name === `${alias}.Expr`) expressions = call.arguments.slice(0, 1);
    else if (call.name === `${alias}.ConcatExpr`) expressions = call.arguments;
    else if (call.name === `${alias}.Alias`)
      expressions = call.arguments.slice(1, 2);
    else if (call.name === `${alias}.Case`)
      expressions = call.arguments.slice(0, 1);
    else if (containsCase && (call.name === "When" || call.name === "Else")) {
      expressions =
        call.name === "When"
          ? call.arguments.slice(0, 2)
          : call.arguments.slice(0, 1);
      method = `Case.${call.name}`;
    }
    if (expressions.length === 0) continue;
    const risk = firstRisk(
      expressions,
      method.replace(`${alias}.`, ""),
      requests,
      taints,
      controls,
      call.line,
    );
    if (risk !== undefined) return risk;
  }
  return undefined;
}

function applyBuilderMethod(
  state: BuilderState,
  call: ParsedCall,
  method: string,
  alias: string,
  requests: readonly string[],
  taints: ReadonlyMap<string, GoTaint>,
  valueContainers: ReadonlySet<string>,
  builders: ReadonlyMap<string, BuilderState>,
  sqlizers: ReadonlyMap<string, SquirrelRisk>,
  calls: readonly ParsedCall[],
  runnerProven: (expression: string) => boolean,
  controls: Array<{ kind: string; line: number }>,
): BuilderState | undefined {
  if (method === "PlaceholderFormat") return state;
  if (method === "RunWith") {
    return mergeState(state, {
      runner:
        call.arguments[0] !== undefined && runnerProven(call.arguments[0]),
    });
  }

  const grammar = (expressions: readonly string[]): SquirrelRisk | undefined =>
    firstRisk(expressions, method, requests, taints, controls, call.line);
  const values = (expressions: readonly string[]): GoTaint | undefined =>
    firstValueTaint(expressions, requests, taints, call.line);
  const nested = (expressions: readonly string[]): SquirrelRisk | undefined =>
    nestedIdentityRisk(expressions, builders, sqlizers) ??
    directNestedSqlizerRisk(call, calls, alias, requests, taints, controls);

  if (state.kind === "statement") {
    if (method === "Where") {
      const condition = call.arguments[0];
      if (condition === undefined) return state;
      const safe = boundConditionValue(condition, alias, valueContainers);
      return mergeState(state, {
        risk: safe ? nested([condition]) : grammar([condition]),
        valueTaint: safe
          ? values([condition, ...call.arguments.slice(1)])
          : values(call.arguments.slice(1)),
      });
    }
    const child = new Map<string, BuilderKind>([
      ["Select", "select"],
      ["Insert", "insert"],
      ["Replace", "insert"],
      ["Update", "update"],
      ["Delete", "delete"],
    ]).get(method);
    if (child !== undefined) {
      const expressions =
        method === "Select" ? call.arguments : call.arguments.slice(0, 1);
      return mergeState(state, { kind: child, risk: grammar(expressions) });
    }
    return undefined;
  }

  if (state.kind === "case") {
    if (method === "When") {
      return mergeState(state, {
        risk:
          grammar(call.arguments.slice(0, 2)) ??
          nested(call.arguments.slice(0, 2)),
      });
    }
    if (method === "Else") {
      return mergeState(state, {
        risk:
          grammar(call.arguments.slice(0, 1)) ??
          nested(call.arguments.slice(0, 1)),
      });
    }
    return undefined;
  }

  if (method === "PrefixExpr" || method === "SuffixExpr") {
    return mergeState(state, { risk: nested(call.arguments.slice(0, 1)) });
  }
  if (method === "Prefix" || method === "Suffix") {
    return mergeState(state, {
      risk: grammar(call.arguments.slice(0, 1)),
      valueTaint: values(call.arguments.slice(1)),
    });
  }
  if (method === "Where" || method === "Having") {
    const condition = call.arguments[0];
    if (condition === undefined) return state;
    const safe = boundConditionValue(condition, alias, valueContainers);
    return mergeState(state, {
      risk: safe
        ? nested([condition])
        : grammar([condition]) ?? nested([condition]),
      valueTaint: safe
        ? values([condition, ...call.arguments.slice(1)])
        : values(call.arguments.slice(1)),
    });
  }
  if (method === "FromSelect") {
    return mergeState(state, {
      risk:
        nested(call.arguments.slice(0, 1)) ??
        grammar(call.arguments.slice(1, 2)),
    });
  }

  if (state.kind === "select") {
    if (["Columns", "Options", "GroupBy", "OrderBy"].includes(method)) {
      return mergeState(state, { risk: grammar(call.arguments) });
    }
    if (
      [
        "From",
        "JoinClause",
        "Join",
        "LeftJoin",
        "RightJoin",
        "InnerJoin",
        "CrossJoin",
        "OrderByClause",
      ].includes(method)
    ) {
      return mergeState(state, {
        risk:
          grammar(call.arguments.slice(0, 1)) ??
          nested(call.arguments.slice(0, 1)),
        valueTaint: values(call.arguments.slice(1)),
      });
    }
    if (method === "Column") {
      return mergeState(state, {
        risk:
          grammar(call.arguments.slice(0, 1)) ??
          nested(call.arguments.slice(0, 1)),
        valueTaint: values(call.arguments.slice(1)),
      });
    }
    if (
      [
        "Distinct",
        "Limit",
        "Offset",
        "RemoveColumns",
        "RemoveLimit",
        "RemoveOffset",
      ].includes(method)
    ) {
      return state;
    }
  }

  if (state.kind === "update") {
    if (["Table", "From"].includes(method)) {
      return mergeState(state, { risk: grammar(call.arguments.slice(0, 1)) });
    }
    if (method === "OrderBy") {
      return mergeState(state, { risk: grammar(call.arguments) });
    }
    if (method === "Set") {
      return mergeState(state, {
        risk:
          grammar(call.arguments.slice(0, 1)) ??
          nested(call.arguments.slice(1, 2)),
        valueTaint:
          nested(call.arguments.slice(1, 2)) === undefined
            ? values(call.arguments.slice(1, 2))
            : undefined,
      });
    }
    if (method === "SetMap") {
      const expression = call.arguments[0];
      if (expression === undefined) return state;
      return mergeState(state, {
        risk:
          dynamicMapKeyRisk(
            expression,
            method,
            requests,
            taints,
            controls,
            call.line,
          ) ?? nested([expression]),
        valueTaint: values([expression]),
      });
    }
    if (["Limit", "Offset"].includes(method)) return state;
  }

  if (state.kind === "insert") {
    if (["Into"].includes(method)) {
      return mergeState(state, { risk: grammar(call.arguments.slice(0, 1)) });
    }
    if (["Columns", "Options"].includes(method)) {
      return mergeState(state, { risk: grammar(call.arguments) });
    }
    if (method === "Values") {
      return mergeState(state, {
        risk: nested(call.arguments),
        valueTaint:
          nested(call.arguments) === undefined
            ? values(call.arguments)
            : undefined,
      });
    }
    if (method === "SetMap") {
      const expression = call.arguments[0];
      if (expression === undefined) return state;
      return mergeState(state, {
        risk:
          dynamicMapKeyRisk(
            expression,
            method,
            requests,
            taints,
            controls,
            call.line,
          ) ?? nested([expression]),
        valueTaint: values([expression]),
      });
    }
    if (method === "Select") {
      return mergeState(state, { risk: nested(call.arguments.slice(0, 1)) });
    }
  }

  if (state.kind === "delete") {
    if (method === "From") {
      return mergeState(state, { risk: grammar(call.arguments.slice(0, 1)) });
    }
    if (method === "OrderBy") {
      return mergeState(state, { risk: grammar(call.arguments) });
    }
    if (["Limit", "Offset"].includes(method)) return state;
  }
  return undefined;
}

function sinkForRisk(
  kind: SquirrelSinkKind,
  risk: SquirrelRisk,
  line: number,
): SquirrelSink {
  return {
    kind,
    line,
    source: risk.source,
    controls: risk.controls,
  };
}

function analyzeFunction(
  function_: GoFunction,
  initialTaints: ReadonlyMap<string, GoTaint> = new Map(),
): SquirrelSink[] {
  const alias = squirrelAlias(function_);
  if (alias === undefined) return [];
  const databaseAlias = sqlAlias(function_);
  const requests = requestParameters(function_);
  const taints = new Map(initialTaints);
  const builders = new Map<string, BuilderState>();
  const sqlizers = new Map<string, SquirrelRisk>();
  const sqlizerValues = new Map<string, GoTaint>();
  const materialized = new Map<string, MaterializedState>();
  const prepared = new Map<string, MaterializedState>();
  const valueContainers = new Set<string>();
  const inferredRunners = new Set<string>();
  const maps = fixedMapNames(function_);
  const controls = functionControls(function_);
  const parsed = parsedCalls(function_);
  const callsByLine = new Map<number, ParsedCall[]>();
  for (const call of parsed.calls) {
    const existing = callsByLine.get(call.line) ?? [];
    existing.push(call);
    callsByLine.set(call.line, existing);
  }

  const staticBuilderKinds = new Map<string, BuilderKind>();
  for (const [kind, typeName] of BUILDER_TYPE_NAMES) {
    for (const name of goTypedReceiverNames(function_, [
      { alias, typeNames: [typeName] },
    ])) {
      staticBuilderKinds.set(name, kind);
    }
  }
  const staticRunners = goTypedReceiverNames(function_, [
    { alias, typeNames: RUNNER_TYPE_NAMES },
    ...(databaseAlias === undefined
      ? []
      : [{ alias: databaseAlias, typeNames: ["DB", "Tx", "Conn"] }]),
  ]);
  const sqlReceivers =
    databaseAlias === undefined
      ? new Set<string>()
      : goTypedReceiverNames(function_, [
          { alias: databaseAlias, typeNames: ["DB", "Tx", "Conn"] },
        ]);
  const sinks: SquirrelSink[] = [];
  let pending: FluentChain | undefined;

  const runnerProven = (expression: string): boolean => {
    for (const name of [...staticRunners, ...inferredRunners]) {
      if (
        new RegExp(`\\b${escapeRegularExpression(name)}\\b`, "u").test(
          expression,
        )
      ) {
        return true;
      }
    }
    return false;
  };

  const stateFor = (receiver: string): BuilderState | undefined => {
    const existing = builders.get(receiver);
    if (existing !== undefined) return existing;
    const kind = staticBuilderKinds.get(receiver);
    return kind === undefined ? undefined : { kind, runner: false };
  };

  const rememberBuilder = (
    name: string | undefined,
    state: BuilderState,
  ): void => {
    if (name === undefined) return;
    builders.set(name, state);
  };

  const materializedRisk = (
    expression: string,
  ): MaterializedState | undefined => {
    for (const [name, state] of materialized) {
      if (
        new RegExp(`\\b${escapeRegularExpression(name)}\\b`, "u").test(
          expression,
        )
      ) {
        return state;
      }
    }
    return undefined;
  };

  const debugStateFor = (
    expression: string,
    line: number,
  ): SquirrelRisk | undefined => {
    for (const [name, state] of builders) {
      if (
        !new RegExp(`\\b${escapeRegularExpression(name)}\\b`, "u").test(
          expression,
        )
      ) {
        continue;
      }
      if (state.risk !== undefined) return state.risk;
      if (state.valueTaint !== undefined) {
        return constructionRisk(
          state.valueTaint,
          controls,
          line,
          "DebugSqlizer",
        );
      }
    }
    for (const [name, risk] of sqlizers) {
      if (
        new RegExp(`\\b${escapeRegularExpression(name)}\\b`, "u").test(
          expression,
        )
      ) {
        return risk;
      }
    }
    for (const [name, source] of sqlizerValues) {
      if (
        new RegExp(`\\b${escapeRegularExpression(name)}\\b`, "u").test(
          expression,
        )
      ) {
        return constructionRisk(source, controls, line, "DebugSqlizer");
      }
    }
    return undefined;
  };

  const inlineBuilderState = (outer: ParsedCall): BuilderState | undefined => {
    const nested = parsed.calls.filter(
      (call) => call.offset > outer.offset && call.offset < outer.endOffset,
    );
    const constructors = new Map<string, BuilderKind>([
      [`${alias}.Select`, "select"],
      [`${alias}.Insert`, "insert"],
      [`${alias}.Replace`, "insert"],
      [`${alias}.Update`, "update"],
      [`${alias}.Delete`, "delete"],
      [`${alias}.Case`, "case"],
    ]);
    const first = nested.find((call) => constructors.has(call.name));
    if (first === undefined) return undefined;
    const kind = constructors.get(first.name)!;
    const helperName = first.name.slice(alias.length + 1);
    let state: BuilderState = {
      kind,
      runner: false,
      risk: firstRisk(
        helperName === "Select" ? first.arguments : first.arguments.slice(0, 1),
        helperName,
        requests,
        taints,
        controls,
        first.line,
      ),
      valueTaint:
        helperName === "Case"
          ? firstValueTaint(
              first.arguments.slice(1),
              requests,
              taints,
              first.line,
            )
          : undefined,
    };
    let endOffset = first.endOffset;
    for (const call of nested) {
      if (call.offset < endOffset) continue;
      const bridge = parsed.structural.slice(endOffset, call.offset);
      if (!/^\s*\.\s*$/u.test(bridge) || !/^[A-Za-z_]\w*$/u.test(call.name)) {
        break;
      }
      const next = applyBuilderMethod(
        state,
        call,
        call.name,
        alias,
        requests,
        taints,
        valueContainers,
        builders,
        sqlizers,
        parsed.calls,
        runnerProven,
        controls,
      );
      if (next === undefined) break;
      state = next;
      endOffset = call.endOffset;
    }
    return state;
  };

  for (
    let line = function_.bodyStartLine;
    line <= function_.endLine;
    line += 1
  ) {
    const buildersBefore = new Map(builders);
    const sqlizersBefore = new Map(sqlizers);
    const sqlizerValuesBefore = new Map(sqlizerValues);
    const materializedBefore = new Map(materialized);
    const runnersBefore = new Set(inferredRunners);
    const structuralLine = function_.structuralLines[line - 1] ?? "";
    const assigned = goAssignment(structuralLine);
    const lineCalls = callsByLine.get(line) ?? [];
    if (assigned !== undefined) {
      const primary = assigned.names[0]!;
      const exactAlias = /^([A-Za-z_]\w*)$/u.exec(assigned.value.trim())?.[1];
      const builderAlias =
        exactAlias === undefined ? undefined : buildersBefore.get(exactAlias);
      const sqlizerAlias =
        exactAlias === undefined ? undefined : sqlizersBefore.get(exactAlias);
      const sqlizerValueAlias =
        exactAlias === undefined
          ? undefined
          : sqlizerValuesBefore.get(exactAlias);
      const materializedAlias =
        exactAlias === undefined
          ? undefined
          : materializedBefore.get(exactAlias);
      const runnerAlias =
        exactAlias !== undefined &&
        (staticRunners.has(exactAlias) || runnersBefore.has(exactAlias));
      const source = requestSource(assigned.value, requests, line);
      const prior = referencedTaint(assigned.value, taints);
      const fixedSelection = fixedMapSelection(assigned.value, maps, taints);
      const isValueContainer = boundConditionValue(
        assigned.value,
        alias,
        valueContainers,
      );
      for (const name of assigned.names) {
        taints.delete(name);
        builders.delete(name);
        sqlizers.delete(name);
        sqlizerValues.delete(name);
        materialized.delete(name);
        prepared.delete(name);
        valueContainers.delete(name);
        inferredRunners.delete(name);
      }
      if (isValueContainer) valueContainers.add(primary);
      if (builderAlias !== undefined) builders.set(primary, builderAlias);
      if (sqlizerAlias !== undefined) sqlizers.set(primary, sqlizerAlias);
      if (sqlizerValueAlias !== undefined) {
        sqlizerValues.set(primary, sqlizerValueAlias);
      }
      if (materializedAlias !== undefined) {
        materialized.set(primary, materializedAlias);
      }
      if (runnerAlias) inferredRunners.add(primary);
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

    for (const call of lineCalls) {
      if (pending !== undefined && call.offset < pending.endOffset) continue;

      if (pending !== undefined) {
        const bridge = parsed.structural.slice(pending.endOffset, call.offset);
        const continuation =
          /^\s*\.\s*$/u.test(bridge) && /^[A-Za-z_]\w*$/u.test(call.name);
        if (continuation) {
          const method = call.name;
          if (BUILDER_EXECUTION_METHODS.has(method)) {
            if (pending.state.runner && pending.state.risk !== undefined) {
              sinks.push(
                sinkForRisk(
                  "go-squirrel-builder-execution",
                  pending.state.risk,
                  call.line,
                ),
              );
            }
            if (pending.result !== undefined) {
              builders.delete(pending.result);
            }
            pending = undefined;
            continue;
          }
          if (MATERIALIZATION_METHODS.has(method)) {
            const result = pending.result;
            if (result !== undefined && pending.state.risk !== undefined) {
              materialized.set(result, {
                risk: pending.state.risk,
                debug: false,
              });
            }
            if (pending.result !== undefined) {
              builders.delete(pending.result);
            }
            pending = undefined;
            continue;
          }
          const next = applyBuilderMethod(
            pending.state,
            call,
            method,
            alias,
            requests,
            taints,
            valueContainers,
            builders,
            sqlizers,
            parsed.calls,
            runnerProven,
            controls,
          );
          if (next !== undefined) {
            pending = {
              ...pending,
              state: next,
              endOffset: call.endOffset,
            };
            rememberBuilder(pending.result, next);
            continue;
          }
        }
        pending = undefined;
      }

      const result = assignedCallResult(call);
      const priorBuilder = (receiver: string): BuilderState | undefined =>
        stateFor(receiver) ?? buildersBefore.get(receiver);

      if (databaseAlias !== undefined) {
        if (
          (call.name === `${databaseAlias}.Open` ||
            call.name === `${databaseAlias}.OpenDB`) &&
          result !== undefined
        ) {
          inferredRunners.add(result);
          sqlReceivers.add(result);
          continue;
        }
      }

      if (
        call.name === `${alias}.NewStmtCache` ||
        call.name === `${alias}.NewStmtCacheProxy` ||
        call.name === `${alias}.WrapStdSql` ||
        call.name === `${alias}.WrapStdSqlCtx`
      ) {
        if (
          result !== undefined &&
          call.arguments[0] !== undefined &&
          runnerProven(call.arguments[0])
        ) {
          inferredRunners.add(result);
        }
        continue;
      }

      if (call.name === `${alias}.Expr`) {
        if (result !== undefined) {
          const risk = firstRisk(
            call.arguments.slice(0, 1),
            "Expr",
            requests,
            taints,
            controls,
            call.line,
          );
          const value = firstValueTaint(
            call.arguments.slice(1),
            requests,
            taints,
            call.line,
          );
          if (risk !== undefined) sqlizers.set(result, risk);
          if (value !== undefined) sqlizerValues.set(result, value);
        }
        continue;
      }

      if (call.name === `${alias}.ConcatExpr`) {
        if (result !== undefined) {
          const risk =
            firstRisk(
              call.arguments,
              "ConcatExpr",
              requests,
              taints,
              controls,
              call.line,
            ) ?? nestedIdentityRisk(call.arguments, builders, sqlizers);
          if (risk !== undefined) sqlizers.set(result, risk);
        }
        continue;
      }

      if (call.name === `${alias}.Alias`) {
        if (result !== undefined) {
          const risk =
            firstRisk(
              call.arguments.slice(1, 2),
              "Alias",
              requests,
              taints,
              controls,
              call.line,
            ) ??
            nestedIdentityRisk(call.arguments.slice(0, 1), builders, sqlizers);
          if (risk !== undefined) sqlizers.set(result, risk);
          const nestedValue = firstValueTaint(
            call.arguments.slice(0, 1),
            requests,
            taints,
            call.line,
          );
          if (nestedValue !== undefined) sqlizerValues.set(result, nestedValue);
        }
        continue;
      }

      if (call.name === `${alias}.DebugSqlizer`) {
        const risk =
          call.arguments[0] === undefined
            ? undefined
            : debugStateFor(call.arguments[0], call.line);
        if (result !== undefined && risk !== undefined) {
          materialized.set(result, { risk, debug: true });
        }
        continue;
      }

      const helper = new RegExp(
        `^${escapeRegularExpression(alias)}\\.([A-Za-z_]\\w*)$`,
        "u",
      ).exec(call.name);
      if (helper !== null) {
        const helperName = helper[1]!;
        const helperShape = PACKAGE_HELPERS.get(helperName);
        if (helperShape !== undefined) {
          const runner = call.arguments[helperShape.runnerIndex];
          const builderExpression = call.arguments[helperShape.builderIndex];
          const state =
            builderExpression === undefined
              ? undefined
              : [...builders].find(([name]) =>
                  new RegExp(
                    `\\b${escapeRegularExpression(name)}\\b`,
                    "u",
                  ).test(builderExpression),
                )?.[1] ?? inlineBuilderState(call);
          if (
            runner !== undefined &&
            runnerProven(runner) &&
            state?.risk !== undefined
          ) {
            sinks.push(
              sinkForRisk(
                "go-squirrel-helper-execution",
                state.risk,
                call.line,
              ),
            );
          }
          continue;
        }

        const constructorKind = new Map<string, BuilderKind>([
          ["Select", "select"],
          ["Insert", "insert"],
          ["Replace", "insert"],
          ["Update", "update"],
          ["Delete", "delete"],
          ["Case", "case"],
        ]).get(helperName);
        if (constructorKind !== undefined) {
          const grammarArguments =
            helperName === "Select"
              ? call.arguments
              : call.arguments.slice(0, 1);
          const state: BuilderState = {
            kind: constructorKind,
            runner: false,
            risk: firstRisk(
              grammarArguments,
              helperName,
              requests,
              taints,
              controls,
              call.line,
            ),
            valueTaint:
              helperName === "Case"
                ? firstValueTaint(
                    call.arguments.slice(1),
                    requests,
                    taints,
                    call.line,
                  )
                : undefined,
          };
          rememberBuilder(result, state);
          pending = {
            endOffset: call.endOffset,
            ...(result === undefined ? {} : { result }),
            state,
          };
          continue;
        }
      }

      const receiverCall =
        /^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.([A-Za-z_]\w*)$/u.exec(call.name);
      if (receiverCall === null) continue;
      const receiver = receiverCall[1]!;
      const method = receiverCall[2]!;

      if (
        result !== undefined &&
        (sqlReceivers.has(receiver) || inferredRunners.has(receiver)) &&
        ["Begin", "BeginTx", "Conn"].includes(method)
      ) {
        inferredRunners.add(result);
        sqlReceivers.add(result);
        continue;
      }

      if (receiver === `${alias}.StatementBuilder`) {
        const state: BuilderState = { kind: "statement", runner: false };
        const next = applyBuilderMethod(
          state,
          call,
          method,
          alias,
          requests,
          taints,
          valueContainers,
          builders,
          sqlizers,
          parsed.calls,
          runnerProven,
          controls,
        );
        if (next !== undefined) {
          rememberBuilder(result, next);
          pending = {
            endOffset: call.endOffset,
            ...(result === undefined ? {} : { result }),
            state: next,
          };
        }
        continue;
      }

      const state = priorBuilder(receiver);
      if (state !== undefined) {
        if (BUILDER_EXECUTION_METHODS.has(method)) {
          if (state.runner && state.risk !== undefined) {
            sinks.push(
              sinkForRisk(
                "go-squirrel-builder-execution",
                state.risk,
                call.line,
              ),
            );
          }
          continue;
        }
        if (MATERIALIZATION_METHODS.has(method)) {
          if (result !== undefined && state.risk !== undefined) {
            materialized.set(result, { risk: state.risk, debug: false });
          }
          continue;
        }
        const next = applyBuilderMethod(
          state,
          call,
          method,
          alias,
          requests,
          taints,
          valueContainers,
          builders,
          sqlizers,
          parsed.calls,
          runnerProven,
          controls,
        );
        if (next !== undefined) {
          rememberBuilder(result, next);
          pending = {
            endOffset: call.endOffset,
            ...(result === undefined ? {} : { result }),
            state: next,
          };
        }
        continue;
      }

      const queryIndex = SQL_METHOD_QUERY_INDEX.get(method);
      if (
        queryIndex !== undefined &&
        (sqlReceivers.has(receiver) || inferredRunners.has(receiver))
      ) {
        const query = call.arguments[queryIndex];
        if (query === undefined) continue;
        let state = materializedRisk(query);
        if (
          state === undefined &&
          new RegExp(
            `\\b${escapeRegularExpression(alias)}\\.DebugSqlizer\\s*\\(`,
            "u",
          ).test(query)
        ) {
          const risk = debugStateFor(query, call.line);
          if (risk !== undefined) state = { risk, debug: true };
        }
        if (state !== undefined) {
          sinks.push(
            sinkForRisk(
              state.debug
                ? "go-squirrel-debug-query-execution"
                : "go-squirrel-materialized-query-execution",
              state.risk,
              call.line,
            ),
          );
        }
      }

      const prepareIndex = new Map<string, number>([
        ["Prepare", 0],
        ["PrepareContext", 1],
      ]).get(method);
      if (
        prepareIndex !== undefined &&
        result !== undefined &&
        (sqlReceivers.has(receiver) || inferredRunners.has(receiver))
      ) {
        const query = call.arguments[prepareIndex];
        if (query === undefined) continue;
        const state = materializedRisk(query);
        if (state !== undefined) prepared.set(result, state);
        continue;
      }

      const preparedState = prepared.get(receiver);
      if (
        preparedState !== undefined &&
        BUILDER_EXECUTION_METHODS.has(method)
      ) {
        sinks.push(
          sinkForRisk(
            preparedState.debug
              ? "go-squirrel-debug-query-execution"
              : "go-squirrel-materialized-query-execution",
            preparedState.risk,
            call.line,
          ),
        );
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
  sink: SquirrelSink,
  propagators: GoPropagator[],
): GoSquirrelSqlInjectionRecord {
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
      "framework-dataflow:go-squirrel-sql-injection",
      `modeled-source:${source.kind}`,
      `modeled-sink:${sink.kind}`,
      ...sink.controls.map((control) => `candidate-control:${control.kind}`),
    ],
    priority: 125,
    startLine,
    endLine,
    excerpt: excerpt(sinkFile.lines, startLine, endLine),
    sourceExcerpt: excerpt(sourceFile.lines, sourceStart, sourceEnd),
    frameworkModel: {
      schemaVersion: "1.2",
      id: "go-squirrel-sql-injection",
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

export function goSquirrelSqlInjectionRecords(
  files: readonly GoHttpSourceFile[],
): GoSquirrelSqlInjectionRecord[] {
  const functions = files
    .filter((file) => file.extension === ".go")
    .flatMap(goFunctions);
  const records: GoSquirrelSqlInjectionRecord[] = [];
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
    if (
      function_.receiver !== undefined ||
      squirrelAlias(function_) === undefined
    ) {
      continue;
    }
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
