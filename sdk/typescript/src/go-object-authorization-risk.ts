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

const CONTEXT_LINES_BEFORE = 3;
const CONTEXT_LINES_AFTER = 5;
const MAX_RECORDS = 64;
const MAX_OBJECT_WRAPPER_DEPTH = 32;
const MAX_OBJECT_WRAPPER_CANDIDATES = 4_096;
const MAX_TRANSACTION_HELPER_DEPTH = 32;
const MAX_TRANSACTION_FUNCTION_VALUE_DEPTH = 8;
const OBJECT_COLUMN = /^(?:id|key|uuid|[a-z][a-z0-9_]*_(?:id|key|uuid))$/iu;
const SECURITY_COLUMN =
  /^(?:account|customer|organization|org|owner|principal|shop|tenant|user|workspace)_(?:id|key|uuid)$/iu;
const PRINCIPAL_NAME =
  /(?:account|auth|customer|identity|organization|org|owner|principal|shop|subject|tenant|user|workspace)/iu;

export interface GoObjectAuthorizationRecord {
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
    id: "go-http-object-authorization";
    language: "go";
    scope: "same-file" | "cross-file-wrapper";
    source: { kind: string; path: string; line: number };
    sink: {
      kind:
        | "go-database-object-read-response"
        | "go-database-object-collection-response"
        | "go-database-object-mutation"
        | "go-database-object-committed-mutation";
      path: string;
      line: number;
      cweIds: readonly ["CWE-639", "CWE-862"];
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

interface FixedString {
  value: string;
  line: number;
}

interface Predicate {
  column: string;
  argumentIndex?: number;
  argumentName?: string;
}

interface EvidencePropagator extends GoPropagator {
  path?: string;
}

interface CandidateQuery {
  mode: "row" | "rows";
  line: number;
  method: string;
  source: GoTaint;
  result?: string;
  iterated: boolean;
  scannedNames: Set<string>;
  propagators: EvidencePropagator[];
  controls: Array<{ kind: string; line: number }>;
}

interface PreparedStatement {
  line: number;
  predicates: Predicate[];
  active: boolean;
  transaction?: TransactionState;
  transfer?: GoPropagator;
}

interface TransactionState {
  active: boolean;
  pending: ObjectSink[];
  creationEvidence: EvidencePropagator[];
}

interface ObjectSink {
  kind:
    | "go-database-object-read-response"
    | "go-database-object-collection-response"
    | "go-database-object-mutation"
    | "go-database-object-committed-mutation";
  line: number;
  source: GoTaint;
  propagators: EvidencePropagator[];
  controls: Array<{ kind: string; line: number }>;
}

interface WrapperSummary {
  file: GoHttpSourceFile;
  sinkFile: GoHttpSourceFile;
  packageName: string;
  packageImportPath?: string;
  functionName: string;
  objectParameterIndex: number;
  objectParameterName: string;
  objectParameterLine: number;
  principalParameterIndexes: number[];
  sink: ObjectSink;
  delegations: EvidencePropagator[];
  wrapperDepth: number;
  wrapperKeys: readonly string[];
}

interface TransactionFinalizerSummary {
  file: GoHttpSourceFile;
  packageName: string;
  packageImportPath?: string;
  functionName: string;
  transactionParameterIndex: number;
  transactionParameterName: string;
  method: "Commit" | "Rollback";
  line: number;
  finalizerFile: GoHttpSourceFile;
  finalizerTransactionName: string;
  delegations: EvidencePropagator[];
}

interface TransactionCreatorSummary {
  file: GoHttpSourceFile;
  packageName: string;
  packageImportPath?: string;
  functionName: string;
  databaseParameterIndex: number;
  databaseParameterName: string;
  receiverKind: "DB" | "Conn";
  method: "Begin" | "BeginTx";
  line: number;
  creatorFile: GoHttpSourceFile;
  creatorReceiverName: string;
  delegations: EvidencePropagator[];
}

interface LocalGoModule {
  root: string;
  importPath: string;
}

interface ResolvedTransactionHelperCall {
  name: string;
  targetLine: number;
  functionValues: EvidencePropagator[];
}

function localGoModules(files: readonly GoHttpSourceFile[]): LocalGoModule[] {
  const modules: LocalGoModule[] = [];
  for (const file of files) {
    if (posix.basename(file.path) !== "go.mod") continue;
    const declarations = file.lines
      .map((line) =>
        /^\s*module\s+(?:"([^"\r\n]+)"|([^\s/][^\s]*))\s*(?:\/\/.*)?$/u.exec(
          line,
        ),
      )
      .filter((match) => match !== null)
      .map((match) => (match[1] ?? match[2]!).trim())
      .filter(
        (importPath) =>
          importPath !== "" &&
          !importPath.includes("\\") &&
          !importPath.startsWith("/") &&
          !importPath.endsWith("/"),
      );
    if (declarations.length !== 1) continue;
    modules.push({
      root: posix.dirname(file.path),
      importPath: declarations[0]!,
    });
  }
  return modules.sort((left, right) => right.root.length - left.root.length);
}

function localPackageImportPath(
  function_: GoFunction,
  modules: readonly LocalGoModule[],
): string | undefined {
  const directory = posix.dirname(function_.file.path);
  const module = modules.find(({ root }) =>
    root === "."
      ? true
      : directory === root || directory.startsWith(`${root}/`),
  );
  if (module === undefined) return undefined;
  const relative =
    module.root === "."
      ? directory === "."
        ? ""
        : directory
      : directory === module.root
        ? ""
        : directory.slice(module.root.length + 1);
  if (relative === "vendor" || relative.startsWith("vendor/")) return undefined;
  return relative === ""
    ? module.importPath
    : `${module.importPath}/${relative}`;
}

function packageAliasIsAvailable(
  function_: GoFunction,
  alias: string,
  line: number,
): boolean {
  if (function_.parameters.some((parameter) => parameter.name === alias))
    return false;
  if (
    function_.receiver !== undefined &&
    new RegExp(`\\(\\s*${escapeRegularExpression(alias)}\\b`, "u").test(
      function_.receiver,
    )
  )
    return false;
  const declaration = new RegExp(
    `\\b(?:var|const)\\s+${escapeRegularExpression(alias)}\\b`,
    "u",
  );
  for (
    let candidateLine = function_.bodyStartLine;
    candidateLine < line;
    candidateLine += 1
  ) {
    const structural = function_.structuralLines[candidateLine - 1] ?? "";
    if (declaration.test(structural)) return false;
    if (goAssignment(structural)?.names.includes(alias) === true) return false;
  }
  return true;
}

function resolvedTransactionHelperCall(
  function_: GoFunction,
  callName: string,
  line: number,
  visiting: ReadonlySet<string> = new Set(),
  depth = 0,
): ResolvedTransactionHelperCall | undefined {
  if (/^[A-Za-z_]\w*\.[A-Za-z_]\w*$/u.test(callName))
    return { name: callName, targetLine: line, functionValues: [] };
  if (!/^[A-Za-z_]\w*$/u.test(callName)) return undefined;
  if (
    depth > MAX_TRANSACTION_FUNCTION_VALUE_DEPTH ||
    visiting.has(callName) ||
    function_.parameters.some((parameter) => parameter.name === callName) ||
    (function_.receiver !== undefined &&
      new RegExp(`\\(\\s*${escapeRegularExpression(callName)}\\b`, "u").test(
        function_.receiver,
      ))
  )
    return undefined;

  let local = false;
  let binding: { target: string; line: number } | undefined;
  const declaration = new RegExp(
    `\\b(?:var|const|type)\\s+${escapeRegularExpression(callName)}\\b`,
    "u",
  );
  for (
    let candidateLine = function_.bodyStartLine;
    candidateLine < line;
    candidateLine += 1
  ) {
    const structural = function_.structuralLines[candidateLine - 1] ?? "";
    const assignment = goAssignment(structural);
    if (assignment?.names.includes(callName) === true) {
      if (local) return undefined;
      local = true;
      binding = undefined;
      if (
        lineNestingDepth(function_, candidateLine) !== 1 ||
        assignment.names.length !== 1 ||
        assignment.names[0] !== callName
      )
        return undefined;
      const target = /^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)$/u.exec(
        assignment.value.trim(),
      )?.[1];
      if (target !== undefined && target !== callName)
        binding = { target, line: candidateLine };
      continue;
    }
    if (declaration.test(structural)) {
      local = true;
      binding = undefined;
    }
  }
  if (!local) return { name: callName, targetLine: line, functionValues: [] };
  if (binding === undefined) return undefined;
  const nextVisiting = new Set(visiting);
  nextVisiting.add(callName);
  const target = resolvedTransactionHelperCall(
    function_,
    binding.target,
    binding.line,
    nextVisiting,
    depth + 1,
  );
  if (target === undefined) return undefined;
  return {
    name: target.name,
    targetLine: target.targetLine,
    functionValues: [
      ...target.functionValues,
      {
        kind: "go-sql-transaction-helper-function-value",
        line: binding.line,
        symbol: binding.target,
        path: function_.file.path,
      },
    ],
  };
}

function transactionSummaryCallMatch(
  function_: GoFunction,
  callName: string,
  line: number,
  summary: {
    file: GoHttpSourceFile;
    packageName: string;
    packageImportPath?: string;
    functionName: string;
  },
): ResolvedTransactionHelperCall | undefined {
  const resolved = resolvedTransactionHelperCall(function_, callName, line);
  if (resolved === undefined) return undefined;
  if (
    summary.functionName === resolved.name &&
    summary.packageName === function_.packageName &&
    posix.dirname(summary.file.path) === posix.dirname(function_.file.path)
  )
    return resolved;
  if (
    summary.packageImportPath === undefined ||
    !/^[A-Z]/u.test(summary.functionName)
  )
    return undefined;
  const qualified = /^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$/u.exec(resolved.name);
  if (qualified?.[2] !== summary.functionName) return undefined;
  const alias = goImportAlias(
    function_.file.lines,
    summary.packageImportPath,
    summary.packageName,
  );
  return alias !== undefined &&
    alias === qualified[1] &&
    packageAliasIsAvailable(function_, alias, resolved.targetLine)
    ? resolved
    : undefined;
}

function sqlAlias(function_: GoFunction): string | undefined {
  return goImportAlias(function_.file.lines, "database/sql", "sql");
}

function requestParameters(function_: GoFunction): string[] {
  return goHttpRequestParameters(function_);
}

function typedReceivers(function_: GoFunction, alias: string): Set<string> {
  return goTypedReceiverNames(function_, [
    { alias, typeNames: ["DB", "Tx", "Conn"] },
  ]);
}

function typedTransactionReceivers(
  function_: GoFunction,
  alias: string,
): Set<string> {
  return goTypedReceiverNames(function_, [{ alias, typeNames: ["Tx"] }]);
}

function typedDatabaseReceivers(
  function_: GoFunction,
  alias: string,
): Set<string> {
  return goTypedReceiverNames(function_, [{ alias, typeNames: ["DB"] }]);
}

function typedConnectionReceivers(
  function_: GoFunction,
  alias: string,
): Set<string> {
  return goTypedReceiverNames(function_, [{ alias, typeNames: ["Conn"] }]);
}

function unquoteGo(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.startsWith("`") && trimmed.endsWith("`")) {
    return trimmed.slice(1, -1);
  }
  if (!trimmed.startsWith('"') || !trimmed.endsWith('"')) return undefined;
  try {
    return JSON.parse(trimmed) as string;
  } catch {
    return undefined;
  }
}

function fixedStrings(function_: GoFunction): Map<string, FixedString> {
  const values = new Map<string, FixedString>();
  for (
    let line = function_.bodyStartLine;
    line <= function_.endLine;
    line += 1
  ) {
    const original = function_.file.lines[line - 1] ?? "";
    const match =
      /^\s*(?:const\s+)?([A-Za-z_]\w*)\s*(?::=|=)\s*((?:`[^`]*`)|(?:"(?:\\.|[^"\\])*"))\s*;?\s*$/u.exec(
        original,
      );
    if (match === null) continue;
    const value = unquoteGo(match[2]!);
    if (value !== undefined) values.set(match[1]!, { value, line });
  }
  return values;
}

function fixedString(
  expression: string,
  values: ReadonlyMap<string, FixedString>,
): FixedString | undefined {
  const literal = unquoteGo(expression);
  if (literal !== undefined) return { value: literal, line: 0 };
  const name = /^([A-Za-z_]\w*)$/u.exec(expression.trim())?.[1];
  return name === undefined ? undefined : values.get(name);
}

function normalizedColumn(value: string): string {
  return (
    value
      .replace(/^[`"[]|[`"\]]$/gu, "")
      .split(".")
      .at(-1)
      ?.toLowerCase() ?? ""
  );
}

function placeholderIndex(token: string): number | undefined {
  if (token === "?") return -1;
  const numbered = /^\$(\d+)$/u.exec(token);
  if (numbered !== null) return Number(numbered[1]) - 1;
  return undefined;
}

function predicates(query: string): Predicate[] {
  const result: Predicate[] = [];
  let sequential = 0;
  const expression =
    /([A-Za-z_][\w.`"\[\]]*)\s*=\s*(\?|\$\d+|[:@][A-Za-z_]\w*)/giu;
  for (const match of query.matchAll(expression)) {
    const placeholder = match[2]!;
    let argumentIndex = placeholderIndex(placeholder);
    if (argumentIndex === -1) {
      argumentIndex = sequential;
      sequential += 1;
    }
    if (argumentIndex !== undefined) {
      result.push({ column: normalizedColumn(match[1]!), argumentIndex });
      continue;
    }
    result.push({
      column: normalizedColumn(match[1]!),
      argumentName: placeholder.slice(1).toLowerCase(),
    });
  }
  return result;
}

function queryPosition(method: string): number | undefined {
  if (/^(?:Exec|Query|QueryRow)$/u.test(method)) return 0;
  if (/^(?:ExecContext|QueryContext|QueryRowContext)$/u.test(method)) return 1;
  return undefined;
}

function preparePosition(method: string): number | undefined {
  if (method === "Prepare") return 0;
  if (method === "PrepareContext") return 1;
  return undefined;
}

function isMutationQuery(query: string): boolean {
  return /^\s*(?:UPDATE|DELETE)\b/iu.test(query);
}

function braceDelta(value: string): number {
  let result = 0;
  for (const character of value) {
    if (character === "{") result += 1;
    if (character === "}") result -= 1;
  }
  return result;
}

function callNestingDepth(function_: GoFunction, call: GoCall): number {
  let depth = 0;
  for (let line = function_.bodyStartLine; line < call.line; line += 1) {
    depth += braceDelta(function_.structuralLines[line - 1] ?? "");
  }
  return depth + braceDelta(call.linePrefix);
}

function lineNestingDepth(function_: GoFunction, line: number): number {
  let depth = 0;
  for (
    let candidateLine = function_.bodyStartLine;
    candidateLine < line;
    candidateLine += 1
  ) {
    depth += braceDelta(function_.structuralLines[candidateLine - 1] ?? "");
  }
  return depth;
}

function transactionCallResultIsReturned(
  function_: GoFunction,
  call: GoCall,
): boolean {
  if (/(?:^|[;{}])\s*return\s*$/u.test(call.linePrefix)) return true;
  const result = assignedCallResult(call);
  if (result === undefined) return false;
  for (let line = call.line + 1; line <= function_.endLine; line += 1) {
    const structural = function_.structuralLines[line - 1] ?? "";
    const assignment = goAssignment(structural);
    if (assignment?.names.includes(result) === true) return false;
    if (lineNestingDepth(function_, line) !== 1) continue;
    if (
      new RegExp(
        `^\\s*return\\s+${escapeRegularExpression(result)}(?:\\s*,|\\s*;|\\s*\\}|\\s*$)`,
        "u",
      ).test(structural)
    )
      return true;
  }
  return false;
}

function exactTransactionReturnSignature(
  function_: GoFunction,
  alias: string,
): boolean {
  const transaction = `(?:[A-Za-z_]\\w*\\s+)?\\*${escapeRegularExpression(alias)}\\.Tx`;
  const error = "(?:[A-Za-z_]\\w*\\s+)?error";
  return new RegExp(
    `^(?:${transaction}|\\(\\s*${transaction}(?:\\s*,\\s*${error})?\\s*\\))$`,
    "u",
  ).test(function_.returnSignature);
}

function hasNoCallArguments(call: GoCall): boolean {
  return call.arguments.every((argument) => argument.trim() === "");
}

function sqlNamedValue(argument: string, alias: string): string {
  const expression = new RegExp(
    `^${escapeRegularExpression(alias)}\\.Named\\s*\\(\\s*[^,]+,(.*)\\)$`,
    "u",
  ).exec(argument.trim());
  return expression?.[1]?.trim() ?? argument;
}

function expressionTaint(
  expression: string,
  taints: ReadonlyMap<string, GoTaint>,
): GoTaint | undefined {
  return referencedTaint(expression, taints)?.taint;
}

function fixedRequestMapSelection(
  expression: string,
  maps: ReadonlySet<string>,
  requests: readonly string[],
  line: number,
): boolean {
  const selection = /^\s*([A-Za-z_]\w*)\s*\[([\s\S]+)\]\s*$/u.exec(expression);
  return (
    selection !== null &&
    maps.has(selection[1]!) &&
    requestSource(selection[2]!, requests, line) !== undefined
  );
}

function principalFromExpression(
  expression: string,
  requests: readonly string[],
  line: number,
): GoTaint | undefined {
  for (const request of requests) {
    const escaped = escapeRegularExpression(request);
    const match = new RegExp(
      `\\b${escaped}\\.Context\\s*\\(\\s*\\)\\.Value\\s*\\(\\s*([A-Za-z_]\\w*)\\s*\\)`,
      "u",
    ).exec(expression);
    if (match !== null && PRINCIPAL_NAME.test(match[1]!)) {
      return {
        kind: "go-http-context-principal",
        line,
        propagators: [],
      };
    }
  }
  return undefined;
}

function namedArgumentValue(
  argumentName: string,
  arguments_: readonly string[],
  alias: string,
): string | undefined {
  const expression = new RegExp(
    `^${escapeRegularExpression(alias)}\\.Named\\s*\\(\\s*[\"\`]${escapeRegularExpression(argumentName)}[\"\`]\\s*,(.*)\\)$`,
    "iu",
  );
  for (const argument of arguments_) {
    const match = expression.exec(argument.trim());
    if (match !== null) return match[1]?.trim();
  }
  return undefined;
}

function predicateArgument(
  predicate: Predicate,
  arguments_: readonly string[],
  alias: string,
): string | undefined {
  if (predicate.argumentName !== undefined) {
    return namedArgumentValue(predicate.argumentName, arguments_, alias);
  }
  const argument =
    predicate.argumentIndex === undefined
      ? undefined
      : arguments_[predicate.argumentIndex];
  return argument === undefined ? undefined : sqlNamedValue(argument, alias);
}

function responseUsesData(
  structural: string,
  names: ReadonlySet<string>,
): boolean {
  if (
    !/(?:\.Write\s*\(|\bio\.WriteString\s*\(|\bfmt\.Fprint(?:f|ln)?\s*\(|\.Encode\s*\()/u.test(
      structural,
    )
  ) {
    return false;
  }
  return [...names].some((name) =>
    new RegExp(`\\b${escapeRegularExpression(name)}\\b`, "u").test(structural),
  );
}

function scanNames(call: GoCall): Set<string> {
  const result = new Set<string>();
  for (const argument of call.arguments) {
    const match = /&?\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)/u.exec(argument);
    if (match === null) continue;
    result.add(match[1]!);
    result.add(match[1]!.split(".")[0]!);
    result.add(match[1]!.split(".").at(-1)!);
  }
  return result;
}

function failClosedComparison(
  function_: GoFunction,
  line: number,
  protectedNames: ReadonlySet<string>,
  principals: ReadonlyMap<string, GoTaint>,
): boolean {
  const structural = function_.structuralLines[line - 1] ?? "";
  if (!/\bif\b/u.test(structural) || !/(?:!=|==)/u.test(structural))
    return false;
  const hasProtected = [...protectedNames].some(
    (name) =>
      PRINCIPAL_NAME.test(name) &&
      new RegExp(`\\b${escapeRegularExpression(name)}\\b`, "u").test(
        structural,
      ),
  );
  const hasPrincipal = [...principals.keys()].some((name) =>
    new RegExp(`\\b${escapeRegularExpression(name)}\\b`, "u").test(structural),
  );
  if (!hasProtected || !hasPrincipal) return false;
  const through = Math.min(function_.endLine, line + 4);
  return function_.structuralLines
    .slice(line - 1, through)
    .some((candidate) => /\breturn\b/u.test(candidate));
}

function callsByLine(function_: GoFunction): Map<number, GoCall[]> {
  const result = new Map<number, GoCall[]>();
  for (const call of goCalls(function_)) {
    const existing = result.get(call.line) ?? [];
    existing.push(call);
    result.set(call.line, existing);
  }
  for (const calls of result.values())
    calls.sort((left, right) => left.offset - right.offset);
  return result;
}

function analyzeFunction(
  function_: GoFunction,
  initialObjects: ReadonlyMap<string, GoTaint> = new Map(),
  initialPrincipals: ReadonlyMap<string, GoTaint> = new Map(),
  finalizers: readonly TransactionFinalizerSummary[] = [],
  creators: readonly TransactionCreatorSummary[] = [],
): ObjectSink[] {
  const alias = sqlAlias(function_);
  if (alias === undefined) return [];
  const requests = requestParameters(function_);
  const receivers = typedReceivers(function_, alias);
  const typedTransactions = typedTransactionReceivers(function_, alias);
  const databaseReceivers = typedDatabaseReceivers(function_, alias);
  const connectionReceivers = typedConnectionReceivers(function_, alias);
  const inferredReceivers = new Set<string>();
  const objects = new Map(initialObjects);
  const principals = new Map(initialPrincipals);
  const strings = fixedStrings(function_);
  const fixedMaps = fixedMapNames(function_);
  const rows = new Map<string, CandidateQuery>();
  const statements = new Map<string, PreparedStatement>();
  const transactions = new Map<string, TransactionState>();
  const chainedStatements = new Map<
    number,
    Array<{ signature: string; statement: PreparedStatement }>
  >();
  for (const receiver of typedTransactions) {
    transactions.set(receiver, {
      active: true,
      pending: [],
      creationEvidence: [],
    });
  }
  const pending: CandidateQuery[] = [];
  const sinks: ObjectSink[] = [];
  const lineCalls = callsByLine(function_);
  const receiverIsTyped = (receiver: string): boolean =>
    receivers.has(receiver) ||
    inferredReceivers.has(receiver) ||
    transactions.has(receiver);
  const recordStatementExecution = (
    statement: PreparedStatement,
    receiver: string,
    method: string,
    call: GoCall,
  ): void => {
    if (
      !statement.active ||
      statement.transaction?.active === false ||
      !/^Exec(?:Context)?$/u.test(method)
    )
      return;
    const argumentIndex = method === "ExecContext" ? 1 : 0;
    const arguments_ = call.rawArguments.slice(argumentIndex);
    const objectPredicate = statement.predicates.find((predicate) => {
      if (!OBJECT_COLUMN.test(predicate.column)) return false;
      const argument = predicateArgument(predicate, arguments_, alias);
      return (
        argument !== undefined &&
        expressionTaint(argument, objects) !== undefined
      );
    });
    if (objectPredicate === undefined) return;
    const objectArgument = predicateArgument(
      objectPredicate,
      arguments_,
      alias,
    )!;
    const source = expressionTaint(objectArgument, objects)!;
    const controls: Array<{ kind: string; line: number }> = [];
    const principalBound = statement.predicates.some((predicate) => {
      if (!SECURITY_COLUMN.test(predicate.column)) return false;
      const argument = predicateArgument(predicate, arguments_, alias);
      return (
        argument !== undefined &&
        expressionTaint(argument, principals) !== undefined
      );
    });
    if (principalBound)
      controls.push({ kind: "principal-bound-object-query", line: call.line });
    const sink: ObjectSink = {
      kind: "go-database-object-mutation",
      line: call.line,
      source,
      propagators: [
        ...source.propagators,
        ...(statement.transaction?.creationEvidence ?? []),
        {
          kind: "go-sql-statement-prepare",
          line: statement.line,
          symbol: receiver,
        },
        ...(statement.transfer === undefined ? [] : [statement.transfer]),
        {
          kind: "go-sql-object-predicate",
          line: statement.line,
          symbol: objectPredicate.column,
        },
        {
          kind: "go-sql-statement-execution",
          line: call.line,
          symbol: receiver,
        },
      ],
      controls,
    };
    if (statement.transaction === undefined) sinks.push(sink);
    else statement.transaction.pending.push(sink);
  };
  const finalizeTransaction = (
    transaction: TransactionState,
    method: "Commit" | "Rollback",
    line: number,
    evidence: readonly EvidencePropagator[],
  ): void => {
    if (!transaction.active) return;
    if (method === "Rollback") {
      transaction.pending.length = 0;
      transaction.active = false;
      return;
    }
    for (const pendingMutation of transaction.pending) {
      sinks.push({
        ...pendingMutation,
        kind: "go-database-object-committed-mutation",
        line,
        propagators: [...pendingMutation.propagators, ...evidence],
      });
    }
    transaction.pending.length = 0;
    transaction.active = false;
  };

  for (
    let line = function_.bodyStartLine;
    line <= function_.endLine;
    line += 1
  ) {
    const structural = function_.structuralLines[line - 1] ?? "";
    const assigned = goAssignment(structural);
    if (assigned !== undefined) {
      const primary = assigned.names[0]!;
      const rowAlias = rows.get(assigned.value.trim());
      const statementAlias = statements.get(assigned.value.trim());
      const transactionAlias = transactions.get(assigned.value.trim());
      const databaseAlias = databaseReceivers.has(assigned.value.trim());
      const connectionAlias = connectionReceivers.has(assigned.value.trim());
      const objectSource =
        requestSource(assigned.value, requests, line) ??
        expressionTaint(assigned.value, objects);
      const fixedObjectSelection =
        fixedMapSelection(assigned.value, fixedMaps, objects) ||
        fixedRequestMapSelection(assigned.value, fixedMaps, requests, line);
      const principalSource =
        principalFromExpression(assigned.value, requests, line) ??
        expressionTaint(assigned.value, principals);
      for (const name of assigned.names) {
        objects.delete(name);
        principals.delete(name);
        inferredReceivers.delete(name);
        databaseReceivers.delete(name);
        connectionReceivers.delete(name);
        rows.delete(name);
        statements.delete(name);
        transactions.delete(name);
      }
      if (objectSource !== undefined && !fixedObjectSelection) {
        objects.set(primary, {
          ...objectSource,
          propagators: [
            ...objectSource.propagators,
            { kind: "go-object-identifier-assignment", line, symbol: primary },
          ],
        });
      }
      if (principalSource !== undefined) {
        principals.set(primary, {
          ...principalSource,
          propagators: [
            ...principalSource.propagators,
            { kind: "go-context-principal-assignment", line, symbol: primary },
          ],
        });
      }
      if (rowAlias !== undefined) rows.set(primary, rowAlias);
      if (statementAlias !== undefined) statements.set(primary, statementAlias);
      if (transactionAlias !== undefined) {
        transactions.set(primary, transactionAlias);
        inferredReceivers.add(primary);
      }
      if (databaseAlias) {
        databaseReceivers.add(primary);
        inferredReceivers.add(primary);
      }
      if (connectionAlias) {
        connectionReceivers.add(primary);
        inferredReceivers.add(primary);
      }
      for (const candidate of pending) {
        if (
          [...candidate.scannedNames].some((name) =>
            new RegExp(`\\b${escapeRegularExpression(name)}\\b`, "u").test(
              assigned.value,
            ),
          )
        ) {
          candidate.scannedNames.add(primary);
        }
      }
    }

    for (const call of lineCalls.get(line) ?? []) {
      const result = assignedCallResult(call);
      const packageOpen = new RegExp(
        `^${escapeRegularExpression(alias)}\\.(?:Open|OpenDB)$`,
        "u",
      ).test(call.name);
      if (packageOpen && result !== undefined) {
        inferredReceivers.add(result);
        databaseReceivers.add(result);
        continue;
      }
      if (call.name === "Scan") {
        const candidate = pending.at(-1);
        if (
          candidate !== undefined &&
          candidate.mode === "row" &&
          line === candidate.line
        ) {
          for (const name of scanNames(call)) candidate.scannedNames.add(name);
          candidate.propagators.push({
            kind: "go-sql-row-scan",
            line,
            symbol: [...candidate.scannedNames].join(","),
          });
        }
        continue;
      }
      if (/^Exec(?:Context)?$/u.test(call.name)) {
        const compactPrefix = call.linePrefix.replace(/\s+/gu, "");
        const chained = chainedStatements
          .get(line)
          ?.find(({ signature }) => compactPrefix.endsWith(signature));
        if (chained !== undefined) {
          recordStatementExecution(
            chained.statement,
            chained.statement.transfer?.symbol ?? "transaction-statement",
            call.name,
            call,
          );
          continue;
        }
      }
      const matchingFinalizers = finalizers.flatMap((summary) => {
        const match = transactionSummaryCallMatch(
          function_,
          call.name,
          line,
          summary,
        );
        return match === undefined ? [] : [{ summary, match }];
      });
      if (matchingFinalizers.length === 1) {
        const { summary, match } = matchingFinalizers[0]!;
        const transactionName =
          call.rawArguments[summary.transactionParameterIndex]?.trim();
        const transaction =
          transactionName === undefined
            ? undefined
            : transactions.get(transactionName);
        if (
          transaction !== undefined &&
          transaction.active &&
          !/\bdefer\b/u.test(structural) &&
          callNestingDepth(function_, call) === 1
        ) {
          finalizeTransaction(transaction, summary.method, line, [
            ...match.functionValues,
            {
              kind: "go-sql-transaction-finalizer-helper",
              line,
              symbol: summary.functionName,
            },
            ...(summary.method === "Commit"
              ? [
                  ...summary.delegations,
                  {
                    kind: "go-sql-transaction-commit",
                    line: summary.line,
                    symbol: summary.finalizerTransactionName,
                    path: summary.finalizerFile.path,
                  },
                ]
              : []),
          ]);
          continue;
        }
      }
      const matchingCreators = creators.flatMap((summary) => {
        const match = transactionSummaryCallMatch(
          function_,
          call.name,
          line,
          summary,
        );
        return match === undefined ? [] : [{ summary, match }];
      });
      if (matchingCreators.length === 1 && result !== undefined) {
        const { summary, match } = matchingCreators[0]!;
        const databaseName =
          call.rawArguments[summary.databaseParameterIndex]?.trim();
        const databaseMatches =
          databaseName !== undefined &&
          (summary.receiverKind === "DB"
            ? databaseReceivers.has(databaseName)
            : connectionReceivers.has(databaseName));
        if (
          databaseMatches &&
          !/\bdefer\b/u.test(structural) &&
          callNestingDepth(function_, call) === 1
        ) {
          inferredReceivers.add(result);
          transactions.set(result, {
            active: true,
            pending: [],
            creationEvidence: [
              ...match.functionValues,
              {
                kind: "go-sql-transaction-begin-helper",
                line,
                symbol: summary.functionName,
              },
              ...summary.delegations,
              {
                kind: "go-sql-transaction-begin",
                line: summary.line,
                symbol: summary.creatorReceiverName,
                path: summary.creatorFile.path,
              },
            ],
          });
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
        ((method === "Begin" && databaseReceivers.has(receiver)) ||
          (method === "BeginTx" &&
            (databaseReceivers.has(receiver) ||
              connectionReceivers.has(receiver))))
      ) {
        inferredReceivers.add(result);
        transactions.set(result, {
          active: true,
          pending: [],
          creationEvidence: [],
        });
        continue;
      }
      if (
        result !== undefined &&
        receiverIsTyped(receiver) &&
        method === "Conn"
      ) {
        inferredReceivers.add(result);
        connectionReceivers.add(result);
        continue;
      }

      const transaction = transactions.get(receiver);
      if (
        transaction !== undefined &&
        /^(?:Commit|Rollback)$/u.test(method) &&
        hasNoCallArguments(call)
      ) {
        if (
          !transaction.active ||
          /\bdefer\b/u.test(structural) ||
          callNestingDepth(function_, call) !== 1
        ) {
          continue;
        }
        finalizeTransaction(
          transaction,
          method === "Commit" ? "Commit" : "Rollback",
          line,
          [
            {
              kind: "go-sql-transaction-commit",
              line,
              symbol: receiver,
            },
          ],
        );
        continue;
      }

      if (
        transaction?.active === true &&
        /^(?:Stmt|StmtContext)$/u.test(method)
      ) {
        const sourceIndex = method === "StmtContext" ? 1 : 0;
        const sourceName = call.rawArguments[sourceIndex]?.trim();
        const sourceStatement =
          sourceName === undefined ? undefined : statements.get(sourceName);
        if (
          sourceStatement !== undefined &&
          sourceStatement.active &&
          (sourceStatement.transaction === undefined ||
            sourceStatement.transaction === transaction)
        ) {
          const transferred: PreparedStatement = {
            line: sourceStatement.line,
            predicates: sourceStatement.predicates,
            active: true,
            transaction,
            transfer: {
              kind: "go-sql-transaction-statement-transfer",
              line,
              symbol: result ?? `${receiver}.${method}`,
            },
          };
          const signature = `${receiver}.${method}(${call.arguments
            .map((argument) => argument.replace(/\s+/gu, ""))
            .join(",")}).`;
          const directExecution = (lineCalls.get(line) ?? []).some(
            (candidate) =>
              candidate.offset > call.offset &&
              /^Exec(?:Context)?$/u.test(candidate.name) &&
              candidate.linePrefix.replace(/\s+/gu, "").endsWith(signature),
          );
          if (result !== undefined && !directExecution)
            statements.set(result, transferred);
          else if (directExecution) {
            const existing = chainedStatements.get(line) ?? [];
            existing.push({ signature, statement: transferred });
            chainedStatements.set(line, existing);
          }
        }
        continue;
      }

      const prepareIndex = receiverIsTyped(receiver)
        ? preparePosition(method)
        : undefined;
      if (prepareIndex !== undefined) {
        const queryExpression = call.rawArguments[prepareIndex];
        const query =
          queryExpression === undefined
            ? undefined
            : fixedString(queryExpression, strings)?.value;
        if (
          result !== undefined &&
          query !== undefined &&
          isMutationQuery(query)
        ) {
          statements.set(result, {
            line,
            predicates: predicates(query),
            active: true,
            ...(transaction === undefined ? {} : { transaction }),
          });
        }
        continue;
      }

      const statement = statements.get(receiver);
      if (statement !== undefined) {
        if (method === "Close") {
          if (!/\bdefer\b/u.test(structural)) statement.active = false;
          continue;
        }
        recordStatementExecution(statement, receiver, method, call);
        continue;
      }

      const queryIndex = receiverIsTyped(receiver)
        ? queryPosition(method)
        : undefined;
      if (queryIndex !== undefined) {
        const queryExpression = call.rawArguments[queryIndex];
        const query =
          queryExpression === undefined
            ? undefined
            : fixedString(queryExpression, strings)?.value;
        if (query === undefined) continue;
        const arguments_ = call.rawArguments.slice(queryIndex + 1);
        const parsed = predicates(query);
        const objectPredicate = parsed.find((predicate) => {
          if (!OBJECT_COLUMN.test(predicate.column)) return false;
          const argument = predicateArgument(predicate, arguments_, alias);
          return (
            argument !== undefined &&
            expressionTaint(argument, objects) !== undefined
          );
        });
        if (objectPredicate === undefined) continue;
        const objectArgument = predicateArgument(
          objectPredicate,
          arguments_,
          alias,
        )!;
        const source = expressionTaint(objectArgument, objects)!;
        const controls: Array<{ kind: string; line: number }> = [];
        const principalBound = parsed.some((predicate) => {
          if (!SECURITY_COLUMN.test(predicate.column)) return false;
          const argument = predicateArgument(predicate, arguments_, alias);
          return (
            argument !== undefined &&
            expressionTaint(argument, principals) !== undefined
          );
        });
        if (principalBound)
          controls.push({ kind: "principal-bound-object-query", line });
        const propagators = [
          ...source.propagators,
          {
            kind: "go-sql-object-predicate",
            line,
            symbol: objectPredicate.column,
          },
        ];
        if (/^Exec(?:Context)?$/u.test(method) && isMutationQuery(query)) {
          const sink: ObjectSink = {
            kind: "go-database-object-mutation",
            line,
            source,
            propagators: [
              ...propagators,
              ...(transaction?.creationEvidence ?? []),
              { kind: "go-sql-mutation-execution", line, symbol: receiver },
            ],
            controls,
          };
          if (transaction === undefined) sinks.push(sink);
          else if (transaction.active) transaction.pending.push(sink);
          continue;
        }
        if (
          !/^Query(?:Row)?(?:Context)?$/u.test(method) ||
          !/^\s*SELECT\b/iu.test(query)
        )
          continue;
        const candidate: CandidateQuery = {
          mode: /^QueryRow/u.test(method) ? "row" : "rows",
          line,
          method,
          source,
          result,
          iterated: false,
          scannedNames: new Set(),
          propagators,
          controls,
        };
        pending.push(candidate);
        if (result !== undefined) rows.set(result, candidate);
        continue;
      }

      if (method === "Next") {
        const candidate = rows.get(receiver);
        if (candidate === undefined || candidate.mode !== "rows") continue;
        if (
          !new RegExp(
            `\\b(?:for|if)\\b[^\\r\\n]*\\b${escapeRegularExpression(receiver)}\\.Next\\s*\\(`,
            "u",
          ).test(structural)
        )
          continue;
        candidate.iterated = true;
        if (
          !candidate.propagators.some(
            (propagator) =>
              propagator.kind === "go-sql-rows-iteration" &&
              propagator.line === line,
          )
        ) {
          candidate.propagators.push({
            kind: "go-sql-rows-iteration",
            line,
            symbol: receiver,
          });
        }
        continue;
      }

      if (method === "Scan") {
        const candidate = rows.get(receiver);
        if (candidate === undefined || line < candidate.line) continue;
        if (candidate.mode === "rows" && !candidate.iterated) continue;
        for (const name of scanNames(call)) candidate.scannedNames.add(name);
        candidate.propagators.push({
          kind:
            candidate.mode === "rows" ? "go-sql-rows-scan" : "go-sql-row-scan",
          line,
          symbol: [...candidate.scannedNames].join(","),
        });
      }
    }

    for (const candidate of pending) {
      if (candidate.scannedNames.size === 0 || line < candidate.line) continue;
      if (
        failClosedComparison(
          function_,
          line,
          candidate.scannedNames,
          principals,
        )
      ) {
        if (
          !candidate.controls.some(
            (control) => control.kind === "post-lookup-principal-check",
          )
        ) {
          candidate.controls.push({
            kind: "post-lookup-principal-check",
            line,
          });
        }
      }
      if (!responseUsesData(structural, candidate.scannedNames)) continue;
      sinks.push({
        kind:
          candidate.mode === "rows"
            ? "go-database-object-collection-response"
            : "go-database-object-read-response",
        line,
        source: candidate.source,
        propagators: [
          ...candidate.propagators,
          { kind: "go-http-protected-response", line },
        ],
        controls: candidate.controls,
      });
      pending.splice(pending.indexOf(candidate), 1);
      if (candidate.result !== undefined) rows.delete(candidate.result);
      break;
    }
  }
  return sinks;
}

function callerTaints(
  function_: GoFunction,
  callLine: number,
): { objects: Map<string, GoTaint>; principals: Map<string, GoTaint> } {
  const requests = requestParameters(function_);
  const objects = new Map<string, GoTaint>();
  const principals = new Map<string, GoTaint>();
  const fixedMaps = fixedMapNames(function_);
  for (let line = function_.bodyStartLine; line < callLine; line += 1) {
    const assigned = goAssignment(function_.structuralLines[line - 1] ?? "");
    if (assigned === undefined) continue;
    const primary = assigned.names[0]!;
    const objectSource =
      requestSource(assigned.value, requests, line) ??
      expressionTaint(assigned.value, objects);
    const fixedObjectSelection =
      fixedMapSelection(assigned.value, fixedMaps, objects) ||
      fixedRequestMapSelection(assigned.value, fixedMaps, requests, line);
    const principalSource =
      principalFromExpression(assigned.value, requests, line) ??
      expressionTaint(assigned.value, principals);
    for (const name of assigned.names) {
      objects.delete(name);
      principals.delete(name);
    }
    if (objectSource !== undefined && !fixedObjectSelection) {
      objects.set(primary, {
        ...objectSource,
        propagators: [
          ...objectSource.propagators,
          { kind: "go-object-identifier-assignment", line, symbol: primary },
        ],
      });
    }
    if (principalSource !== undefined) {
      principals.set(primary, {
        ...principalSource,
        propagators: [
          ...principalSource.propagators,
          { kind: "go-context-principal-assignment", line, symbol: primary },
        ],
      });
    }
  }
  return { objects, principals };
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
  sink: ObjectSink,
  propagators: readonly EvidencePropagator[],
): GoObjectAuthorizationRecord {
  const startLine = Math.max(1, sink.line - CONTEXT_LINES_BEFORE);
  const endLine = Math.min(
    sinkFile.lines.length,
    sink.line + CONTEXT_LINES_AFTER,
  );
  const sourceStart = Math.max(1, source.line - 2);
  const sourceEnd = Math.min(sourceFile.lines.length, source.line + 2);
  const wrapperBoundary = propagators.findIndex(
    (propagator) => propagator.kind === "go-function-argument",
  );
  return {
    path: sinkFile.path,
    line: sink.line,
    categories: [
      "framework-dataflow:go-http-object-authorization",
      `modeled-source:${source.kind}`,
      `modeled-sink:${sink.kind}`,
      ...sink.controls.map((control) => `candidate-control:${control.kind}`),
    ],
    priority: 130,
    startLine,
    endLine,
    excerpt: excerpt(sinkFile.lines, startLine, endLine),
    sourceExcerpt: excerpt(sourceFile.lines, sourceStart, sourceEnd),
    frameworkModel: {
      schemaVersion: "1.2",
      id: "go-http-object-authorization",
      language: "go",
      scope,
      source: { kind: source.kind, path: sourceFile.path, line: source.line },
      sink: {
        kind: sink.kind,
        path: sinkFile.path,
        line: sink.line,
        cweIds: ["CWE-639", "CWE-862"],
      },
      propagators: propagators.map((propagator, index) => ({
        ...propagator,
        path:
          propagator.path ??
          (scope === "cross-file-wrapper" &&
          wrapperBoundary >= 0 &&
          index <= wrapperBoundary
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

function transactionCreatorSummaries(
  files: readonly GoHttpSourceFile[],
  functions: readonly GoFunction[],
  functionCounts: ReadonlyMap<string, number>,
): TransactionCreatorSummary[] {
  interface DatabaseParameter {
    index: number;
    name: string;
    kind: "DB" | "Conn";
  }
  interface Descriptor {
    function_: GoFunction;
    parameters: DatabaseParameter[];
    importPath?: string;
  }
  type Resolution =
    | { kind: "none" }
    | { kind: "ambiguous" }
    | { kind: "exact"; summary: TransactionCreatorSummary };

  const functionKey = (function_: GoFunction): string =>
    `${posix.dirname(function_.file.path)}\0${function_.packageName}\0${function_.name}`;
  const modules = localGoModules(files);
  const descriptors = new Map<string, Descriptor>();
  for (const function_ of functions) {
    if (function_.receiver !== undefined) continue;
    const alias = sqlAlias(function_);
    if (
      alias === undefined ||
      !exactTransactionReturnSignature(function_, alias)
    )
      continue;
    const key = functionKey(function_);
    if (functionCounts.get(key) !== 1) continue;
    const parameters = function_.parameters.flatMap(
      (parameter, index): DatabaseParameter[] => {
        const type = parameter.type.replace(/\s+/gu, "");
        if (type === `*${alias}.DB`)
          return [{ index, name: parameter.name, kind: "DB" }];
        if (type === `*${alias}.Conn`)
          return [{ index, name: parameter.name, kind: "Conn" }];
        return [];
      },
    );
    if (parameters.length === 0) continue;
    const importPath = localPackageImportPath(function_, modules);
    descriptors.set(key, {
      function_,
      parameters,
      ...(importPath === undefined ? {} : { importPath }),
    });
  }

  const aliasesAtLine = (
    descriptor: Descriptor,
    parameterName: string,
    line: number,
  ): Set<string> => {
    const aliases = new Set([parameterName]);
    for (
      let candidateLine = descriptor.function_.bodyStartLine;
      candidateLine < line;
      candidateLine += 1
    ) {
      const assignment = goAssignment(
        descriptor.function_.structuralLines[candidateLine - 1] ?? "",
      );
      if (assignment === undefined) continue;
      const preservesIdentity = aliases.has(assignment.value.trim());
      for (const name of assignment.names) aliases.delete(name);
      if (preservesIdentity && assignment.names[0] !== undefined)
        aliases.add(assignment.names[0]);
    }
    return aliases;
  };
  const parameterForName = (
    descriptor: Descriptor,
    name: string,
    line: number,
  ): DatabaseParameter | undefined => {
    const matching = descriptor.parameters.filter(({ name: parameterName }) =>
      aliasesAtLine(descriptor, parameterName, line).has(name),
    );
    return matching.length === 1 ? matching[0] : undefined;
  };
  const memo = new Map<string, Resolution>();
  const resolve = (
    key: string,
    visiting: ReadonlySet<string>,
    depth: number,
  ): Resolution => {
    const cached = memo.get(key);
    if (cached !== undefined) return cached;
    if (depth >= MAX_TRANSACTION_HELPER_DEPTH || visiting.has(key))
      return { kind: "ambiguous" };
    const descriptor = descriptors.get(key);
    if (descriptor === undefined) return { kind: "none" };
    const nextVisiting = new Set(visiting);
    nextVisiting.add(key);
    const candidates: TransactionCreatorSummary[] = [];
    for (const call of goCalls(descriptor.function_)) {
      const structural =
        descriptor.function_.structuralLines[call.line - 1] ?? "";
      if (/\bdefer\b/u.test(structural)) continue;
      const returnsTransaction = transactionCallResultIsReturned(
        descriptor.function_,
        call,
      );
      if (!returnsTransaction) continue;
      if (callNestingDepth(descriptor.function_, call) !== 1) {
        const result: Resolution = { kind: "ambiguous" };
        memo.set(key, result);
        return result;
      }
      const receiverCall = /^([A-Za-z_]\w*)\.(Begin|BeginTx)$/u.exec(call.name);
      if (receiverCall !== null) {
        const parameter = parameterForName(
          descriptor,
          receiverCall[1]!,
          call.line,
        );
        const method = receiverCall[2] as "Begin" | "BeginTx";
        const argumentShapeMatches =
          (method === "Begin" &&
            parameter?.kind === "DB" &&
            hasNoCallArguments(call)) ||
          (method === "BeginTx" &&
            parameter !== undefined &&
            call.rawArguments.length === 2 &&
            call.rawArguments.every((argument) => argument.trim() !== ""));
        if (parameter !== undefined && argumentShapeMatches) {
          candidates.push({
            file: descriptor.function_.file,
            packageName: descriptor.function_.packageName,
            ...(descriptor.importPath === undefined
              ? {}
              : { packageImportPath: descriptor.importPath }),
            functionName: descriptor.function_.name,
            databaseParameterIndex: parameter.index,
            databaseParameterName: parameter.name,
            receiverKind: parameter.kind,
            method,
            line: call.line,
            creatorFile: descriptor.function_.file,
            creatorReceiverName: receiverCall[1]!,
            delegations: [],
          });
        }
        continue;
      }
      const resolvedCall = resolvedTransactionHelperCall(
        descriptor.function_,
        call.name,
        call.line,
      );
      if (resolvedCall === undefined) continue;
      const plainCall = /^([A-Za-z_]\w*)$/u.exec(resolvedCall.name);
      const qualifiedCall = /^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$/u.exec(
        resolvedCall.name,
      );
      const targets: Array<{ key: string; descriptor: Descriptor }> = [];
      if (plainCall !== null) {
        const targetKey = `${posix.dirname(descriptor.function_.file.path)}\0${descriptor.function_.packageName}\0${plainCall[1]}`;
        const target = descriptors.get(targetKey);
        if (target !== undefined)
          targets.push({ key: targetKey, descriptor: target });
      } else if (
        qualifiedCall !== null &&
        /^[A-Z]/u.test(qualifiedCall[2]!) &&
        packageAliasIsAvailable(
          descriptor.function_,
          qualifiedCall[1]!,
          resolvedCall.targetLine,
        )
      ) {
        for (const [targetKey, target] of descriptors) {
          if (
            target.importPath === undefined ||
            target.function_.name !== qualifiedCall[2]
          )
            continue;
          const importAlias = goImportAlias(
            descriptor.function_.file.lines,
            target.importPath,
            target.function_.packageName,
          );
          if (importAlias === qualifiedCall[1])
            targets.push({ key: targetKey, descriptor: target });
        }
      }
      if (targets.length === 0) continue;
      const passesDatabaseParameter = targets.some(({ descriptor: target }) =>
        target.parameters.some(({ index, kind }) => {
          const argument = call.rawArguments[index]?.trim();
          const parameter =
            argument === undefined
              ? undefined
              : parameterForName(descriptor, argument, call.line);
          return parameter?.kind === kind;
        }),
      );
      if (!passesDatabaseParameter) continue;
      if (targets.length !== 1) {
        const result: Resolution = { kind: "ambiguous" };
        memo.set(key, result);
        return result;
      }
      const target = resolve(targets[0]!.key, nextVisiting, depth + 1);
      if (target.kind === "ambiguous") {
        const result: Resolution = { kind: "ambiguous" };
        memo.set(key, result);
        return result;
      }
      if (target.kind === "none") continue;
      const argument =
        call.rawArguments[target.summary.databaseParameterIndex]?.trim();
      const parameter =
        argument === undefined
          ? undefined
          : parameterForName(descriptor, argument, call.line);
      if (
        parameter === undefined ||
        parameter.kind !== target.summary.receiverKind
      )
        continue;
      candidates.push({
        file: descriptor.function_.file,
        packageName: descriptor.function_.packageName,
        ...(descriptor.importPath === undefined
          ? {}
          : { packageImportPath: descriptor.importPath }),
        functionName: descriptor.function_.name,
        databaseParameterIndex: parameter.index,
        databaseParameterName: parameter.name,
        receiverKind: parameter.kind,
        method: target.summary.method,
        line: target.summary.line,
        creatorFile: target.summary.creatorFile,
        creatorReceiverName: target.summary.creatorReceiverName,
        delegations: [
          ...resolvedCall.functionValues,
          {
            kind: "go-sql-transaction-begin-helper",
            line: call.line,
            symbol: target.summary.functionName,
            path: descriptor.function_.file.path,
          },
          ...target.summary.delegations,
        ],
      });
    }
    const result: Resolution =
      candidates.length === 0
        ? { kind: "none" }
        : candidates.length === 1
          ? { kind: "exact", summary: candidates[0]! }
          : { kind: "ambiguous" };
    memo.set(key, result);
    return result;
  };

  const summaries: TransactionCreatorSummary[] = [];
  for (const key of descriptors.keys()) {
    const resolution = resolve(key, new Set(), 0);
    if (resolution.kind === "exact") summaries.push(resolution.summary);
  }
  return summaries;
}

function transactionFinalizerSummaries(
  files: readonly GoHttpSourceFile[],
  functions: readonly GoFunction[],
  functionCounts: ReadonlyMap<string, number>,
): TransactionFinalizerSummary[] {
  interface Descriptor {
    function_: GoFunction;
    parameters: Array<{
      index: number;
      name: string;
    }>;
    importPath?: string;
  }
  type Resolution =
    | { kind: "none" }
    | { kind: "ambiguous" }
    | { kind: "exact"; summary: TransactionFinalizerSummary };

  const functionKey = (function_: GoFunction): string =>
    `${posix.dirname(function_.file.path)}\0${function_.packageName}\0${function_.name}`;
  const modules = localGoModules(files);
  const descriptors = new Map<string, Descriptor>();
  for (const function_ of functions) {
    if (function_.receiver !== undefined) continue;
    const alias = sqlAlias(function_);
    if (alias === undefined) continue;
    const key = functionKey(function_);
    if (functionCounts.get(key) !== 1) continue;
    const parameters = function_.parameters
      .map((parameter, index) => ({ parameter, index }))
      .filter(({ parameter }) =>
        new RegExp(`^\\*?${escapeRegularExpression(alias)}\\.Tx$`, "u").test(
          parameter.type.replace(/\s+/gu, ""),
        ),
      )
      .map(({ parameter, index }) => ({
        index,
        name: parameter.name,
      }));
    if (parameters.length > 0) {
      const importPath = localPackageImportPath(function_, modules);
      descriptors.set(key, {
        function_,
        parameters,
        ...(importPath === undefined ? {} : { importPath }),
      });
    }
  }

  const aliasesAtLine = (
    descriptor: Descriptor,
    parameterName: string,
    line: number,
  ): Set<string> => {
    const aliases = new Set([parameterName]);
    for (
      let candidateLine = descriptor.function_.bodyStartLine;
      candidateLine < line;
      candidateLine += 1
    ) {
      const assignment = goAssignment(
        descriptor.function_.structuralLines[candidateLine - 1] ?? "",
      );
      if (assignment === undefined) continue;
      const preservesIdentity = aliases.has(assignment.value.trim());
      for (const name of assignment.names) aliases.delete(name);
      if (preservesIdentity && assignment.names[0] !== undefined)
        aliases.add(assignment.names[0]);
    }
    return aliases;
  };
  const parameterForName = (
    descriptor: Descriptor,
    name: string,
    line: number,
  ): { index: number; name: string } | undefined => {
    const matching = descriptor.parameters.filter(({ name: parameterName }) =>
      aliasesAtLine(descriptor, parameterName, line).has(name),
    );
    return matching.length === 1 ? matching[0] : undefined;
  };
  const memo = new Map<string, Resolution>();
  const resolve = (
    key: string,
    visiting: ReadonlySet<string>,
    depth: number,
  ): Resolution => {
    const cached = memo.get(key);
    if (cached !== undefined) return cached;
    if (depth >= MAX_TRANSACTION_HELPER_DEPTH || visiting.has(key))
      return { kind: "ambiguous" };
    const descriptor = descriptors.get(key);
    if (descriptor === undefined) return { kind: "none" };
    const nextVisiting = new Set(visiting);
    nextVisiting.add(key);
    const candidates: TransactionFinalizerSummary[] = [];
    for (const call of goCalls(descriptor.function_)) {
      const structural =
        descriptor.function_.structuralLines[call.line - 1] ?? "";
      if (
        /\bdefer\b/u.test(structural) ||
        callNestingDepth(descriptor.function_, call) !== 1
      )
        continue;
      const receiverCall = /^([A-Za-z_]\w*)\.(Commit|Rollback)$/u.exec(
        call.name,
      );
      if (receiverCall !== null && hasNoCallArguments(call)) {
        const parameter = parameterForName(
          descriptor,
          receiverCall[1]!,
          call.line,
        );
        if (parameter !== undefined)
          candidates.push({
            file: descriptor.function_.file,
            packageName: descriptor.function_.packageName,
            ...(descriptor.importPath === undefined
              ? {}
              : { packageImportPath: descriptor.importPath }),
            functionName: descriptor.function_.name,
            transactionParameterIndex: parameter.index,
            transactionParameterName: parameter.name,
            method: receiverCall[2] as "Commit" | "Rollback",
            line: call.line,
            finalizerFile: descriptor.function_.file,
            finalizerTransactionName: receiverCall[1]!,
            delegations: [],
          });
        continue;
      }
      const resolvedCall = resolvedTransactionHelperCall(
        descriptor.function_,
        call.name,
        call.line,
      );
      if (resolvedCall === undefined) continue;
      const plainCall = /^([A-Za-z_]\w*)$/u.exec(resolvedCall.name);
      const qualifiedCall = /^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$/u.exec(
        resolvedCall.name,
      );
      const targets: Array<{ key: string; descriptor: Descriptor }> = [];
      if (plainCall !== null) {
        const targetKey = `${posix.dirname(descriptor.function_.file.path)}\0${descriptor.function_.packageName}\0${plainCall[1]}`;
        const target = descriptors.get(targetKey);
        if (target !== undefined)
          targets.push({ key: targetKey, descriptor: target });
      } else if (
        qualifiedCall !== null &&
        /^[A-Z]/u.test(qualifiedCall[2]!) &&
        packageAliasIsAvailable(
          descriptor.function_,
          qualifiedCall[1]!,
          resolvedCall.targetLine,
        )
      ) {
        for (const [targetKey, target] of descriptors) {
          if (
            target.importPath === undefined ||
            target.function_.name !== qualifiedCall[2]
          )
            continue;
          const importAlias = goImportAlias(
            descriptor.function_.file.lines,
            target.importPath,
            target.function_.packageName,
          );
          if (importAlias === qualifiedCall[1])
            targets.push({ key: targetKey, descriptor: target });
        }
      }
      if (targets.length === 0) continue;
      const passesTransactionParameter = targets.some(
        ({ descriptor: target }) =>
          target.parameters.some(({ index }) => {
            const argument = call.rawArguments[index]?.trim();
            return (
              argument !== undefined &&
              parameterForName(descriptor, argument, call.line) !== undefined
            );
          }),
      );
      if (!passesTransactionParameter) continue;
      if (targets.length !== 1) {
        const result: Resolution = { kind: "ambiguous" };
        memo.set(key, result);
        return result;
      }
      const targetKey = targets[0]!.key;
      const target = resolve(targetKey, nextVisiting, depth + 1);
      if (target.kind === "ambiguous") {
        const result: Resolution = { kind: "ambiguous" };
        memo.set(key, result);
        return result;
      }
      if (target.kind === "none") continue;
      const argument =
        call.rawArguments[target.summary.transactionParameterIndex]?.trim();
      const parameter =
        argument === undefined
          ? undefined
          : parameterForName(descriptor, argument, call.line);
      if (parameter === undefined) continue;
      candidates.push({
        file: descriptor.function_.file,
        packageName: descriptor.function_.packageName,
        ...(descriptor.importPath === undefined
          ? {}
          : { packageImportPath: descriptor.importPath }),
        functionName: descriptor.function_.name,
        transactionParameterIndex: parameter.index,
        transactionParameterName: parameter.name,
        method: target.summary.method,
        line: target.summary.line,
        finalizerFile: target.summary.finalizerFile,
        finalizerTransactionName: target.summary.finalizerTransactionName,
        delegations: [
          ...resolvedCall.functionValues,
          {
            kind: "go-sql-transaction-finalizer-helper",
            line: call.line,
            symbol: target.summary.functionName,
            path: descriptor.function_.file.path,
          },
          ...target.summary.delegations,
        ],
      });
    }
    const result: Resolution =
      candidates.length === 0
        ? { kind: "none" }
        : candidates.length === 1
          ? { kind: "exact", summary: candidates[0]! }
          : { kind: "ambiguous" };
    memo.set(key, result);
    return result;
  };

  const summaries: TransactionFinalizerSummary[] = [];
  for (const key of descriptors.keys()) {
    const resolution = resolve(key, new Set(), 0);
    if (resolution.kind === "exact") summaries.push(resolution.summary);
  }
  return summaries;
}

function objectWrapperSummaries(
  files: readonly GoHttpSourceFile[],
  functions: readonly GoFunction[],
  functionCounts: ReadonlyMap<string, number>,
  finalizers: readonly TransactionFinalizerSummary[],
  creators: readonly TransactionCreatorSummary[],
): WrapperSummary[] {
  interface StringParameter {
    index: number;
    name: string;
  }
  interface Descriptor {
    function_: GoFunction;
    parameters: StringParameter[];
    importPath?: string;
  }
  interface Edge {
    sourceKey: string;
    source: Descriptor;
    sourceParameter: StringParameter;
    targetKey: string;
    target: Descriptor;
    call: GoCall;
    objectPropagators: EvidencePropagator[];
  }
  interface ParameterFlow {
    index: number;
    propagators: EvidencePropagator[];
  }

  const functionKey = (function_: GoFunction): string =>
    `${posix.dirname(function_.file.path)}\0${function_.packageName}\0${function_.name}`;
  const parameterKey = (function_: GoFunction, index: number): string =>
    `${functionKey(function_)}\0${index}`;
  const summaryParameterKey = (summary: WrapperSummary): string =>
    `${posix.dirname(summary.file.path)}\0${summary.packageName}\0${summary.functionName}\0${summary.objectParameterIndex}`;
  const modules = localGoModules(files);
  const descriptors = new Map<string, Descriptor>();
  for (const function_ of functions) {
    if (function_.receiver !== undefined) continue;
    const key = functionKey(function_);
    if (functionCounts.get(key) !== 1) continue;
    const parameters = function_.parameters.flatMap(
      (parameter, index): StringParameter[] =>
        parameter.type.replace(/\s+/gu, "") === "string"
          ? [{ index, name: parameter.name }]
          : [],
    );
    if (parameters.length === 0) continue;
    const importPath = localPackageImportPath(function_, modules);
    descriptors.set(key, {
      function_,
      parameters,
      ...(importPath === undefined ? {} : { importPath }),
    });
  }

  const parameterFlowsReachingExpression = (
    descriptor: Descriptor,
    expression: string,
    line: number,
    assignmentKind:
      | "go-object-identifier-assignment"
      | "go-context-principal-assignment",
  ): ParameterFlow[] => {
    const fixedMaps = fixedMapNames(descriptor.function_);
    const reaches = (parameter: StringParameter): GoTaint | undefined => {
      const taints = new Map<string, GoTaint>([
        [
          parameter.name,
          {
            kind: "go-string-parameter",
            line: descriptor.function_.startLine,
            propagators: [],
          },
        ],
      ]);
      for (
        let candidateLine = descriptor.function_.bodyStartLine;
        candidateLine < line;
        candidateLine += 1
      ) {
        const assignment = goAssignment(
          descriptor.function_.structuralLines[candidateLine - 1] ?? "",
        );
        if (assignment === undefined) continue;
        const source = expressionTaint(assignment.value, taints);
        const touchesIdentity =
          source !== undefined ||
          assignment.names.some((name) => taints.has(name));
        if (lineNestingDepth(descriptor.function_, candidateLine) !== 1) {
          if (touchesIdentity) return undefined;
          continue;
        }
        const fixedSelection = fixedMapSelection(
          assignment.value,
          fixedMaps,
          taints,
        );
        for (const name of assignment.names) taints.delete(name);
        if (source === undefined || fixedSelection) continue;
        if (assignment.names.length !== 1) return undefined;
        taints.set(assignment.names[0]!, {
          ...source,
          propagators: [
            ...source.propagators,
            {
              kind: assignmentKind,
              line: candidateLine,
              symbol: assignment.names[0]!,
            },
          ],
        });
      }
      return fixedMapSelection(expression, fixedMaps, taints)
        ? undefined
        : expressionTaint(expression, taints);
    };
    return descriptor.parameters.flatMap((parameter): ParameterFlow[] => {
      const taint = reaches(parameter);
      return taint === undefined
        ? []
        : [
            {
              index: parameter.index,
              propagators: taint.propagators.map((propagator) => ({
                ...propagator,
                path: descriptor.function_.file.path,
              })),
            },
          ];
    });
  };

  const direct: WrapperSummary[] = [];
  for (const descriptor of descriptors.values()) {
    const alias = sqlAlias(descriptor.function_);
    if (alias === undefined) continue;
    for (const parameter of descriptor.parameters) {
      const objectTaint: GoTaint = {
        kind: "go-string-parameter",
        line: descriptor.function_.startLine,
        propagators: [],
      };
      const allPrincipalParameters = new Map<string, GoTaint>();
      for (const candidate of descriptor.parameters) {
        if (candidate.index === parameter.index) continue;
        allPrincipalParameters.set(candidate.name, {
          kind: "go-principal-parameter",
          line: descriptor.function_.startLine,
          propagators: [],
        });
      }
      for (const sink of analyzeFunction(
        descriptor.function_,
        new Map([[parameter.name, objectTaint]]),
        allPrincipalParameters,
        finalizers,
        creators,
      )) {
        const principalParameterIndexes: number[] = [];
        if (
          sink.controls.some(
            (control) => control.kind === "principal-bound-object-query",
          )
        ) {
          for (const candidate of descriptor.parameters) {
            if (
              candidate.index === parameter.index ||
              !allPrincipalParameters.has(candidate.name)
            )
              continue;
            const isolated = analyzeFunction(
              descriptor.function_,
              new Map([[parameter.name, objectTaint]]),
              new Map([
                [
                  candidate.name,
                  {
                    kind: "go-principal-parameter",
                    line: descriptor.function_.startLine,
                    propagators: [],
                  },
                ],
              ]),
              finalizers,
              creators,
            );
            if (
              isolated.some(
                (item) =>
                  item.line === sink.line &&
                  item.controls.some(
                    (control) =>
                      control.kind === "principal-bound-object-query",
                  ),
              )
            )
              principalParameterIndexes.push(candidate.index);
          }
        }
        direct.push({
          file: descriptor.function_.file,
          sinkFile: descriptor.function_.file,
          packageName: descriptor.function_.packageName,
          ...(descriptor.importPath === undefined
            ? {}
            : { packageImportPath: descriptor.importPath }),
          functionName: descriptor.function_.name,
          objectParameterIndex: parameter.index,
          objectParameterName: parameter.name,
          objectParameterLine: descriptor.function_.startLine,
          principalParameterIndexes,
          sink,
          delegations: [],
          wrapperDepth: 0,
          wrapperKeys: [parameterKey(descriptor.function_, parameter.index)],
        });
      }
    }
  }

  const targetDescriptors = (
    caller: Descriptor,
    call: GoCall,
  ): Descriptor[] => {
    const resolved = resolvedTransactionHelperCall(
      caller.function_,
      call.name,
      call.line,
    );
    if (
      resolved === undefined ||
      resolved.functionValues.length !== 0 ||
      resolved.name !== call.name
    )
      return [];
    const plain = /^([A-Za-z_]\w*)$/u.exec(resolved.name);
    if (plain !== null) {
      const target = descriptors.get(
        `${posix.dirname(caller.function_.file.path)}\0${caller.function_.packageName}\0${plain[1]}`,
      );
      return target === undefined ? [] : [target];
    }
    const qualified = /^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$/u.exec(resolved.name);
    if (
      qualified === null ||
      !/^[A-Z]/u.test(qualified[2]!) ||
      !packageAliasIsAvailable(
        caller.function_,
        qualified[1]!,
        resolved.targetLine,
      )
    )
      return [];
    const targets: Descriptor[] = [];
    for (const target of descriptors.values()) {
      if (
        target.importPath === undefined ||
        target.function_.name !== qualified[2]
      )
        continue;
      const alias = goImportAlias(
        caller.function_.file.lines,
        target.importPath,
        target.function_.packageName,
      );
      if (alias === qualified[1]) targets.push(target);
    }
    return targets;
  };

  const edges: Edge[] = [];
  for (const source of descriptors.values()) {
    for (const call of goCalls(source.function_)) {
      const structural = source.function_.structuralLines[call.line - 1] ?? "";
      if (
        callNestingDepth(source.function_, call) !== 1 ||
        /\b(?:defer|go)\s+[A-Za-z_]/u.test(structural)
      )
        continue;
      const targets = targetDescriptors(source, call);
      if (targets.length !== 1) continue;
      const target = targets[0]!;
      for (const sourceParameter of source.parameters) {
        const sourceKey = parameterKey(source.function_, sourceParameter.index);
        for (const targetParameter of target.parameters) {
          const argument = call.rawArguments[targetParameter.index];
          if (argument === undefined) continue;
          const reaching = parameterFlowsReachingExpression(
            source,
            argument,
            call.line,
            "go-object-identifier-assignment",
          );
          if (
            reaching.length !== 1 ||
            reaching[0]!.index !== sourceParameter.index
          )
            continue;
          edges.push({
            sourceKey,
            source,
            sourceParameter,
            targetKey: parameterKey(target.function_, targetParameter.index),
            target,
            call,
            objectPropagators: reaching[0]!.propagators,
          });
        }
      }
    }
  }

  const groups = new Map<string, Map<string, WrapperSummary>>();
  let candidateCount = 0;
  let overflow = false;
  const candidateIdentity = (summary: WrapperSummary): string =>
    `${summaryParameterKey(summary)}\0${summary.sinkFile.path}\0${summary.sink.line}\0${summary.sink.kind}`;
  const candidateSignature = (summary: WrapperSummary): string =>
    JSON.stringify({
      wrapperKeys: summary.wrapperKeys,
      principalParameterIndexes: summary.principalParameterIndexes,
      delegations: summary.delegations,
    });
  const addCandidate = (summary: WrapperSummary): boolean => {
    const identity = candidateIdentity(summary);
    const group = groups.get(identity) ?? new Map<string, WrapperSummary>();
    const signature = candidateSignature(summary);
    if (group.has(signature)) return false;
    if (candidateCount >= MAX_OBJECT_WRAPPER_CANDIDATES) {
      overflow = true;
      return false;
    }
    group.set(signature, summary);
    groups.set(identity, group);
    candidateCount += 1;
    return true;
  };
  for (const summary of direct) addCandidate(summary);

  for (let depth = 1; depth <= MAX_OBJECT_WRAPPER_DEPTH; depth += 1) {
    let changed = false;
    const childrenByKey = new Map<string, WrapperSummary[]>();
    for (const group of groups.values()) {
      for (const summary of group.values()) {
        if (summary.wrapperDepth !== depth - 1) continue;
        const key = summaryParameterKey(summary);
        const children = childrenByKey.get(key) ?? [];
        children.push(summary);
        childrenByKey.set(key, children);
      }
    }
    for (const edge of edges) {
      const children = childrenByKey.get(edge.targetKey) ?? [];
      for (const child of children) {
        if (child.wrapperKeys.includes(edge.sourceKey)) continue;
        const principalParameterIndexes = new Set<number>();
        for (const childIndex of child.principalParameterIndexes) {
          const argument = edge.call.rawArguments[childIndex];
          if (argument === undefined) continue;
          const reaching = parameterFlowsReachingExpression(
            edge.source,
            argument,
            edge.call.line,
            "go-context-principal-assignment",
          );
          if (
            reaching.length === 1 &&
            reaching[0]!.index !== edge.sourceParameter.index
          )
            principalParameterIndexes.add(reaching[0]!.index);
        }
        changed =
          addCandidate({
            file: edge.source.function_.file,
            sinkFile: child.sinkFile,
            packageName: edge.source.function_.packageName,
            ...(edge.source.importPath === undefined
              ? {}
              : { packageImportPath: edge.source.importPath }),
            functionName: edge.source.function_.name,
            objectParameterIndex: edge.sourceParameter.index,
            objectParameterName: edge.sourceParameter.name,
            objectParameterLine: edge.source.function_.startLine,
            principalParameterIndexes: [...principalParameterIndexes].sort(
              (left, right) => left - right,
            ),
            sink: child.sink,
            delegations: [
              ...edge.objectPropagators,
              {
                kind: "go-function-argument",
                line: edge.call.line,
                symbol: `${edge.target.function_.name}[${child.objectParameterIndex}]`,
                path: edge.source.function_.file.path,
              },
              {
                kind: "go-string-parameter",
                line: edge.target.function_.startLine,
                symbol: child.objectParameterName,
                path: edge.target.function_.file.path,
              },
              ...child.delegations,
            ],
            wrapperDepth: depth,
            wrapperKeys: [edge.sourceKey, ...child.wrapperKeys],
          }) || changed;
        if (overflow) break;
      }
      if (overflow) break;
    }
    if (overflow || !changed) break;
  }

  if (overflow) return direct;
  return [...groups.values()]
    .filter((group) => group.size === 1)
    .map((group) => group.values().next().value!)
    .sort(
      (left, right) =>
        left.file.path.localeCompare(right.file.path) ||
        left.functionName.localeCompare(right.functionName) ||
        left.objectParameterIndex - right.objectParameterIndex ||
        left.sinkFile.path.localeCompare(right.sinkFile.path) ||
        left.sink.line - right.sink.line,
    );
}

function wrapperSummaryCallMatches(
  caller: GoFunction,
  call: GoCall,
  summary: WrapperSummary,
): boolean {
  const resolved = resolvedTransactionHelperCall(caller, call.name, call.line);
  if (
    resolved === undefined ||
    resolved.functionValues.length !== 0 ||
    resolved.name !== call.name
  )
    return false;
  if (
    summary.functionName === resolved.name &&
    summary.packageName === caller.packageName &&
    posix.dirname(summary.file.path) === posix.dirname(caller.file.path)
  )
    return true;
  if (
    summary.packageImportPath === undefined ||
    !/^[A-Z]/u.test(summary.functionName)
  )
    return false;
  const qualified = /^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$/u.exec(resolved.name);
  if (qualified?.[2] !== summary.functionName) return false;
  const alias = goImportAlias(
    caller.file.lines,
    summary.packageImportPath,
    summary.packageName,
  );
  return (
    alias !== undefined &&
    alias === qualified[1] &&
    packageAliasIsAvailable(caller, alias, resolved.targetLine)
  );
}

function uniqueWrapperSummaryMatches(
  caller: GoFunction,
  call: GoCall,
  summaries: readonly WrapperSummary[],
): WrapperSummary[] {
  const matching = summaries.filter((summary) =>
    wrapperSummaryCallMatches(caller, call, summary),
  );
  const targets = new Set(
    matching.map(
      (summary) =>
        `${posix.dirname(summary.file.path)}\0${summary.packageName}\0${summary.functionName}`,
    ),
  );
  return targets.size === 1 ? matching : [];
}

export function goObjectAuthorizationRecords(
  files: readonly GoHttpSourceFile[],
): GoObjectAuthorizationRecord[] {
  const functions = files
    .filter((file) => file.extension === ".go")
    .flatMap(goFunctions);
  const records: GoObjectAuthorizationRecord[] = [];
  const emitted = new Set<string>();
  const functionCounts = new Map<string, number>();
  for (const function_ of functions) {
    if (function_.receiver !== undefined) continue;
    const key = `${posix.dirname(function_.file.path)}\0${function_.packageName}\0${function_.name}`;
    functionCounts.set(key, (functionCounts.get(key) ?? 0) + 1);
  }
  const finalizers = transactionFinalizerSummaries(
    files,
    functions,
    functionCounts,
  );
  const creators = transactionCreatorSummaries(
    files,
    functions,
    functionCounts,
  );

  for (const function_ of functions) {
    if (requestParameters(function_).length === 0) continue;
    for (const sink of analyzeFunction(
      function_,
      new Map(),
      new Map(),
      finalizers,
      creators,
    )) {
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

  const summaries = objectWrapperSummaries(
    files,
    functions,
    functionCounts,
    finalizers,
    creators,
  );

  for (const caller of functions) {
    if (requestParameters(caller).length === 0) continue;
    const calls = goCalls(caller);
    for (const call of calls) {
      for (const summary of uniqueWrapperSummaryMatches(
        caller,
        call,
        summaries,
      )) {
        const argument = call.arguments[summary.objectParameterIndex];
        if (argument === undefined) continue;
        const taints = callerTaints(caller, call.line);
        const source =
          requestSource(argument, requestParameters(caller), call.line) ??
          expressionTaint(argument, taints.objects);
        if (source === undefined) continue;
        const controls = summary.sink.controls.filter((control) => {
          if (control.kind !== "principal-bound-object-query") return true;
          return summary.principalParameterIndexes.some((index) => {
            const principalArgument = call.arguments[index];
            return (
              principalArgument !== undefined &&
              (principalFromExpression(
                principalArgument,
                requestParameters(caller),
                call.line,
              ) !== undefined ||
                expressionTaint(principalArgument, taints.principals) !==
                  undefined)
            );
          });
        });
        const sink = { ...summary.sink, controls };
        const identity = `${caller.file.path}:${call.line}:${summary.sinkFile.path}:${sink.line}:${sink.kind}`;
        if (emitted.has(identity)) continue;
        emitted.add(identity);
        records.push(
          record(
            caller.file,
            summary.sinkFile,
            caller.file.path === summary.sinkFile.path
              ? "same-file"
              : "cross-file-wrapper",
            source,
            sink,
            [
              ...source.propagators,
              {
                kind: "go-function-argument",
                line: call.line,
                symbol: `${summary.functionName}[${summary.objectParameterIndex}]`,
              },
              {
                kind: "go-string-parameter",
                line: summary.objectParameterLine,
                symbol: summary.objectParameterName,
                path: summary.file.path,
              },
              ...summary.delegations,
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
