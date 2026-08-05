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
  type GoTaint,
} from "./go-http-risk.js";

const CONTEXT_LINES_BEFORE = 3;
const CONTEXT_LINES_AFTER = 5;
const MAX_RECORDS = 64;
const MAX_OBJECT_WRAPPER_DEPTH = 32;
const MAX_OBJECT_WRAPPER_CANDIDATES = 4_096;
const MAX_OBJECT_RECEIVER_ALIAS_DEPTH = 8;
const MAX_OBJECT_RECEIVER_FIELD_DEPTH = 8;
const MAX_OBJECT_CONSTRUCTOR_ALIAS_DEPTH = 8;
const MAX_OBJECT_CONSTRUCTOR_HELPER_DEPTH = 8;
const MAX_OBJECT_CONSTRUCTOR_FIELD_WRITES = 8;
const MAX_OBJECT_CONSTRUCTOR_STATEMENT_LINES = 13;
const MAX_OBJECT_CONSTRUCTOR_BRANCH_LINES = 16;
const MAX_OBJECT_CONSTRUCTOR_BRANCH_ARMS = 4;
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

interface ObjectReceiverRequirement {
  fieldPath: readonly string[];
  directory: string;
  packageName: string;
  typeName: string;
  pointer: "value" | "pointer" | "either";
}

interface WrapperSummary {
  file: GoHttpSourceFile;
  sinkFile: GoHttpSourceFile;
  packageName: string;
  packageImportPath?: string;
  callableKey: string;
  functionName: string;
  receiverTypeName?: string;
  receiverPointer?: boolean;
  objectParameterIndex: number;
  objectParameterName: string;
  objectParameterLine: number;
  principalParameterIndexes: number[];
  sink: ObjectSink;
  delegations: EvidencePropagator[];
  receiverRequirements: readonly ObjectReceiverRequirement[];
  wrapperDepth: number;
  wrapperKeys: readonly string[];
}

interface ObjectWrapperMatch {
  summary: WrapperSummary;
  receiverPropagators: EvidencePropagator[];
}

interface ObjectWrapperGraph {
  summaries: WrapperSummary[];
  matches(caller: GoFunction, call: GoCall): ObjectWrapperMatch[];
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
  return localDirectoryImportPath(posix.dirname(function_.file.path), modules);
}

function localDirectoryImportPath(
  directory: string,
  modules: readonly LocalGoModule[],
): string | undefined {
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
  if (/^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$/u.test(callName))
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
  finalizers: readonly TransactionFinalizerSummary[],
  creators: readonly TransactionCreatorSummary[],
): ObjectWrapperGraph {
  interface StringParameter {
    index: number;
    name: string;
  }
  interface MethodReceiver {
    name: string;
    typeName: string;
    pointer: boolean;
  }
  interface Descriptor {
    key: string;
    function_: GoFunction;
    parameters: StringParameter[];
    importPath?: string;
    receiver?: MethodReceiver;
  }
  interface TypeReference {
    qualifier?: string;
    typeName: string;
    pointer: boolean;
    resolvedDirectory?: string;
    resolvedPackageName?: string;
    resolvedImportPath?: string;
  }
  interface StructFieldDescriptor {
    file: GoHttpSourceFile;
    packageName: string;
    name: string;
    type: TypeReference;
    line: number;
  }
  interface StructDescriptor {
    key: string;
    file: GoHttpSourceFile;
    directory: string;
    packageName: string;
    importPath?: string;
    name: string;
    fields: ReadonlyMap<string, StructFieldDescriptor>;
  }
  interface ConstructorValueState {
    expression: string;
    line: number;
    write: boolean;
    path?: string;
    bindingLine?: number;
    useLine?: number;
    origins?: number[];
    propagators?: EvidencePropagator[];
    composite?: {
      reference: TypeReference;
      fields: Map<string, ConstructorValueState>;
    };
  }
  interface ConstructorSummary {
    key: string;
    function_: GoFunction;
    importPath?: string;
    result: TypeReference;
    resultStruct: StructDescriptor;
    returnLine: number;
    aliases: EvidencePropagator[];
    fieldSources: ReadonlyMap<
      string,
      {
        parameterIndex?: number;
        expression?: string;
        line: number;
        write?: boolean;
        state?: ConstructorValueState;
      }
    >;
  }
  interface ConstructorValueHelperWriteStep {
    kind: "write";
    target: string;
    fields: string[];
    value: string;
    valueLine: number;
    line: number;
    propagators: EvidencePropagator[];
  }
  type ConstructorValueHelperStep =
    | {
        kind: "bind";
        name: string;
        expression: string;
        line: number;
      }
    | {
        kind: "copy";
        name: string;
        source: string;
        line: number;
      }
    | ConstructorValueHelperWriteStep
    | {
        kind: "branch";
        arms: ReadonlyArray<ReadonlyArray<ConstructorValueHelperWriteStep>>;
      };
  interface ConstructorValueHelperSummary {
    key: string;
    function_: GoFunction;
    result: TypeReference;
    expression: string;
    expressionLine: number;
    returnLine: number;
    aliases: EvidencePropagator[];
    returnAlias?: string;
    steps: ReadonlyArray<ConstructorValueHelperStep>;
  }
  interface InterfaceDescriptor {
    directory: string;
    packageName: string;
    importPath?: string;
    name: string;
    methods: ReadonlySet<string>;
  }
  interface ReceiverBinding {
    concrete: TypeReference;
    interface_?: InterfaceDescriptor;
    fields: ReadonlyMap<string, ReceiverBinding>;
    aliasDepth: number;
    propagators: EvidencePropagator[];
  }
  interface ResolvedTarget {
    descriptor: Descriptor;
    receiverPropagators: EvidencePropagator[];
    receiverRequirements: ObjectReceiverRequirement[];
    receiverFieldPath: string[];
    receiverBinding?: ReceiverBinding;
  }
  interface Edge {
    sourceKey: string;
    source: Descriptor;
    sourceParameter: StringParameter;
    targetKey: string;
    target: Descriptor;
    call: GoCall;
    receiverPropagators: EvidencePropagator[];
    receiverRequirements: ObjectReceiverRequirement[];
    receiverFieldPath: string[];
    objectPropagators: EvidencePropagator[];
  }
  interface ParameterFlow {
    index: number;
    propagators: EvidencePropagator[];
  }

  const receiverOf = (function_: GoFunction): MethodReceiver | undefined => {
    if (function_.receiver === undefined) return undefined;
    const named = /^\(\s*([A-Za-z_]\w*)\s+(\*)?([A-Za-z_]\w*)\s*\)$/u.exec(
      function_.receiver,
    );
    if (named !== null)
      return {
        name: named[1]!,
        typeName: named[3]!,
        pointer: named[2] !== undefined,
      };
    const unnamed = /^\(\s*(\*)?([A-Za-z_]\w*)\s*\)$/u.exec(function_.receiver);
    return unnamed === null
      ? undefined
      : {
          name: "",
          typeName: unnamed[2]!,
          pointer: unnamed[1] !== undefined,
        };
  };
  const callableKey = (
    function_: GoFunction,
    receiver: MethodReceiver | undefined,
  ): string =>
    `${posix.dirname(function_.file.path)}\0${function_.packageName}\0${receiver?.typeName ?? ""}\0${function_.name}`;
  const parameterKey = (descriptor: Descriptor, index: number): string =>
    `${descriptor.key}\0${index}`;
  const summaryParameterKey = (summary: WrapperSummary): string =>
    `${summary.callableKey}\0${summary.objectParameterIndex}`;
  const modules = localGoModules(files);
  const callableCounts = new Map<string, number>();
  const callableReceivers = new Map<GoFunction, MethodReceiver | undefined>();
  for (const function_ of functions) {
    const receiver = receiverOf(function_);
    if (function_.receiver !== undefined && receiver === undefined) continue;
    callableReceivers.set(function_, receiver);
    const key = callableKey(function_, receiver);
    callableCounts.set(key, (callableCounts.get(key) ?? 0) + 1);
  }
  const descriptors = new Map<string, Descriptor>();
  for (const function_ of functions) {
    if (!callableReceivers.has(function_)) continue;
    const receiver = callableReceivers.get(function_);
    const key = callableKey(function_, receiver);
    if (callableCounts.get(key) !== 1) continue;
    const parameters = function_.parameters.flatMap(
      (parameter, index): StringParameter[] =>
        parameter.type.replace(/\s+/gu, "") === "string"
          ? [{ index, name: parameter.name }]
          : [],
    );
    if (parameters.length === 0) continue;
    const importPath = localPackageImportPath(function_, modules);
    descriptors.set(key, {
      key,
      function_,
      parameters,
      ...(importPath === undefined ? {} : { importPath }),
      ...(receiver === undefined ? {} : { receiver }),
    });
  }

  const interfaces: InterfaceDescriptor[] = [];
  for (const file of files) {
    if (file.extension !== ".go") continue;
    const structural = maskGoLines(file.lines, true).join("\n");
    const packageMatch = /^\s*package\s+([A-Za-z_]\w*)\b/mu.exec(structural);
    if (packageMatch === null) continue;
    const directory = posix.dirname(file.path);
    const importPath = localDirectoryImportPath(directory, modules);
    for (const declaration of structural.matchAll(
      /\btype\s+([A-Za-z_]\w*)\s+interface\s*\{([\s\S]*?)\}/gu,
    )) {
      const body = declaration[2]!;
      if (
        /[~|]/u.test(body) ||
        /^\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?\s*;?\s*$/mu.test(body)
      )
        continue;
      const methodNames = [...body.matchAll(/^\s*([A-Za-z_]\w*)\s*\(/gmu)].map(
        (method) => method[1]!,
      );
      const methods = new Set(methodNames);
      if (methods.size === 0 || methods.size !== methodNames.length) continue;
      interfaces.push({
        directory,
        packageName: packageMatch[1]!,
        ...(importPath === undefined ? {} : { importPath }),
        name: declaration[1]!,
        methods,
      });
    }
  }

  const typeReference = (value: string): TypeReference | undefined => {
    const match =
      /^\s*(\*)?\s*(?:([A-Za-z_]\w*)\s*\.\s*)?([A-Za-z_]\w*)\s*$/u.exec(value);
    return match === null
      ? undefined
      : {
          ...(match[2] === undefined ? {} : { qualifier: match[2] }),
          typeName: match[3]!,
          pointer: match[1] !== undefined,
        };
  };

  const structCandidates: StructDescriptor[] = [];
  const structCounts = new Map<string, number>();
  for (const file of files) {
    if (file.extension !== ".go") continue;
    const structural = maskGoLines(file.lines, true).join("\n");
    const packageMatch = /^\s*package\s+([A-Za-z_]\w*)\b/mu.exec(structural);
    if (packageMatch === null) continue;
    const packageName = packageMatch[1]!;
    const directory = posix.dirname(file.path);
    const importPath = localDirectoryImportPath(directory, modules);
    for (const declaration of structural.matchAll(
      /\btype\s+([A-Za-z_]\w*)\s+struct\s*\{([^{}]*)\}/gu,
    )) {
      const name = declaration[1]!;
      const key = `${directory}\0${packageName}\0${name}`;
      structCounts.set(key, (structCounts.get(key) ?? 0) + 1);
      const open = declaration[0].indexOf("{");
      const bodyOffset = (declaration.index ?? 0) + open + 1;
      const bodyStartLine = structural.slice(0, bodyOffset).split("\n").length;
      const fields = new Map<string, StructFieldDescriptor>();
      let valid = true;
      for (const [lineOffset, rawLine] of declaration[2]!
        .split("\n")
        .entries()) {
        for (const rawField of rawLine.split(";")) {
          const fieldText = rawField.trim();
          if (fieldText === "") continue;
          const fieldMatch =
            /^([A-Za-z_]\w*)\s+(\*?\s*(?:[A-Za-z_]\w*\s*\.\s*)?[A-Za-z_]\w*)$/u.exec(
              fieldText,
            );
          if (fieldMatch === null || fields.has(fieldMatch[1]!)) {
            valid = false;
            break;
          }
          const fieldType = typeReference(fieldMatch[2]!);
          if (fieldType === undefined) {
            valid = false;
            break;
          }
          fields.set(fieldMatch[1]!, {
            file,
            packageName,
            name: fieldMatch[1]!,
            type: fieldType,
            line: bodyStartLine + lineOffset,
          });
        }
        if (!valid) break;
      }
      if (!valid) continue;
      structCandidates.push({
        key,
        file,
        directory,
        packageName,
        ...(importPath === undefined ? {} : { importPath }),
        name,
        fields,
      });
    }
  }
  const structs = structCandidates.filter(
    (descriptor) => structCounts.get(descriptor.key) === 1,
  );

  const typeMatchesIdentity = (
    reference: TypeReference,
    contextFile: GoHttpSourceFile,
    contextPackageName: string,
    targetDirectory: string,
    targetPackageName: string,
    targetImportPath: string | undefined,
    contextFunction?: GoFunction,
    contextLine?: number,
  ): boolean => {
    if (
      reference.qualifier !== undefined &&
      !/^[A-Z]/u.test(reference.typeName)
    )
      return false;
    if (reference.resolvedDirectory !== undefined) {
      return (
        reference.resolvedDirectory === targetDirectory &&
        reference.resolvedPackageName === targetPackageName
      );
    }
    if (reference.qualifier === undefined) {
      return (
        posix.dirname(contextFile.path) === targetDirectory &&
        contextPackageName === targetPackageName
      );
    }
    if (targetImportPath === undefined) return false;
    if (
      goImportAlias(contextFile.lines, targetImportPath, targetPackageName) !==
      reference.qualifier
    )
      return false;
    return (
      contextFunction === undefined ||
      contextLine === undefined ||
      packageAliasIsAvailable(contextFunction, reference.qualifier, contextLine)
    );
  };

  const keyedCompositeResult = (
    expression: string,
  ):
    | {
        reference: TypeReference;
        fields: ReadonlyMap<string, string>;
      }
    | undefined => {
    const trimmed = expression.trim().replace(/;\s*$/u, "");
    const prefix = /^(&)?\s*((?:[A-Za-z_]\w*\s*\.\s*)?[A-Za-z_]\w*)\s*/u.exec(
      trimmed,
    );
    if (prefix === null) return undefined;
    const composite = trimmed.slice(prefix[0].length);
    if (!composite.startsWith("{") || !composite.endsWith("}"))
      return undefined;
    let depth = 0;
    for (let index = 0; index < composite.length; index += 1) {
      if (composite[index] === "{") depth += 1;
      if (composite[index] === "}") depth -= 1;
      if (depth < 0 || (depth === 0 && index !== composite.length - 1))
        return undefined;
    }
    if (depth !== 0) return undefined;
    const fields = new Map<string, string>();
    const body = composite.slice(1, -1).trim();
    if (body !== "") {
      const items = splitGoArguments(body);
      if (items.at(-1)?.trim() === "") items.pop();
      for (const item of items) {
        const field = /^([A-Za-z_]\w*)\s*:\s*([\s\S]+)$/u.exec(item.trim());
        if (field === null || fields.has(field[1]!)) return undefined;
        fields.set(field[1]!, field[2]!.trim());
      }
    }
    const reference = typeReference(
      `${prefix[1] === undefined ? "" : "*"}${prefix[2]!}`,
    );
    return reference === undefined ? undefined : { reference, fields };
  };

  const localCompositeResult = (
    expression: string,
    typeName: string,
  ):
    | {
        pointer: boolean;
        fields: ReadonlyMap<string, string>;
      }
    | undefined => {
    const composite = keyedCompositeResult(expression);
    return composite === undefined ||
      composite.reference.qualifier !== undefined ||
      composite.reference.typeName !== typeName
      ? undefined
      : { pointer: composite.reference.pointer, fields: composite.fields };
  };

  const constructorValueState = (
    expression: string,
    line: number,
    write: boolean,
    depth = 0,
    path?: string,
    helper?: (
      expression: string,
      line: number,
      write: boolean,
      depth: number,
    ) => ConstructorValueState | undefined,
  ): ConstructorValueState => {
    const materialized = helper?.(expression, line, write, depth);
    if (materialized !== undefined) return materialized;
    const composite =
      depth >= MAX_OBJECT_RECEIVER_FIELD_DEPTH
        ? undefined
        : keyedCompositeResult(expression);
    return {
      expression,
      line,
      write,
      ...(path === undefined ? {} : { path }),
      ...(composite === undefined
        ? {}
        : {
            composite: {
              reference: composite.reference,
              fields: new Map(
                [...composite.fields].map(
                  ([field, value]): [string, ConstructorValueState] => [
                    field,
                    constructorValueState(
                      value,
                      line,
                      false,
                      depth + 1,
                      path,
                      helper,
                    ),
                  ],
                ),
              ),
            },
          }),
    };
  };

  const copyConstructorValueState = (
    state: ConstructorValueState,
  ): ConstructorValueState => ({
    expression: state.expression,
    line: state.line,
    write: state.write,
    ...(state.path === undefined ? {} : { path: state.path }),
    ...(state.bindingLine === undefined
      ? {}
      : { bindingLine: state.bindingLine }),
    ...(state.useLine === undefined ? {} : { useLine: state.useLine }),
    ...(state.origins === undefined ? {} : { origins: [...state.origins] }),
    ...(state.propagators === undefined
      ? {}
      : { propagators: [...state.propagators] }),
    ...(state.composite === undefined
      ? {}
      : {
          composite: {
            reference: state.composite.reference,
            fields: new Map(
              [...state.composite.fields].map(
                ([field, value]): [string, ConstructorValueState] => [
                  field,
                  copyConstructorValueState(value),
                ],
              ),
            ),
          },
        }),
  });

  const renderConstructorValueState = (
    state: ConstructorValueState,
  ): string => {
    if (state.composite === undefined) return state.expression;
    const reference = state.composite.reference;
    const type = `${reference.qualifier === undefined ? "" : `${reference.qualifier}.`}${reference.typeName}`;
    const fields = [...state.composite.fields]
      .map(
        ([field, value]) => `${field}: ${renderConstructorValueState(value)}`,
      )
      .join(", ");
    return `${reference.pointer ? "&" : ""}${type}{${fields}}`;
  };

  const constructorValueOrigins = (state: ConstructorValueState): number[] =>
    state.origins ?? [state.line];

  const sameTypeReference = (
    left: TypeReference,
    right: TypeReference,
  ): boolean =>
    left.qualifier === right.qualifier &&
    left.typeName === right.typeName &&
    left.pointer === right.pointer &&
    left.resolvedDirectory === right.resolvedDirectory &&
    left.resolvedPackageName === right.resolvedPackageName &&
    left.resolvedImportPath === right.resolvedImportPath;

  const mergeEvidencePropagators = (
    left: readonly EvidencePropagator[],
    right: readonly EvidencePropagator[],
  ): EvidencePropagator[] => {
    const unique = new Map<string, EvidencePropagator>();
    for (const propagator of [...left, ...right])
      unique.set(
        `${propagator.kind}\0${propagator.path}\0${propagator.line}\0${propagator.symbol ?? ""}`,
        propagator,
      );
    return [...unique.values()];
  };

  interface ConstructorValueJoinMemo {
    pairs: Map<
      ConstructorValueState,
      Map<ConstructorValueState, ConstructorValueState>
    >;
    leftToRight: Map<ConstructorValueState, ConstructorValueState>;
    rightToLeft: Map<ConstructorValueState, ConstructorValueState>;
  }

  const constructorValueJoinMemo = (): ConstructorValueJoinMemo => ({
    pairs: new Map(),
    leftToRight: new Map(),
    rightToLeft: new Map(),
  });

  const joinConstructorValueState = (
    left: ConstructorValueState,
    right: ConstructorValueState,
    memo: ConstructorValueJoinMemo,
  ): ConstructorValueState | undefined => {
    const prior = memo.pairs.get(left)?.get(right);
    if (prior !== undefined) return prior;
    const mappedRight = memo.leftToRight.get(left);
    const mappedLeft = memo.rightToLeft.get(right);
    if (
      (mappedRight !== undefined && mappedRight !== right) ||
      (mappedLeft !== undefined && mappedLeft !== left)
    )
      return undefined;
    if (
      left.write !== right.write ||
      left.path !== right.path ||
      left.bindingLine !== right.bindingLine ||
      left.useLine !== right.useLine ||
      (left.composite === undefined) !== (right.composite === undefined)
    )
      return undefined;
    if (
      left.composite === undefined &&
      left.expression.trim() !== right.expression.trim()
    )
      return undefined;
    if (
      left.composite !== undefined &&
      right.composite !== undefined &&
      (!sameTypeReference(
        left.composite.reference,
        right.composite.reference,
      ) ||
        left.composite.fields.size !== right.composite.fields.size)
    )
      return undefined;
    const origins = [
      ...new Set([
        ...constructorValueOrigins(left),
        ...constructorValueOrigins(right),
      ]),
    ].sort((first, second) => first - second);
    const propagators = mergeEvidencePropagators(
      left.propagators ?? [],
      right.propagators ?? [],
    );
    const joined: ConstructorValueState = {
      expression: left.expression,
      line: origins[0]!,
      write: left.write,
      ...(left.path === undefined ? {} : { path: left.path }),
      ...(left.bindingLine === undefined
        ? {}
        : { bindingLine: left.bindingLine }),
      ...(left.useLine === undefined ? {} : { useLine: left.useLine }),
      ...(origins.length === 1 ? {} : { origins }),
      ...(propagators.length === 0 ? {} : { propagators }),
    };
    const byRight = memo.pairs.get(left) ?? new Map();
    byRight.set(right, joined);
    memo.pairs.set(left, byRight);
    memo.leftToRight.set(left, right);
    memo.rightToLeft.set(right, left);
    if (left.composite !== undefined && right.composite !== undefined) {
      const fields = new Map<string, ConstructorValueState>();
      for (const [field, leftValue] of left.composite.fields) {
        const rightValue = right.composite.fields.get(field);
        if (rightValue === undefined) return undefined;
        const value = joinConstructorValueState(leftValue, rightValue, memo);
        if (value === undefined) return undefined;
        fields.set(field, value);
      }
      joined.composite = {
        reference: left.composite.reference,
        fields,
      };
    }
    return joined;
  };

  const constructorFieldAssignment = (
    statement: string,
  ):
    | {
        target: string;
        explicitDereference: boolean;
        fields: string[];
        value: string;
      }
    | undefined => {
    const match =
      /^\s*(?:([A-Za-z_]\w*)|\(\s*\*\s*([A-Za-z_]\w*)\s*\))((?:\s*\.\s*[A-Za-z_]\w*)+)\s*=\s*(?!=)([\s\S]+?)\s*;?\s*$/u.exec(
        statement,
      );
    if (match === null) return undefined;
    return {
      target: (match[1] ?? match[2])!,
      explicitDereference: match[2] !== undefined,
      fields: [...match[3]!.matchAll(/[A-Za-z_]\w*/gu)].map(([field]) => field),
      value: match[4]!,
    };
  };

  const constructorStatement = (
    function_: GoFunction,
    startLine: number,
  ): { structural: string; endLine: number } => {
    const first = function_.structuralLines[startLine - 1] ?? "";
    if (
      !/^\s*return\b/u.test(first) &&
      goAssignment(first) === undefined &&
      constructorFieldAssignment(first) === undefined
    )
      return { structural: first, endLine: startLine };
    let depth = 0;
    let structural = "";
    const maximumLine = Math.min(
      function_.endLine,
      startLine + MAX_OBJECT_CONSTRUCTOR_STATEMENT_LINES - 1,
    );
    for (let line = startLine; line <= maximumLine; line += 1) {
      const fragment = function_.structuralLines[line - 1] ?? "";
      structural += `${structural === "" ? "" : "\n"}${fragment.trim()}`;
      for (const character of fragment) {
        if (character === "(" || character === "[" || character === "{")
          depth += 1;
        if (character === ")" || character === "]" || character === "}")
          depth -= 1;
        if (depth < 0) return { structural: first, endLine: startLine };
      }
      if (depth === 0) return { structural, endLine: line };
    }
    return { structural: first, endLine: startLine };
  };

  const constructorIfElseBranches = (
    function_: GoFunction,
    startLine: number,
  ):
    | {
        arms: ReadonlyArray<{ startLine: number; endLine: number }>;
        statementDepth: number;
        endLine: number;
      }
    | undefined => {
    const opening = function_.structuralLines[startLine - 1] ?? "";
    if (!/^\s*if\s+[^{};]+\s*\{\s*$/u.test(opening)) return undefined;
    let relativeDepth = braceDelta(opening);
    if (relativeDepth !== 1) return undefined;
    const arms: Array<{ startLine: number; endLine: number }> = [];
    let armStartLine = startLine + 1;
    let finalElse = false;
    const maximumLine = Math.min(
      function_.endLine,
      startLine +
        MAX_OBJECT_CONSTRUCTOR_BRANCH_LINES *
          MAX_OBJECT_CONSTRUCTOR_BRANCH_ARMS +
        MAX_OBJECT_CONSTRUCTOR_BRANCH_ARMS,
    );
    for (let line = startLine + 1; line <= maximumLine; line += 1) {
      const structural = function_.structuralLines[line - 1] ?? "";
      if (
        relativeDepth === 1 &&
        !finalElse &&
        /^\s*\}\s*else\s+if\s+[^{};]+\s*\{\s*$/u.test(structural)
      ) {
        if (
          line - armStartLine > MAX_OBJECT_CONSTRUCTOR_BRANCH_LINES ||
          arms.length + 1 >= MAX_OBJECT_CONSTRUCTOR_BRANCH_ARMS
        )
          return undefined;
        arms.push({ startLine: armStartLine, endLine: line - 1 });
        armStartLine = line + 1;
        continue;
      }
      if (
        relativeDepth === 1 &&
        !finalElse &&
        /^\s*\}\s*else\s*\{\s*$/u.test(structural)
      ) {
        if (
          line - armStartLine > MAX_OBJECT_CONSTRUCTOR_BRANCH_LINES ||
          arms.length + 1 >= MAX_OBJECT_CONSTRUCTOR_BRANCH_ARMS
        )
          return undefined;
        arms.push({ startLine: armStartLine, endLine: line - 1 });
        armStartLine = line + 1;
        finalElse = true;
        continue;
      }
      if (relativeDepth === 1 && finalElse && /^\s*\}\s*$/u.test(structural)) {
        if (
          line - armStartLine > MAX_OBJECT_CONSTRUCTOR_BRANCH_LINES ||
          arms.length + 1 > MAX_OBJECT_CONSTRUCTOR_BRANCH_ARMS
        )
          return undefined;
        arms.push({ startLine: armStartLine, endLine: line - 1 });
        return arms.length >= 2
          ? { arms, statementDepth: 2, endLine: line }
          : undefined;
      }
      relativeDepth += braceDelta(structural);
      if (relativeDepth < 1) return undefined;
    }
    return undefined;
  };

  const constructorSwitchBranches = (
    function_: GoFunction,
    startLine: number,
  ):
    | {
        arms: ReadonlyArray<{ startLine: number; endLine: number }>;
        statementDepth: number;
        endLine: number;
      }
    | undefined => {
    const opening = function_.structuralLines[startLine - 1] ?? "";
    if (!/^\s*switch(?:\s+[^{};]+)?\s*\{\s*$/u.test(opening)) return undefined;
    if (/\.\s*\(\s*type\s*\)/u.test(opening)) return undefined;
    let relativeDepth = braceDelta(opening);
    if (relativeDepth !== 1) return undefined;
    const arms: Array<{ startLine: number; endLine: number }> = [];
    const switchArm = (armStart: number, armEnd: number) => {
      let contentEnd = armEnd;
      while (
        contentEnd >= armStart &&
        (function_.structuralLines[contentEnd - 1] ?? "").trim() === ""
      )
        contentEnd -= 1;
      if (
        contentEnd >= armStart &&
        /^\s*break\s*;?\s*$/u.test(
          function_.structuralLines[contentEnd - 1] ?? "",
        )
      )
        contentEnd -= 1;
      return { startLine: armStart, endLine: contentEnd };
    };
    let armStartLine: number | undefined;
    let finalDefault = false;
    const maximumLine = Math.min(
      function_.endLine,
      startLine +
        MAX_OBJECT_CONSTRUCTOR_BRANCH_LINES *
          MAX_OBJECT_CONSTRUCTOR_BRANCH_ARMS +
        MAX_OBJECT_CONSTRUCTOR_BRANCH_ARMS +
        1,
    );
    for (let line = startLine + 1; line <= maximumLine; line += 1) {
      const structural = function_.structuralLines[line - 1] ?? "";
      if (
        relativeDepth === 1 &&
        !finalDefault &&
        /^\s*case\s+[^:{};]+\s*:\s*$/u.test(structural)
      ) {
        if (armStartLine !== undefined) {
          if (
            line - armStartLine > MAX_OBJECT_CONSTRUCTOR_BRANCH_LINES ||
            arms.length + 1 >= MAX_OBJECT_CONSTRUCTOR_BRANCH_ARMS
          )
            return undefined;
          arms.push(switchArm(armStartLine, line - 1));
        }
        armStartLine = line + 1;
        continue;
      }
      if (
        relativeDepth === 1 &&
        !finalDefault &&
        /^\s*default\s*:\s*$/u.test(structural)
      ) {
        if (armStartLine === undefined) return undefined;
        if (
          line - armStartLine > MAX_OBJECT_CONSTRUCTOR_BRANCH_LINES ||
          arms.length + 1 >= MAX_OBJECT_CONSTRUCTOR_BRANCH_ARMS
        )
          return undefined;
        arms.push(switchArm(armStartLine, line - 1));
        armStartLine = line + 1;
        finalDefault = true;
        continue;
      }
      if (relativeDepth === 1 && /^\s*\}\s*$/u.test(structural)) {
        if (!finalDefault || armStartLine === undefined) return undefined;
        if (
          line - armStartLine > MAX_OBJECT_CONSTRUCTOR_BRANCH_LINES ||
          arms.length + 1 > MAX_OBJECT_CONSTRUCTOR_BRANCH_ARMS
        )
          return undefined;
        arms.push(switchArm(armStartLine, line - 1));
        return arms.length >= 2
          ? { arms, statementDepth: 2, endLine: line }
          : undefined;
      }
      if (
        relativeDepth === 1 &&
        armStartLine === undefined &&
        structural.trim() !== ""
      )
        return undefined;
      relativeDepth += braceDelta(structural);
      if (relativeDepth < 1) return undefined;
    }
    return undefined;
  };

  const constructorControlBranches = (
    function_: GoFunction,
    startLine: number,
  ) =>
    constructorIfElseBranches(function_, startLine) ??
    constructorSwitchBranches(function_, startLine);

  const constructorValueHelperCall = (
    expression: string,
  ): { name: string; arguments: string[] } | undefined => {
    const match =
      /^([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)?)\s*\(([\s\S]*)\)\s*;?\s*$/u.exec(
        expression.trim(),
      );
    if (match === null) return undefined;
    const arguments_ =
      match[2]!.trim() === "" ? [] : splitGoArguments(match[2]!);
    if (arguments_.some((argument) => argument.trim() === "")) return undefined;
    return { name: match[1]!.replace(/\s+/gu, ""), arguments: arguments_ };
  };

  const singleLineConstructorHelperReturn = (
    function_: GoFunction,
  ): string | undefined => {
    if (
      function_.startLine !== function_.bodyStartLine ||
      function_.bodyStartLine !== function_.endLine
    )
      return undefined;
    const structural = function_.structuralLines[function_.startLine - 1] ?? "";
    const declaration = new RegExp(
      `\\bfunc\\s+${escapeRegularExpression(function_.name)}\\s*\\(`,
      "u",
    ).exec(structural);
    if (declaration === null) return undefined;
    const open = structural.indexOf("(", declaration.index);
    if (open < 0) return undefined;
    let depth = 0;
    let close = -1;
    for (let index = open; index < structural.length; index += 1) {
      if (structural[index] === "(") depth += 1;
      if (structural[index] === ")") depth -= 1;
      if (depth === 0) {
        close = index;
        break;
      }
    }
    if (close < 0) return undefined;
    const bodyOpen = structural.indexOf("{", close + 1);
    const bodyClose = structural.lastIndexOf("}");
    if (bodyOpen < 0 || bodyClose <= bodyOpen) return undefined;
    return /^\s*return\s+([\s\S]+?)\s*;?\s*$/u.exec(
      structural.slice(bodyOpen + 1, bodyClose),
    )?.[1];
  };

  const cloneConstructorValueHelperStep = (
    step: ConstructorValueHelperStep,
  ): ConstructorValueHelperStep => {
    if (step.kind === "write")
      return {
        ...step,
        fields: [...step.fields],
        propagators: [...step.propagators],
      };
    if (step.kind === "branch")
      return {
        kind: "branch",
        arms: step.arms.map((arm) =>
          arm.map((write) => ({
            ...write,
            fields: [...write.fields],
            propagators: [...write.propagators],
          })),
        ),
      };
    return { ...step };
  };

  const constructorValueHelperWriteSteps = (
    steps: readonly ConstructorValueHelperStep[],
  ): ConstructorValueHelperWriteStep[] =>
    steps.flatMap((step) =>
      step.kind === "write"
        ? [step]
        : step.kind === "branch"
          ? step.arms.flat()
          : [],
    );

  const constructorValueHelperPathWriteCount = (
    steps: readonly ConstructorValueHelperStep[],
  ): number =>
    steps.reduce(
      (count, step) =>
        count +
        (step.kind === "write"
          ? 1
          : step.kind === "branch"
            ? Math.max(...step.arms.map((arm) => arm.length))
            : 0),
      0,
    );

  const constructorValueHelperCandidates: ConstructorValueHelperSummary[] = [];
  const constructorValueHelperCounts = new Map<string, number>();
  for (const function_ of functions) {
    if (function_.receiver !== undefined) continue;
    const key = `${posix.dirname(function_.file.path)}\0${function_.packageName}\0${function_.name}`;
    constructorValueHelperCounts.set(
      key,
      (constructorValueHelperCounts.get(key) ?? 0) + 1,
    );
    const result = typeReference(function_.returnSignature);
    if (result === undefined || result.qualifier !== undefined) continue;
    const matchingStructs = structs.filter(
      (descriptor) =>
        descriptor.directory === posix.dirname(function_.file.path) &&
        descriptor.packageName === function_.packageName &&
        descriptor.name === result.typeName,
    );
    if (matchingStructs.length !== 1) continue;
    const aliases = new Map<
      string,
      {
        expression: string;
        expressionLine: number;
        depth: number;
        propagators: EvidencePropagator[];
      }
    >();
    const returns: Array<{
      expression: string;
      expressionLine: number;
      returnLine: number;
      propagators: EvidencePropagator[];
      returnAlias?: string;
      steps: ConstructorValueHelperSummary["steps"];
    }> = [];
    const steps: ConstructorValueHelperSummary["steps"][number][] = [];
    let invalid = false;
    let writeCount = 0;
    const branchWrites = (
      startLine: number,
      endLine: number,
      statementDepth: number,
    ): ConstructorValueHelperWriteStep[] | undefined => {
      const writes: ConstructorValueHelperWriteStep[] = [];
      for (let line = startLine; line <= endLine; line += 1) {
        if ((function_.structuralLines[line - 1] ?? "").trim() === "") continue;
        const statementLine = line;
        const statement = constructorStatement(function_, line);
        if (statement.endLine > endLine) return undefined;
        line = statement.endLine;
        const fieldWrite = constructorFieldAssignment(statement.structural);
        const alias =
          fieldWrite === undefined ? undefined : aliases.get(fieldWrite.target);
        if (
          fieldWrite === undefined ||
          alias === undefined ||
          lineNestingDepth(function_, statementLine) !== statementDepth ||
          (fieldWrite.explicitDereference && !result.pointer) ||
          fieldWrite.fields.length === 0 ||
          fieldWrite.fields.length > MAX_OBJECT_RECEIVER_FIELD_DEPTH
        )
          return undefined;
        const valueOffset = statement.structural.indexOf(fieldWrite.value);
        const valueLine =
          valueOffset < 0
            ? statementLine
            : statementLine +
              statement.structural.slice(0, valueOffset).split("\n").length -
              1;
        writes.push({
          kind: "write",
          target: fieldWrite.target,
          fields: [...fieldWrite.fields],
          value: fieldWrite.value,
          valueLine,
          line: statementLine,
          propagators: [...alias.propagators],
        });
      }
      return writes;
    };
    const singleLineReturn = singleLineConstructorHelperReturn(function_);
    if (singleLineReturn !== undefined) {
      const direct = localCompositeResult(singleLineReturn, result.typeName);
      const helperCall = constructorValueHelperCall(singleLineReturn);
      if (
        (direct === undefined || direct.pointer !== result.pointer) &&
        helperCall === undefined
      )
        invalid = true;
      else
        returns.push({
          expression: singleLineReturn,
          expressionLine: function_.startLine,
          returnLine: function_.startLine,
          propagators: [],
          steps: [],
        });
    }
    for (
      let line =
        singleLineReturn === undefined
          ? function_.bodyStartLine
          : function_.endLine + 1;
      line <= function_.endLine;
      line += 1
    ) {
      const statementLine = line;
      const conditional =
        lineNestingDepth(function_, statementLine) === 1
          ? constructorControlBranches(function_, statementLine)
          : undefined;
      if (conditional !== undefined) {
        const arms: ConstructorValueHelperWriteStep[][] = [];
        for (const { startLine, endLine } of conditional.arms) {
          const writes = branchWrites(
            startLine,
            endLine,
            conditional.statementDepth,
          );
          if (writes === undefined) {
            invalid = true;
            break;
          }
          arms.push(writes);
        }
        if (invalid) break;
        const writeCounts = arms.map((arm) => arm?.length);
        const firstWriteCount = writeCounts[0];
        if (
          firstWriteCount === undefined ||
          firstWriteCount === 0 ||
          writeCounts.some((count) => count !== firstWriteCount) ||
          writeCount + firstWriteCount > MAX_OBJECT_CONSTRUCTOR_FIELD_WRITES
        ) {
          invalid = true;
          break;
        }
        steps.push({ kind: "branch", arms });
        writeCount += firstWriteCount;
        line = conditional.endLine;
        continue;
      }
      const statement = constructorStatement(function_, line);
      const structural = statement.structural;
      line = statement.endLine;
      const returnMatch = /^\s*return\s+([\s\S]+?)\s*;?\s*$/u.exec(structural);
      if (/\breturn\b/u.test(structural)) {
        if (
          lineNestingDepth(function_, statementLine) !== 1 ||
          returnMatch === null
        ) {
          invalid = true;
          break;
        }
        const direct = localCompositeResult(returnMatch[1]!, result.typeName);
        const aliasName = /^([A-Za-z_]\w*)$/u.exec(returnMatch[1]!.trim())?.[1];
        const alias =
          aliasName === undefined ? undefined : aliases.get(aliasName);
        const helperCall = constructorValueHelperCall(returnMatch[1]!);
        if (
          (direct === undefined || direct.pointer !== result.pointer) &&
          alias === undefined &&
          helperCall === undefined
        ) {
          invalid = true;
          break;
        }
        returns.push({
          expression:
            direct !== undefined || helperCall !== undefined
              ? returnMatch[1]!
              : alias!.expression,
          expressionLine:
            direct !== undefined || helperCall !== undefined
              ? statementLine
              : alias!.expressionLine,
          returnLine: statementLine,
          propagators: alias?.propagators ?? [],
          ...(aliasName === undefined ? {} : { returnAlias: aliasName }),
          steps: steps.map(cloneConstructorValueHelperStep),
        });
        continue;
      }
      const syntacticAssignedNames =
        /^\s*(?:var\s+)?([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::=|=(?!=))/u
          .exec(structural)?.[1]
          ?.split(",")
          .map((name) => name.trim()) ?? [];
      if (
        syntacticAssignedNames.some((name) =>
          function_.parameters.some((parameter) => parameter.name === name),
        )
      ) {
        invalid = true;
        break;
      }
      const fieldWrite = constructorFieldAssignment(structural);
      if (fieldWrite !== undefined) {
        const alias = aliases.get(fieldWrite.target);
        if (alias === undefined) continue;
        if (
          lineNestingDepth(function_, statementLine) !== 1 ||
          (fieldWrite.explicitDereference && !result.pointer) ||
          fieldWrite.fields.length === 0 ||
          fieldWrite.fields.length > MAX_OBJECT_RECEIVER_FIELD_DEPTH ||
          writeCount >= MAX_OBJECT_CONSTRUCTOR_FIELD_WRITES
        ) {
          invalid = true;
          break;
        }
        const valueOffset = structural.indexOf(fieldWrite.value);
        const valueLine =
          valueOffset < 0
            ? statementLine
            : statementLine +
              structural.slice(0, valueOffset).split("\n").length -
              1;
        steps.push({
          kind: "write",
          target: fieldWrite.target,
          fields: [...fieldWrite.fields],
          value: fieldWrite.value,
          valueLine,
          line: statementLine,
          propagators: [...alias.propagators],
        });
        writeCount += 1;
        continue;
      }
      const assignment = goAssignment(structural);
      if (assignment === undefined) continue;
      if (lineNestingDepth(function_, statementLine) !== 1) {
        if (assignment.names.some((name) => aliases.has(name))) {
          invalid = true;
          break;
        }
        continue;
      }
      if (assignment.names.length !== 1) {
        for (const name of assignment.names) aliases.delete(name);
        continue;
      }
      const name = assignment.names[0]!;
      const direct = localCompositeResult(assignment.value, result.typeName);
      const helperCall = constructorValueHelperCall(assignment.value);
      if (direct !== undefined && direct.pointer !== result.pointer) {
        aliases.delete(name);
        continue;
      }
      if (direct !== undefined || helperCall !== undefined) {
        aliases.set(name, {
          expression: assignment.value,
          expressionLine: statementLine,
          depth: 0,
          propagators: [
            {
              kind: "go-method-receiver-constructor-helper-alias",
              line: statementLine,
              symbol: name,
              path: function_.file.path,
            },
          ],
        });
        steps.push({
          kind: "bind",
          name,
          expression: assignment.value,
          line: statementLine,
        });
        continue;
      }
      const priorName = /^([A-Za-z_]\w*)$/u.exec(assignment.value.trim())?.[1];
      const prior =
        priorName === undefined ? undefined : aliases.get(priorName);
      if (
        prior === undefined ||
        prior.depth >= MAX_OBJECT_CONSTRUCTOR_ALIAS_DEPTH
      ) {
        aliases.delete(name);
        continue;
      }
      aliases.set(name, {
        expression: prior.expression,
        expressionLine: prior.expressionLine,
        depth: prior.depth + 1,
        propagators: [
          ...prior.propagators,
          {
            kind: "go-method-receiver-constructor-helper-alias",
            line: statementLine,
            symbol: name,
            path: function_.file.path,
          },
        ],
      });
      steps.push({
        kind: "copy",
        name,
        source: priorName!,
        line: statementLine,
      });
    }
    if (
      invalid ||
      returns.length !== 1 ||
      constructorValueHelperPathWriteCount(returns[0]!.steps) >
        MAX_OBJECT_CONSTRUCTOR_FIELD_WRITES
    )
      continue;
    const returned = returns[0]!;
    const resolvedImportPath = localPackageImportPath(function_, modules);
    constructorValueHelperCandidates.push({
      key,
      function_,
      result: {
        typeName: result.typeName,
        pointer: result.pointer,
        resolvedDirectory: posix.dirname(function_.file.path),
        resolvedPackageName: function_.packageName,
        ...(resolvedImportPath === undefined ? {} : { resolvedImportPath }),
      },
      expression: returned.expression,
      expressionLine: returned.expressionLine,
      returnLine: returned.returnLine,
      aliases: returned.propagators,
      ...(returned.returnAlias === undefined
        ? {}
        : { returnAlias: returned.returnAlias }),
      steps: returned.steps,
    });
  }
  const constructorValueHelpers = constructorValueHelperCandidates.filter(
    (summary) => constructorValueHelperCounts.get(summary.key) === 1,
  );

  interface ConstructorHelperArgumentBinding {
    expression: string;
    useLine: number;
  }
  const expressionReferencesHelperBinding = (
    expression: string,
    bindings: ReadonlyMap<string, ConstructorHelperArgumentBinding>,
  ): boolean =>
    [...bindings.keys()].some((name) =>
      new RegExp(`\\b${escapeRegularExpression(name)}\\b`, "u").test(
        expression,
      ),
    );

  const constructorHelperCompositeReference = (
    reference: TypeReference,
    context: GoFunction,
    line: number,
  ): TypeReference | undefined => {
    const matches = structs.filter(
      (descriptor) =>
        descriptor.name === reference.typeName &&
        typeMatchesIdentity(
          reference,
          context.file,
          context.packageName,
          descriptor.directory,
          descriptor.packageName,
          descriptor.importPath,
          context,
          line,
        ),
    );
    if (matches.length !== 1) return undefined;
    const descriptor = matches[0]!;
    return {
      typeName: descriptor.name,
      pointer: reference.pointer,
      resolvedDirectory: descriptor.directory,
      resolvedPackageName: descriptor.packageName,
      ...(descriptor.importPath === undefined
        ? {}
        : { resolvedImportPath: descriptor.importPath }),
    };
  };

  const constructorHelperCompositeOwner = (
    reference: TypeReference,
    context: GoFunction,
    line: number,
  ): StructDescriptor | undefined => {
    const matches = structs.filter(
      (descriptor) =>
        descriptor.name === reference.typeName &&
        typeMatchesIdentity(
          reference,
          context.file,
          context.packageName,
          descriptor.directory,
          descriptor.packageName,
          descriptor.importPath,
          context,
          line,
        ),
    );
    return matches.length === 1 ? matches[0] : undefined;
  };

  function materializeConstructorHelperValue(
    expression: string,
    context: GoFunction,
    line: number,
    bindings: ReadonlyMap<string, ConstructorHelperArgumentBinding>,
    helperDepth: number,
    fieldDepth: number,
    visiting: ReadonlySet<string>,
  ): ConstructorValueState | undefined {
    const bare = /^([A-Za-z_]\w*)$/u.exec(expression.trim())?.[1];
    const binding = bare === undefined ? undefined : bindings.get(bare);
    if (binding !== undefined) {
      const state = constructorValueState(
        binding.expression,
        line,
        false,
        fieldDepth,
        context.file.path,
      );
      state.useLine = binding.useLine;
      return state;
    }
    const helperCall = constructorValueHelperCall(expression);
    if (helperCall !== undefined)
      return materializeConstructorValueHelperCall(
        context,
        expression,
        line,
        bindings,
        helperDepth,
        fieldDepth,
        visiting,
      );
    const composite = keyedCompositeResult(expression);
    if (composite !== undefined) {
      if (fieldDepth >= MAX_OBJECT_RECEIVER_FIELD_DEPTH) return undefined;
      const reference = constructorHelperCompositeReference(
        composite.reference,
        context,
        line,
      );
      if (reference === undefined) return undefined;
      const fields = new Map<string, ConstructorValueState>();
      for (const [field, value] of composite.fields) {
        const state = materializeConstructorHelperValue(
          value,
          context,
          line,
          bindings,
          helperDepth,
          fieldDepth + 1,
          visiting,
        );
        if (state === undefined) return undefined;
        fields.set(field, state);
      }
      const state: ConstructorValueState = {
        expression,
        line,
        write: false,
        path: context.file.path,
        composite: { reference, fields },
      };
      state.expression = renderConstructorValueState(state);
      return state;
    }
    if (expressionReferencesHelperBinding(expression, bindings))
      return undefined;
    return constructorValueState(
      expression,
      line,
      false,
      fieldDepth,
      context.file.path,
    );
  }

  function copyConstructorHelperStructValue(
    value: ConstructorValueState,
    owner: StructDescriptor,
    context: GoFunction,
    line: number,
  ): ConstructorValueState | undefined {
    if (value.composite === undefined) return copyConstructorValueState(value);
    const fields = new Map<string, ConstructorValueState>();
    const copy: ConstructorValueState = {
      expression: value.expression,
      line: value.line,
      write: value.write,
      ...(value.path === undefined ? {} : { path: value.path }),
      ...(value.bindingLine === undefined
        ? {}
        : { bindingLine: value.bindingLine }),
      ...(value.useLine === undefined ? {} : { useLine: value.useLine }),
      ...(value.origins === undefined ? {} : { origins: [...value.origins] }),
      ...(value.propagators === undefined
        ? {}
        : { propagators: [...value.propagators] }),
      composite: {
        reference: value.composite.reference,
        fields,
      },
    };
    for (const [fieldName, fieldValue] of value.composite.fields) {
      const field = owner.fields.get(fieldName);
      if (field === undefined) return undefined;
      if (field.type.pointer) {
        fields.set(fieldName, fieldValue);
        continue;
      }
      if (fieldValue.composite === undefined) {
        fields.set(fieldName, copyConstructorValueState(fieldValue));
        continue;
      }
      const nextOwner = constructorHelperCompositeOwner(
        fieldValue.composite.reference,
        context,
        line,
      );
      if (
        nextOwner === undefined ||
        field.type.pointer !== fieldValue.composite.reference.pointer ||
        !typeMatchesIdentity(
          field.type,
          field.file,
          field.packageName,
          nextOwner.directory,
          nextOwner.packageName,
          nextOwner.importPath,
        )
      )
        return undefined;
      const fieldCopy = copyConstructorHelperStructValue(
        fieldValue,
        nextOwner,
        context,
        line,
      );
      if (fieldCopy === undefined) return undefined;
      fields.set(fieldName, fieldCopy);
    }
    copy.expression = renderConstructorValueState(copy);
    return copy;
  }

  function materializeConstructorValueHelperCall(
    caller: GoFunction,
    expression: string,
    line: number,
    inheritedBindings: ReadonlyMap<
      string,
      ConstructorHelperArgumentBinding
    > = new Map(),
    helperDepth = 0,
    fieldDepth = 0,
    visiting: ReadonlySet<string> = new Set(),
  ): ConstructorValueState | undefined {
    if (helperDepth >= MAX_OBJECT_CONSTRUCTOR_HELPER_DEPTH) return undefined;
    const call = constructorValueHelperCall(expression);
    if (call === undefined) return undefined;
    const matches = constructorValueHelpers.flatMap((summary) => {
      if (
        summary.function_.parameters.length !== call.arguments.length ||
        summary.function_.parameters.some((parameter) =>
          parameter.type.trim().startsWith("..."),
        )
      )
        return [];
      const resolved = transactionSummaryCallMatch(caller, call.name, line, {
        file: summary.function_.file,
        packageName: summary.function_.packageName,
        packageImportPath: summary.result.resolvedImportPath,
        functionName: summary.function_.name,
      });
      return resolved === undefined || resolved.functionValues.length !== 0
        ? []
        : [{ summary, resolved }];
    });
    if (matches.length !== 1) return undefined;
    const { summary, resolved } = matches[0]!;
    if (visiting.has(summary.key)) return undefined;
    const bindings = new Map<string, ConstructorHelperArgumentBinding>();
    for (const [index, parameter] of summary.function_.parameters.entries()) {
      const argument = call.arguments[index];
      if (argument === undefined) return undefined;
      const bare = /^([A-Za-z_]\w*)$/u.exec(argument.trim())?.[1];
      const inherited =
        bare === undefined ? undefined : inheritedBindings.get(bare);
      if (inherited !== undefined) {
        bindings.set(parameter.name, inherited);
        continue;
      }
      if (expressionReferencesHelperBinding(argument, inheritedBindings))
        return undefined;
      bindings.set(parameter.name, { expression: argument, useLine: line });
    }
    const nextVisiting = new Set(visiting);
    nextVisiting.add(summary.key);
    const applyWrite = (
      target: ConstructorValueState,
      write: Extract<
        ConstructorValueHelperSummary["steps"][number],
        { kind: "write" }
      >,
    ): boolean => {
      if (
        target.composite === undefined ||
        fieldDepth + write.fields.length > MAX_OBJECT_RECEIVER_FIELD_DEPTH
      )
        return false;
      let composite = target.composite;
      let owner = constructorHelperCompositeOwner(
        composite.reference,
        summary.function_,
        write.line,
      );
      if (owner === undefined) return false;
      for (const [index, fieldName] of write.fields.entries()) {
        const field = owner.fields.get(fieldName);
        if (
          field === undefined ||
          (owner.packageName !== summary.function_.packageName &&
            !/^[A-Z]/u.test(fieldName))
        )
          return false;
        if (index === write.fields.length - 1) {
          const value = materializeConstructorHelperValue(
            write.value,
            summary.function_,
            write.valueLine,
            bindings,
            helperDepth + 1,
            fieldDepth + write.fields.length,
            nextVisiting,
          );
          if (value === undefined) return false;
          value.line = write.line;
          value.write = true;
          value.path = summary.function_.file.path;
          value.propagators = [
            ...write.propagators,
            ...(value.propagators ?? []),
          ];
          composite.fields.set(fieldName, value);
          return true;
        }
        const parent = composite.fields.get(fieldName);
        if (parent?.composite === undefined) return false;
        const nextOwner = constructorHelperCompositeOwner(
          parent.composite.reference,
          summary.function_,
          write.line,
        );
        if (
          nextOwner === undefined ||
          field.type.pointer !== parent.composite.reference.pointer ||
          !typeMatchesIdentity(
            field.type,
            field.file,
            field.packageName,
            nextOwner.directory,
            nextOwner.packageName,
            nextOwner.importPath,
          )
        )
          return false;
        composite = parent.composite;
        owner = nextOwner;
      }
      return false;
    };
    const cloneHelperValueGraph = (
      value: ConstructorValueState,
      memo: Map<ConstructorValueState, ConstructorValueState>,
    ): ConstructorValueState => {
      const prior = memo.get(value);
      if (prior !== undefined) return prior;
      const clone: ConstructorValueState = {
        expression: value.expression,
        line: value.line,
        write: value.write,
        ...(value.path === undefined ? {} : { path: value.path }),
        ...(value.bindingLine === undefined
          ? {}
          : { bindingLine: value.bindingLine }),
        ...(value.useLine === undefined ? {} : { useLine: value.useLine }),
        ...(value.origins === undefined ? {} : { origins: [...value.origins] }),
        ...(value.propagators === undefined
          ? {}
          : { propagators: [...value.propagators] }),
      };
      memo.set(value, clone);
      if (value.composite !== undefined)
        clone.composite = {
          reference: value.composite.reference,
          fields: new Map(
            [...value.composite.fields].map(
              ([field, fieldValue]): [string, ConstructorValueState] => [
                field,
                cloneHelperValueGraph(fieldValue, memo),
              ],
            ),
          ),
        };
      return clone;
    };
    const cloneHelperAliases = (
      source: ReadonlyMap<string, ConstructorValueState>,
    ): Map<string, ConstructorValueState> => {
      const memo = new Map<ConstructorValueState, ConstructorValueState>();
      return new Map(
        [...source].map(([name, value]): [string, ConstructorValueState] => [
          name,
          cloneHelperValueGraph(value, memo),
        ]),
      );
    };
    const applyBranchWrites = (
      targetAliases: ReadonlyMap<string, ConstructorValueState>,
      writes: readonly ConstructorValueHelperWriteStep[],
    ): boolean => {
      for (const write of writes) {
        const target = targetAliases.get(write.target);
        if (target === undefined || !applyWrite(target, write)) return false;
      }
      return true;
    };
    const joinHelperAliases = (
      left: ReadonlyMap<string, ConstructorValueState>,
      right: ReadonlyMap<string, ConstructorValueState>,
    ): Map<string, ConstructorValueState> | undefined => {
      if (left.size !== right.size) return undefined;
      const memo = constructorValueJoinMemo();
      const joined = new Map<string, ConstructorValueState>();
      for (const [name, leftValue] of left) {
        const rightValue = right.get(name);
        if (rightValue === undefined) return undefined;
        const value = joinConstructorValueState(leftValue, rightValue, memo);
        if (value === undefined) return undefined;
        joined.set(name, value);
      }
      return joined;
    };
    let state: ConstructorValueState | undefined;
    if (summary.returnAlias === undefined) {
      state = materializeConstructorHelperValue(
        summary.expression,
        summary.function_,
        summary.expressionLine,
        bindings,
        helperDepth + 1,
        fieldDepth,
        nextVisiting,
      );
    } else {
      const aliases = new Map<string, ConstructorValueState>();
      for (const step of summary.steps) {
        if (step.kind === "bind") {
          const bound = materializeConstructorHelperValue(
            step.expression,
            summary.function_,
            step.line,
            bindings,
            helperDepth + 1,
            fieldDepth,
            nextVisiting,
          );
          if (bound === undefined) return undefined;
          aliases.set(step.name, bound);
          continue;
        }
        if (step.kind === "copy") {
          const source = aliases.get(step.source);
          if (source?.composite === undefined) return undefined;
          if (summary.result.pointer) {
            aliases.set(step.name, source);
            continue;
          }
          const owner = constructorHelperCompositeOwner(
            source.composite.reference,
            summary.function_,
            step.line,
          );
          if (owner === undefined) return undefined;
          const copied = copyConstructorHelperStructValue(
            source,
            owner,
            summary.function_,
            step.line,
          );
          if (copied === undefined) return undefined;
          aliases.set(step.name, copied);
          continue;
        }
        if (step.kind === "branch") {
          const worlds = step.arms.map((arm) => {
            const world = cloneHelperAliases(aliases);
            return applyBranchWrites(world, arm) ? world : undefined;
          });
          if (worlds.length < 2 || worlds.some((world) => world === undefined))
            return undefined;
          let joined = worlds[0]!;
          for (const world of worlds.slice(1)) {
            const next = joinHelperAliases(joined, world!);
            if (next === undefined) return undefined;
            joined = next;
          }
          aliases.clear();
          for (const [name, value] of joined) aliases.set(name, value);
          continue;
        }
        const target = aliases.get(step.target);
        if (target === undefined || !applyWrite(target, step)) return undefined;
      }
      state = aliases.get(summary.returnAlias);
    }
    if (state?.composite !== undefined) {
      state.expression = renderConstructorValueState(state);
    }
    if (
      state?.composite === undefined ||
      state.composite.reference.qualifier !== undefined ||
      !sameTypeReference(
        {
          ...state.composite.reference,
          resolvedDirectory: posix.dirname(summary.function_.file.path),
          resolvedPackageName: summary.function_.packageName,
          ...(summary.result.resolvedImportPath === undefined
            ? {}
            : { resolvedImportPath: summary.result.resolvedImportPath }),
        },
        summary.result,
      )
    )
      return undefined;
    state.bindingLine = line;
    const helperBoundary: EvidencePropagator[] = [
      {
        kind: "go-method-receiver-constructor-helper-call",
        line,
        symbol: resolved.name,
        path: caller.file.path,
      },
      ...(state.propagators ?? []),
      ...summary.aliases,
      ...constructorValueHelperWriteSteps(summary.steps).flatMap(
        (step) => step.propagators,
      ),
      {
        kind: "go-method-receiver-constructor-helper-return",
        line: summary.returnLine,
        symbol: `${summary.result.pointer ? "*" : ""}${summary.function_.packageName}.${summary.result.typeName}`,
        path: summary.function_.file.path,
      },
    ];
    const attachHelperBoundary = (
      value: ConstructorValueState,
      visited: Set<ConstructorValueState>,
    ): void => {
      if (visited.has(value)) return;
      visited.add(value);
      value.propagators = [...helperBoundary, ...(value.propagators ?? [])];
      if (value.composite !== undefined)
        for (const field of value.composite.fields.values())
          attachHelperBoundary(field, visited);
    };
    const existingPropagators = state.propagators ?? [];
    if (state.composite !== undefined) {
      const visited = new Set<ConstructorValueState>([state]);
      for (const field of state.composite.fields.values())
        attachHelperBoundary(field, visited);
    }
    state.propagators = [
      helperBoundary[0]!,
      ...existingPropagators,
      ...helperBoundary.slice(1),
    ];
    state.expression = renderConstructorValueState(state);
    return state;
  }

  const constructorCandidates: ConstructorSummary[] = [];
  const constructorCounts = new Map<string, number>();
  for (const function_ of functions) {
    if (function_.receiver !== undefined) continue;
    const key = `${posix.dirname(function_.file.path)}\0${function_.packageName}\0${function_.name}`;
    constructorCounts.set(key, (constructorCounts.get(key) ?? 0) + 1);
    const result = typeReference(function_.returnSignature);
    if (result === undefined || result.qualifier !== undefined) continue;
    const matchingStructs = structs.filter(
      (descriptor) =>
        descriptor.directory === posix.dirname(function_.file.path) &&
        descriptor.packageName === function_.packageName &&
        descriptor.name === result.typeName,
    );
    if (matchingStructs.length !== 1) continue;
    const resultStruct = matchingStructs[0]!;
    const materializeHelper = (
      expression: string,
      line: number,
      write: boolean,
      fieldDepth: number,
    ): ConstructorValueState | undefined => {
      const state = materializeConstructorValueHelperCall(
        function_,
        expression,
        line,
        new Map(),
        0,
        fieldDepth,
      );
      if (state === undefined) return undefined;
      state.write = write;
      state.bindingLine = line;
      return state;
    };
    const valueState = (
      expression: string,
      line: number,
      write: boolean,
    ): ConstructorValueState =>
      constructorValueState(
        expression,
        line,
        write,
        0,
        function_.file.path,
        materializeHelper,
      );
    interface ConstructorState {
      fields: Map<string, ConstructorValueState>;
    }
    interface ConstructorWriteBudget {
      count: number;
    }
    interface ConstructorAlias {
      pointer: boolean;
      depth: number;
      state: ConstructorState;
      propagators: EvidencePropagator[];
    }
    const stateForComposite = (
      fields: ReadonlyMap<string, string>,
      line: number,
      source: string,
    ): ConstructorState => {
      let searchOffset = 0;
      return {
        fields: new Map(
          [...fields].map(
            ([field, expression]): [string, ConstructorValueState] => {
              const expressionOffset = source.indexOf(expression, searchOffset);
              const expressionLine =
                expressionOffset < 0
                  ? line
                  : line +
                    source.slice(0, expressionOffset).split("\n").length -
                    1;
              if (expressionOffset >= 0)
                searchOffset = expressionOffset + expression.length;
              return [field, valueState(expression, expressionLine, false)];
            },
          ),
        ),
      };
    };
    const snapshotState = (state: ConstructorState): ConstructorState => ({
      fields: new Map(
        [...state.fields].map(
          ([field, value]): [string, ConstructorValueState] => [
            field,
            copyConstructorValueState(value),
          ],
        ),
      ),
    });
    function copyValueForStruct(
      value: ConstructorValueState,
      owner: StructDescriptor,
    ): ConstructorValueState {
      if (value.composite === undefined)
        return copyConstructorValueState(value);
      return {
        expression: value.expression,
        line: value.line,
        write: value.write,
        ...(value.path === undefined ? {} : { path: value.path }),
        ...(value.bindingLine === undefined
          ? {}
          : { bindingLine: value.bindingLine }),
        ...(value.useLine === undefined ? {} : { useLine: value.useLine }),
        ...(value.origins === undefined ? {} : { origins: [...value.origins] }),
        ...(value.propagators === undefined
          ? {}
          : { propagators: [...value.propagators] }),
        composite: {
          reference: value.composite.reference,
          fields: new Map(
            [...value.composite.fields].map(
              ([fieldName, fieldValue]): [string, ConstructorValueState] => {
                const field = owner.fields.get(fieldName);
                return [
                  fieldName,
                  field === undefined
                    ? copyConstructorValueState(fieldValue)
                    : copyValueForField(fieldValue, field),
                ];
              },
            ),
          ),
        },
      };
    }
    function copyValueForField(
      value: ConstructorValueState,
      field: StructFieldDescriptor,
    ): ConstructorValueState {
      if (field.type.pointer) return value;
      const owners = structs.filter(
        (descriptor) =>
          descriptor.name === field.type.typeName &&
          typeMatchesIdentity(
            field.type,
            field.file,
            field.packageName,
            descriptor.directory,
            descriptor.packageName,
            descriptor.importPath,
          ),
      );
      if (owners.length === 1) return copyValueForStruct(value, owners[0]!);
      return value.composite?.reference.pointer === true
        ? value
        : copyConstructorValueState(value);
    }
    const copyAssignedState = (state: ConstructorState): ConstructorState => ({
      fields: new Map(
        [...state.fields].map(
          ([fieldName, value]): [string, ConstructorValueState] => {
            const field = resultStruct.fields.get(fieldName);
            return [
              fieldName,
              field === undefined
                ? copyConstructorValueState(value)
                : copyValueForField(value, field),
            ];
          },
        ),
      ),
    });
    const cloneConstructorValueGraph = (
      value: ConstructorValueState,
      memo: Map<ConstructorValueState, ConstructorValueState>,
    ): ConstructorValueState => {
      const prior = memo.get(value);
      if (prior !== undefined) return prior;
      const clone: ConstructorValueState = {
        expression: value.expression,
        line: value.line,
        write: value.write,
        ...(value.path === undefined ? {} : { path: value.path }),
        ...(value.bindingLine === undefined
          ? {}
          : { bindingLine: value.bindingLine }),
        ...(value.useLine === undefined ? {} : { useLine: value.useLine }),
        ...(value.origins === undefined ? {} : { origins: [...value.origins] }),
        ...(value.propagators === undefined
          ? {}
          : { propagators: [...value.propagators] }),
      };
      memo.set(value, clone);
      if (value.composite !== undefined) {
        clone.composite = {
          reference: value.composite.reference,
          fields: new Map(
            [...value.composite.fields].map(
              ([field, fieldValue]): [string, ConstructorValueState] => [
                field,
                cloneConstructorValueGraph(fieldValue, memo),
              ],
            ),
          ),
        };
      }
      return clone;
    };
    const cloneAliases = (
      source: ReadonlyMap<string, ConstructorAlias>,
    ): {
      aliases: Map<string, ConstructorAlias>;
      states: Map<ConstructorState, ConstructorState>;
    } => {
      const states = new Map<ConstructorState, ConstructorState>();
      const values = new Map<ConstructorValueState, ConstructorValueState>();
      const aliases = new Map<string, ConstructorAlias>();
      for (const [name, alias] of source) {
        let state = states.get(alias.state);
        if (state === undefined) {
          state = {
            fields: new Map(
              [...alias.state.fields].map(
                ([field, value]): [string, ConstructorValueState] => [
                  field,
                  cloneConstructorValueGraph(value, values),
                ],
              ),
            ),
          };
          states.set(alias.state, state);
        }
        aliases.set(name, {
          pointer: alias.pointer,
          depth: alias.depth,
          state,
          propagators: [...alias.propagators],
        });
      }
      return { aliases, states };
    };
    const constructorCompositeOwner = (
      reference: TypeReference,
    ): StructDescriptor | undefined => {
      const matches = structs.filter(
        (descriptor) =>
          descriptor.name === reference.typeName &&
          typeMatchesIdentity(
            reference,
            function_.file,
            function_.packageName,
            descriptor.directory,
            descriptor.packageName,
            descriptor.importPath,
            function_,
            function_.startLine,
          ),
      );
      return matches.length === 1 ? matches[0] : undefined;
    };
    const applyConstructorFieldWrite = (
      targetAliases: ReadonlyMap<string, ConstructorAlias>,
      fieldWrite: NonNullable<ReturnType<typeof constructorFieldAssignment>>,
      statementLine: number,
      expectedDepth: number,
      budget: ConstructorWriteBudget,
    ): boolean => {
      const alias = targetAliases.get(fieldWrite.target);
      if (
        alias === undefined ||
        lineNestingDepth(function_, statementLine) !== expectedDepth ||
        fieldWrite.fields.length > MAX_OBJECT_RECEIVER_FIELD_DEPTH ||
        (fieldWrite.explicitDereference && !alias.pointer) ||
        budget.count >= MAX_OBJECT_CONSTRUCTOR_FIELD_WRITES
      )
        return false;
      let fields = alias.state.fields;
      let owner = resultStruct;
      for (const [index, fieldName] of fieldWrite.fields.entries()) {
        const field = owner.fields.get(fieldName);
        if (
          field === undefined ||
          (owner.packageName !== function_.packageName &&
            !/^[A-Z]/u.test(fieldName))
        )
          return false;
        if (index === fieldWrite.fields.length - 1) break;
        const parent = fields.get(fieldName);
        if (parent?.composite === undefined) return false;
        const nextOwner = constructorCompositeOwner(parent.composite.reference);
        if (
          nextOwner === undefined ||
          field.type.pointer !== parent.composite.reference.pointer ||
          !typeMatchesIdentity(
            field.type,
            field.file,
            field.packageName,
            nextOwner.directory,
            nextOwner.packageName,
            nextOwner.importPath,
          )
        )
          return false;
        owner = nextOwner;
        fields = parent.composite.fields;
      }
      fields.set(
        fieldWrite.fields.at(-1)!,
        valueState(fieldWrite.value, statementLine, true),
      );
      budget.count += 1;
      return true;
    };
    const applyConstructorBranch = (
      targetAliases: ReadonlyMap<string, ConstructorAlias>,
      startLine: number,
      endLine: number,
      statementDepth: number,
      budget: ConstructorWriteBudget,
    ): number | undefined => {
      let writes = 0;
      for (let line = startLine; line <= endLine; line += 1) {
        if ((function_.structuralLines[line - 1] ?? "").trim() === "") continue;
        const statementLine = line;
        const statement = constructorStatement(function_, line);
        if (statement.endLine > endLine) return undefined;
        line = statement.endLine;
        const fieldWrite = constructorFieldAssignment(statement.structural);
        if (
          fieldWrite === undefined ||
          !applyConstructorFieldWrite(
            targetAliases,
            fieldWrite,
            statementLine,
            statementDepth,
            budget,
          )
        )
          return undefined;
        writes += 1;
      }
      return writes;
    };
    const joinConstructorStates = (
      left: ConstructorState,
      right: ConstructorState,
      memo: ConstructorValueJoinMemo,
    ): ConstructorState | undefined => {
      if (left.fields.size !== right.fields.size) return undefined;
      const fields = new Map<string, ConstructorValueState>();
      for (const [field, leftValue] of left.fields) {
        const rightValue = right.fields.get(field);
        if (rightValue === undefined) return undefined;
        const value = joinConstructorValueState(leftValue, rightValue, memo);
        if (value === undefined) return undefined;
        fields.set(field, value);
      }
      return { fields };
    };
    const aliases = new Map<string, ConstructorAlias>();
    const writeBudget: ConstructorWriteBudget = { count: 0 };
    const returns: Array<{
      pointer: boolean;
      line: number;
      fields: ReadonlyMap<string, ConstructorValueState>;
      propagators: EvidencePropagator[];
    }> = [];
    let invalid = false;
    for (
      let line = function_.bodyStartLine;
      line <= function_.endLine;
      line += 1
    ) {
      const statementLine = line;
      const statement = constructorStatement(function_, line);
      const structural = statement.structural;
      line = statement.endLine;
      const conditional =
        lineNestingDepth(function_, statementLine) === 1
          ? constructorControlBranches(function_, statementLine)
          : undefined;
      if (conditional !== undefined) {
        const worlds = conditional.arms.map(({ startLine, endLine }) => {
          const branch = cloneAliases(aliases);
          const budget: ConstructorWriteBudget = { count: writeBudget.count };
          const writes = applyConstructorBranch(
            branch.aliases,
            startLine,
            endLine,
            conditional.statementDepth,
            budget,
          );
          return { branch, budget, writes };
        });
        const firstWrites = worlds[0]?.writes;
        const firstBudget = worlds[0]?.budget.count;
        if (
          worlds.length < 2 ||
          firstWrites === undefined ||
          firstWrites === 0 ||
          firstBudget === undefined ||
          worlds.some(
            ({ writes, budget }) =>
              writes === undefined ||
              writes !== firstWrites ||
              budget.count !== firstBudget,
          )
        ) {
          invalid = true;
          break;
        }
        const originalStates = new Set<ConstructorState>();
        for (const alias of aliases.values()) {
          originalStates.add(alias.state);
        }
        let joinedStates = new Map<ConstructorState, ConstructorState>();
        for (const original of originalStates) {
          const state = worlds[0]!.branch.states.get(original);
          if (state === undefined) {
            invalid = true;
            break;
          }
          joinedStates.set(original, state);
        }
        for (const world of worlds.slice(1)) {
          if (invalid) break;
          const nextStates = new Map<ConstructorState, ConstructorState>();
          const valueMemo = constructorValueJoinMemo();
          for (const original of originalStates) {
            const left = joinedStates.get(original);
            const right = world.branch.states.get(original);
            if (left === undefined || right === undefined) {
              invalid = true;
              break;
            }
            const joined = joinConstructorStates(left, right, valueMemo);
            if (joined === undefined) {
              invalid = true;
              break;
            }
            nextStates.set(original, joined);
          }
          joinedStates = nextStates;
        }
        if (invalid) break;
        for (const alias of aliases.values())
          alias.state = joinedStates.get(alias.state)!;
        writeBudget.count = firstBudget;
        line = conditional.endLine;
        continue;
      }
      const returnMatch = /^\s*return\s+([\s\S]+?)\s*;?\s*$/u.exec(structural);
      if (/\breturn\b/u.test(structural)) {
        if (
          lineNestingDepth(function_, statementLine) !== 1 ||
          returnMatch === null
        ) {
          invalid = true;
          break;
        }
        const direct = localCompositeResult(returnMatch[1]!, result.typeName);
        const aliasName = /^([A-Za-z_]\w*)$/u.exec(returnMatch[1]!.trim())?.[1];
        const alias =
          aliasName === undefined ? undefined : aliases.get(aliasName);
        if (direct === undefined && alias === undefined) {
          invalid = true;
          break;
        }
        const state =
          direct === undefined
            ? snapshotState(alias!.state)
            : stateForComposite(direct.fields, statementLine, returnMatch[1]!);
        returns.push({
          pointer: direct?.pointer ?? alias!.pointer,
          line: statementLine,
          fields: state.fields,
          propagators: alias?.propagators ?? [],
        });
        continue;
      }
      const fieldWrite = constructorFieldAssignment(structural);
      if (fieldWrite !== undefined) {
        if (!aliases.has(fieldWrite.target)) continue;
        if (
          !applyConstructorFieldWrite(
            aliases,
            fieldWrite,
            statementLine,
            1,
            writeBudget,
          )
        ) {
          invalid = true;
          break;
        }
        continue;
      }
      const assignment = goAssignment(structural);
      if (assignment === undefined) continue;
      if (lineNestingDepth(function_, statementLine) !== 1) {
        if (assignment.names.some((name) => aliases.has(name))) {
          invalid = true;
          break;
        }
        continue;
      }
      if (assignment.names.length !== 1) {
        for (const name of assignment.names) aliases.delete(name);
        continue;
      }
      const name = assignment.names[0]!;
      const direct = localCompositeResult(assignment.value, result.typeName);
      if (direct !== undefined) {
        aliases.set(name, {
          pointer: direct.pointer,
          depth: 0,
          state: stateForComposite(
            direct.fields,
            statementLine,
            assignment.value,
          ),
          propagators: [
            {
              kind: "go-method-receiver-constructor-alias",
              line: statementLine,
              symbol: name,
              path: function_.file.path,
            },
          ],
        });
        continue;
      }
      const priorName = /^([A-Za-z_]\w*)$/u.exec(assignment.value.trim())?.[1];
      const prior =
        priorName === undefined ? undefined : aliases.get(priorName);
      if (
        prior === undefined ||
        prior.depth >= MAX_OBJECT_CONSTRUCTOR_ALIAS_DEPTH
      ) {
        aliases.delete(name);
        continue;
      }
      aliases.set(name, {
        pointer: prior.pointer,
        depth: prior.depth + 1,
        state: prior.pointer ? prior.state : copyAssignedState(prior.state),
        propagators: [
          ...prior.propagators,
          {
            kind: "go-method-receiver-constructor-alias",
            line: statementLine,
            symbol: name,
            path: function_.file.path,
          },
        ],
      });
    }
    if (
      invalid ||
      returns.length !== 1 ||
      returns[0]!.pointer !== result.pointer
    )
      continue;
    const importPath = localPackageImportPath(function_, modules);
    const fieldSources = new Map<
      string,
      {
        parameterIndex?: number;
        expression?: string;
        line: number;
        write?: boolean;
        state?: ConstructorValueState;
      }
    >();
    const parameterUses = (
      value: ConstructorValueState,
    ): Array<{ name: string; line: number }> =>
      value.composite === undefined
        ? function_.parameters.flatMap((parameter) =>
            new RegExp(
              `\\b${escapeRegularExpression(parameter.name)}\\b`,
              "u",
            ).test(value.expression)
              ? (value.useLine === undefined
                  ? constructorValueOrigins(value)
                  : [value.useLine]
                ).map((line) => ({
                  name: parameter.name,
                  line,
                }))
              : [],
          )
        : [...value.composite.fields.values()].flatMap(parameterUses);
    for (const [fieldName, state] of returns[0]!.fields) {
      if (!resultStruct.fields.has(fieldName)) {
        invalid = true;
        break;
      }
      const expression = renderConstructorValueState(state);
      const parameterName = /^([A-Za-z_]\w*)$/u.exec(expression)?.[1];
      const parameterIndex = function_.parameters.findIndex(
        (parameter) => parameter.name === parameterName,
      );
      for (const use of parameterUses(state)) {
        const reassigned = Array.from(
          {
            length: Math.max(0, use.line - function_.bodyStartLine),
          },
          (_, index) => function_.bodyStartLine + index,
        ).some((line) => {
          const assignment = goAssignment(
            function_.structuralLines[line - 1] ?? "",
          );
          return assignment?.names.includes(use.name) === true;
        });
        if (reassigned) {
          invalid = true;
          break;
        }
      }
      if (invalid) break;
      fieldSources.set(fieldName, {
        ...(parameterIndex < 0 ? { expression } : { parameterIndex }),
        line: state.bindingLine ?? state.line,
        ...(state.write ? { write: true } : {}),
        state,
      });
    }
    if (invalid) continue;
    constructorCandidates.push({
      key,
      function_,
      ...(importPath === undefined ? {} : { importPath }),
      result: {
        typeName: result.typeName,
        pointer: result.pointer,
        resolvedDirectory: posix.dirname(function_.file.path),
        resolvedPackageName: function_.packageName,
        ...(importPath === undefined ? {} : { resolvedImportPath: importPath }),
      },
      resultStruct,
      returnLine: returns[0]!.line,
      aliases: returns[0]!.propagators,
      fieldSources,
    });
  }
  const constructors = constructorCandidates.filter(
    (summary) => constructorCounts.get(summary.key) === 1,
  );

  const interfaceForReference = (
    reference: TypeReference,
    contextFile: GoHttpSourceFile,
    contextPackageName: string,
    contextFunction?: GoFunction,
    contextLine?: number,
  ): InterfaceDescriptor | undefined => {
    if (reference.pointer) return undefined;
    const candidates = interfaces.filter((interface_) => {
      if (interface_.name !== reference.typeName) return false;
      if (reference.qualifier === undefined) {
        return (
          interface_.directory === posix.dirname(contextFile.path) &&
          interface_.packageName === contextPackageName
        );
      }
      if (interface_.importPath === undefined) return false;
      return (
        goImportAlias(
          contextFile.lines,
          interface_.importPath,
          interface_.packageName,
        ) === reference.qualifier &&
        (contextFunction === undefined ||
          contextLine === undefined ||
          packageAliasIsAvailable(
            contextFunction,
            reference.qualifier,
            contextLine,
          ))
      );
    });
    return candidates.length === 1 ? candidates[0] : undefined;
  };

  const interfaceForType = (
    caller: GoFunction,
    reference: TypeReference,
    line: number,
  ): InterfaceDescriptor | undefined =>
    interfaceForReference(
      reference,
      caller.file,
      caller.packageName,
      caller,
      line,
    );

  const canonicalConcreteReference = (
    reference: TypeReference,
    contextFile: GoHttpSourceFile,
    contextPackageName: string,
    contextFunction?: GoFunction,
    contextLine?: number,
  ): TypeReference | undefined => {
    const matches = structs.filter(
      (descriptor) =>
        descriptor.name === reference.typeName &&
        typeMatchesIdentity(
          reference,
          contextFile,
          contextPackageName,
          descriptor.directory,
          descriptor.packageName,
          descriptor.importPath,
          contextFunction,
          contextLine,
        ),
    );
    if (matches.length !== 1) return undefined;
    const descriptor = matches[0]!;
    return {
      typeName: descriptor.name,
      pointer: reference.pointer,
      resolvedDirectory: descriptor.directory,
      resolvedPackageName: descriptor.packageName,
      ...(descriptor.importPath === undefined
        ? {}
        : { resolvedImportPath: descriptor.importPath }),
    };
  };

  const concreteSatisfiesInterface = (
    concrete: TypeReference,
    interface_: InterfaceDescriptor,
  ): boolean =>
    [...interface_.methods].every((method) => {
      const matches = [...descriptors.values()].filter(
        (descriptor) =>
          descriptor.receiver !== undefined &&
          descriptor.function_.name === method &&
          descriptor.receiver.typeName === concrete.typeName &&
          posix.dirname(descriptor.function_.file.path) ===
            concrete.resolvedDirectory &&
          descriptor.function_.packageName === concrete.resolvedPackageName &&
          (!descriptor.receiver.pointer || concrete.pointer),
      );
      return matches.length === 1;
    });

  const concreteExpression = (
    caller: GoFunction,
    expression: string,
    line: number,
    availableBindings: ReadonlyMap<string, ReceiverBinding> = new Map(),
    constructorDepth = 0,
    valueState?: ConstructorValueState,
  ):
    | {
        concrete: TypeReference;
        interface_?: InterfaceDescriptor;
        fields?: ReadonlyMap<string, ReceiverBinding>;
        propagators?: EvidencePropagator[];
      }
    | undefined => {
    const trimmed = expression.trim().replace(/;\s*$/u, "");
    const composite = keyedCompositeResult(trimmed);
    if (composite !== undefined) {
      const compositeReference =
        valueState?.composite?.reference ?? composite.reference;
      if (
        compositeReference.typeName !== composite.reference.typeName ||
        compositeReference.pointer !== composite.reference.pointer
      )
        return undefined;
      if (
        constructorDepth > MAX_OBJECT_CONSTRUCTOR_ALIAS_DEPTH &&
        composite.fields.size > 0
      )
        return undefined;
      const concrete = canonicalConcreteReference(
        compositeReference,
        caller.file,
        caller.packageName,
        caller,
        line,
      );
      if (concrete === undefined) return undefined;
      const owners = structs.filter(
        (descriptor) =>
          descriptor.directory === concrete.resolvedDirectory &&
          descriptor.packageName === concrete.resolvedPackageName &&
          descriptor.name === concrete.typeName,
      );
      if (owners.length !== 1) return undefined;
      const owner = owners[0]!;
      const fields = new Map<string, ReceiverBinding>();
      for (const [fieldName, fieldExpression] of composite.fields) {
        const fieldState = valueState?.composite?.fields.get(fieldName);
        const fieldLines =
          fieldState === undefined
            ? [line]
            : constructorValueOrigins(fieldState);
        const fieldLine = fieldLines[0]!;
        const field = owner.fields.get(fieldName);
        if (field === undefined) return undefined;
        const fieldInterface = interfaceForReference(
          field.type,
          field.file,
          field.packageName,
        );
        const expected = canonicalConcreteReference(
          field.type,
          field.file,
          field.packageName,
        );
        if (fieldInterface === undefined && expected === undefined) continue;
        const bare = /^([A-Za-z_]\w*)$/u.exec(fieldExpression.trim())?.[1];
        const bound =
          bare === undefined ? undefined : availableBindings.get(bare);
        const value =
          bound === undefined
            ? concreteExpression(
                caller,
                fieldExpression,
                fieldLine,
                availableBindings,
                constructorDepth + 1,
                fieldState,
              )
            : {
                concrete: bound.concrete,
                ...(bound.interface_ === undefined
                  ? {}
                  : { interface_: bound.interface_ }),
                fields: bound.fields,
                propagators: bound.propagators,
              };
        if (value === undefined) return undefined;
        const canonical = canonicalConcreteReference(
          value.concrete,
          caller.file,
          caller.packageName,
          caller,
          fieldLine,
        );
        if (canonical === undefined) return undefined;
        if (
          fieldInterface === undefined
            ? expected === undefined ||
              expected.resolvedDirectory !== canonical.resolvedDirectory ||
              expected.resolvedPackageName !== canonical.resolvedPackageName ||
              expected.typeName !== canonical.typeName ||
              expected.pointer !== canonical.pointer
            : !concreteSatisfiesInterface(canonical, fieldInterface)
        )
          return undefined;
        fields.set(fieldName, {
          concrete: canonical,
          ...(fieldInterface === undefined
            ? {}
            : { interface_: fieldInterface }),
          fields: value.fields ?? new Map(),
          aliasDepth: 0,
          propagators: [
            ...(value.propagators ?? []),
            ...fieldLines.map(
              (originLine): EvidencePropagator => ({
                kind:
                  fieldState?.write === true
                    ? "go-method-receiver-constructor-field-write"
                    : "go-method-receiver-composite-field",
                line: originLine,
                symbol: `${owner.name}.${fieldName}:${canonical.resolvedPackageName}.${canonical.typeName}`,
                path: fieldState?.path ?? caller.file.path,
              }),
            ),
          ],
        });
      }
      return {
        concrete: compositeReference,
        fields,
        ...(valueState?.propagators === undefined
          ? {}
          : { propagators: valueState.propagators }),
      };
    }
    const allocation =
      /^new\s*\(\s*((?:[A-Za-z_]\w*\s*\.\s*)?[A-Za-z_]\w*)\s*\)$/u.exec(
        trimmed,
      );
    if (allocation !== null) {
      const concrete = typeReference(`*${allocation[1]!}`);
      return concrete === undefined ? undefined : { concrete };
    }
    const constructorCall =
      /^((?:[A-Za-z_]\w*\s*\.\s*)?[A-Za-z_]\w*)\s*\(([\s\S]*)\)$/u.exec(
        trimmed,
      );
    if (constructorCall !== null) {
      const segments = constructorCall[1]!
        .split(".")
        .map((segment) => segment.trim());
      const arguments_ =
        constructorCall[2]!.trim() === ""
          ? []
          : splitGoArguments(constructorCall[2]!);
      const matches = constructors.filter((summary) => {
        if (constructorDepth >= MAX_OBJECT_CONSTRUCTOR_ALIAS_DEPTH)
          return false;
        const variadic =
          summary.function_.parameters.at(-1)?.type.trim().startsWith("...") ===
          true;
        if (
          variadic
            ? arguments_.length < summary.function_.parameters.length - 1
            : arguments_.length !== summary.function_.parameters.length
        )
          return false;
        if (segments.length === 1) {
          const resolvedConstructor = resolvedTransactionHelperCall(
            caller,
            segments[0]!,
            line,
          );
          return (
            resolvedConstructor !== undefined &&
            resolvedConstructor.name === segments[0] &&
            resolvedConstructor.functionValues.length === 0 &&
            summary.function_.name === segments[0] &&
            posix.dirname(summary.function_.file.path) ===
              posix.dirname(caller.file.path) &&
            summary.function_.packageName === caller.packageName
          );
        }
        if (
          segments.length !== 2 ||
          !/^[A-Z]/u.test(segments[1]!) ||
          summary.importPath === undefined ||
          summary.function_.name !== segments[1] ||
          !packageAliasIsAvailable(caller, segments[0]!, line)
        )
          return false;
        return (
          goImportAlias(
            caller.file.lines,
            summary.importPath,
            summary.function_.packageName,
          ) === segments[0]
        );
      });
      if (matches.length === 1) {
        const summary = matches[0]!;
        const fields = new Map<string, ReceiverBinding>();
        const parameterBindings = new Map<string, ReceiverBinding>();
        for (const [
          parameterIndex,
          parameter,
        ] of summary.function_.parameters.entries()) {
          const parameterType = typeReference(parameter.type);
          const argument = arguments_[parameterIndex];
          if (parameterType === undefined || argument === undefined) continue;
          const parameterInterface = interfaceForType(
            summary.function_,
            parameterType,
            summary.function_.startLine,
          );
          const expectedParameter = canonicalConcreteReference(
            parameterType,
            summary.function_.file,
            summary.function_.packageName,
            summary.function_,
            summary.function_.startLine,
          );
          if (
            parameterInterface === undefined &&
            expectedParameter === undefined
          )
            continue;
          const bare = /^([A-Za-z_]\w*)$/u.exec(argument.trim())?.[1];
          const bound =
            bare === undefined ? undefined : availableBindings.get(bare);
          const value =
            bound === undefined
              ? concreteExpression(
                  caller,
                  argument,
                  line,
                  availableBindings,
                  constructorDepth + 1,
                )
              : {
                  concrete: bound.concrete,
                  ...(bound.interface_ === undefined
                    ? {}
                    : { interface_: bound.interface_ }),
                  fields: bound.fields,
                  propagators: bound.propagators,
                };
          if (value === undefined) continue;
          const canonical = canonicalConcreteReference(
            value.concrete,
            caller.file,
            caller.packageName,
            caller,
            line,
          );
          if (
            canonical === undefined ||
            (parameterInterface === undefined
              ? expectedParameter === undefined ||
                expectedParameter.resolvedDirectory !==
                  canonical.resolvedDirectory ||
                expectedParameter.resolvedPackageName !==
                  canonical.resolvedPackageName ||
                expectedParameter.typeName !== canonical.typeName ||
                expectedParameter.pointer !== canonical.pointer
              : !concreteSatisfiesInterface(canonical, parameterInterface))
          )
            continue;
          parameterBindings.set(parameter.name, {
            concrete: canonical,
            ...(parameterInterface === undefined
              ? {}
              : { interface_: parameterInterface }),
            fields: value.fields ?? new Map(),
            aliasDepth: 0,
            propagators: value.propagators ?? [],
          });
        }
        let validFields = true;
        for (const [fieldName, source] of summary.fieldSources) {
          const field = summary.resultStruct.fields.get(fieldName);
          if (field === undefined) {
            validFields = false;
            break;
          }
          const fieldInterface = interfaceForReference(
            field.type,
            field.file,
            field.packageName,
          );
          const fieldConcrete = canonicalConcreteReference(
            field.type,
            field.file,
            field.packageName,
          );
          if (fieldInterface === undefined && fieldConcrete === undefined)
            continue;
          let value:
            | {
                concrete: TypeReference;
                interface_?: InterfaceDescriptor;
                fields?: ReadonlyMap<string, ReceiverBinding>;
                propagators?: EvidencePropagator[];
              }
            | undefined;
          if (source.parameterIndex !== undefined) {
            const argument = arguments_[source.parameterIndex];
            if (argument === undefined) {
              validFields = false;
              break;
            }
            const parameter =
              summary.function_.parameters[source.parameterIndex];
            const parameterType =
              parameter === undefined
                ? undefined
                : typeReference(parameter.type);
            if (parameterType === undefined) {
              validFields = false;
              break;
            }
            const parameterInterface = interfaceForType(
              summary.function_,
              parameterType,
              source.line,
            );
            if (fieldInterface !== undefined) {
              if (
                parameterInterface !== undefined &&
                (parameterInterface.directory !== fieldInterface.directory ||
                  parameterInterface.packageName !==
                    fieldInterface.packageName ||
                  parameterInterface.name !== fieldInterface.name)
              ) {
                validFields = false;
                break;
              }
            } else {
              const expectedParameter = fieldConcrete;
              const actualParameter = canonicalConcreteReference(
                parameterType,
                summary.function_.file,
                summary.function_.packageName,
                summary.function_,
                source.line,
              );
              if (
                parameterInterface !== undefined ||
                expectedParameter === undefined ||
                actualParameter === undefined ||
                expectedParameter.resolvedDirectory !==
                  actualParameter.resolvedDirectory ||
                expectedParameter.resolvedPackageName !==
                  actualParameter.resolvedPackageName ||
                expectedParameter.typeName !== actualParameter.typeName ||
                expectedParameter.pointer !== actualParameter.pointer
              ) {
                validFields = false;
                break;
              }
            }
            const bare = /^([A-Za-z_]\w*)$/u.exec(argument.trim())?.[1];
            const bound =
              bare === undefined ? undefined : availableBindings.get(bare);
            value =
              bound === undefined
                ? concreteExpression(
                    caller,
                    argument,
                    line,
                    availableBindings,
                    constructorDepth + 1,
                  )
                : {
                    concrete: bound.concrete,
                    ...(bound.interface_ === undefined
                      ? {}
                      : { interface_: bound.interface_ }),
                    fields: bound.fields,
                    propagators: bound.propagators,
                  };
          } else if (source.expression !== undefined) {
            value = concreteExpression(
              summary.function_,
              source.expression,
              source.line,
              parameterBindings,
              constructorDepth + 1,
              source.state,
            );
          }
          if (value === undefined) {
            validFields = false;
            break;
          }
          const canonical = canonicalConcreteReference(
            value.concrete,
            source.parameterIndex === undefined
              ? summary.function_.file
              : caller.file,
            source.parameterIndex === undefined
              ? summary.function_.packageName
              : caller.packageName,
            source.parameterIndex === undefined ? summary.function_ : caller,
            source.parameterIndex === undefined ? source.line : line,
          );
          if (canonical === undefined) {
            validFields = false;
            break;
          }
          if (fieldInterface === undefined) {
            const expected = fieldConcrete;
            if (
              expected === undefined ||
              expected.resolvedDirectory !== canonical.resolvedDirectory ||
              expected.resolvedPackageName !== canonical.resolvedPackageName ||
              expected.typeName !== canonical.typeName ||
              expected.pointer !== canonical.pointer
            ) {
              validFields = false;
              break;
            }
          } else if (!concreteSatisfiesInterface(canonical, fieldInterface)) {
            validFields = false;
            break;
          }
          fields.set(fieldName, {
            concrete: canonical,
            ...(fieldInterface === undefined
              ? {}
              : { interface_: fieldInterface }),
            fields: value.fields ?? new Map(),
            aliasDepth: 0,
            propagators: [
              ...(value.propagators ?? []),
              {
                kind:
                  source.write === true
                    ? "go-method-receiver-constructor-field-write"
                    : "go-method-receiver-constructor-field",
                line: source.line,
                symbol: `${summary.resultStruct.name}.${fieldName}:${canonical.resolvedPackageName}.${canonical.typeName}`,
                path: summary.function_.file.path,
              },
            ],
          });
        }
        if (!validFields) return undefined;
        return {
          concrete: summary.result,
          fields,
          propagators: [
            {
              kind: "go-method-receiver-constructor-call",
              line,
              symbol: summary.function_.name,
              path: caller.file.path,
            },
            ...summary.aliases,
            {
              kind: "go-method-receiver-constructor-return",
              line: summary.returnLine,
              symbol: `${summary.result.pointer ? "*" : ""}${summary.function_.packageName}.${summary.result.typeName}`,
              path: summary.function_.file.path,
            },
          ],
        };
      }
    }
    const conversion =
      /^((?:[A-Za-z_]\w*\s*\.\s*)?[A-Za-z_]\w*)\s*\(\s*([\s\S]+)\s*\)$/u.exec(
        trimmed,
      );
    if (conversion === null) return undefined;
    const interfaceType = typeReference(conversion[1]!);
    if (interfaceType === undefined) return undefined;
    const interface_ = interfaceForType(caller, interfaceType, line);
    if (interface_ === undefined) return undefined;
    const inner = concreteExpression(
      caller,
      conversion[2]!,
      line,
      availableBindings,
      constructorDepth,
    );
    return inner === undefined
      ? undefined
      : {
          concrete: inner.concrete,
          interface_,
          ...(inner.fields === undefined ? {} : { fields: inner.fields }),
          ...(inner.propagators === undefined
            ? {}
            : { propagators: inner.propagators }),
        };
  };

  const typeMatchesDescriptor = (
    caller: GoFunction,
    reference: TypeReference,
    descriptor: Descriptor,
    line: number,
    interfaceDispatch: boolean,
  ): boolean => {
    if (
      descriptor.receiver === undefined ||
      descriptor.receiver.typeName !== reference.typeName ||
      (interfaceDispatch && descriptor.receiver.pointer && !reference.pointer)
    )
      return false;
    if (reference.resolvedDirectory !== undefined) {
      return (
        reference.resolvedDirectory ===
          posix.dirname(descriptor.function_.file.path) &&
        reference.resolvedPackageName === descriptor.function_.packageName
      );
    }
    if (reference.qualifier === undefined) {
      return (
        posix.dirname(descriptor.function_.file.path) ===
          posix.dirname(caller.file.path) &&
        descriptor.function_.packageName === caller.packageName
      );
    }
    if (descriptor.importPath === undefined) return false;
    return (
      goImportAlias(
        caller.file.lines,
        descriptor.importPath,
        descriptor.function_.packageName,
      ) === reference.qualifier &&
      packageAliasIsAvailable(caller, reference.qualifier, line)
    );
  };

  const receiverBindings = (
    caller: GoFunction,
    line: number,
    methodName: string,
  ): ReadonlyMap<string, ReceiverBinding> => {
    const bindings = new Map<string, ReceiverBinding>();
    const declaredInterfaces = new Map<string, InterfaceDescriptor>();
    const declaredConcreteTypes = new Map<string, TypeReference>();
    const resolvedMatches = (
      syntactic: TypeReference,
      resolved: TypeReference,
    ): boolean => {
      if (
        resolved.resolvedDirectory === undefined ||
        resolved.resolvedPackageName === undefined
      )
        return false;
      if (syntactic.qualifier === undefined) {
        return (
          posix.dirname(caller.file.path) === resolved.resolvedDirectory &&
          caller.packageName === resolved.resolvedPackageName
        );
      }
      return (
        resolved.resolvedImportPath !== undefined &&
        goImportAlias(
          caller.file.lines,
          resolved.resolvedImportPath,
          resolved.resolvedPackageName,
        ) === syntactic.qualifier
      );
    };
    const sameType = (left: TypeReference, right: TypeReference): boolean =>
      left.typeName === right.typeName &&
      left.pointer === right.pointer &&
      (left.qualifier === right.qualifier ||
        resolvedMatches(left, right) ||
        resolvedMatches(right, left));
    const typeSymbol = (reference: TypeReference): string =>
      `${
        reference.qualifier === undefined
          ? reference.resolvedPackageName === undefined
            ? ""
            : `${reference.resolvedPackageName}.`
          : `${reference.qualifier}.`
      }${reference.typeName}`;
    const addStaticBinding = (
      name: string,
      reference: TypeReference,
      bindingLine: number,
      kind: string,
    ): void => {
      const interface_ = interfaceForType(caller, reference, bindingLine);
      if (interface_ !== undefined) return;
      bindings.set(name, {
        concrete: reference,
        fields: new Map(),
        aliasDepth: 0,
        propagators: [
          {
            kind,
            line: bindingLine,
            symbol: `${name}:${typeSymbol(reference)}`,
            path: caller.file.path,
          },
        ],
      });
    };
    for (const parameter of caller.parameters) {
      const reference = typeReference(parameter.type);
      if (reference !== undefined)
        addStaticBinding(
          parameter.name,
          reference,
          caller.startLine,
          "go-method-receiver-parameter",
        );
    }
    const callerReceiver = receiverOf(caller);
    if (callerReceiver !== undefined && callerReceiver.name !== "") {
      addStaticBinding(
        callerReceiver.name,
        {
          typeName: callerReceiver.typeName,
          pointer: callerReceiver.pointer,
        },
        caller.startLine,
        "go-method-receiver-parameter",
      );
    }

    const typedVariable =
      /^\s*var\s+([A-Za-z_]\w*)\s+(\*?\s*(?:[A-Za-z_]\w*\s*\.\s*)?[A-Za-z_]\w*)(?:\s*=\s*([\s\S]+?))?\s*;?\s*$/u;
    for (
      let candidateLine = caller.bodyStartLine;
      candidateLine < line;
      candidateLine += 1
    ) {
      const structural = caller.structuralLines[candidateLine - 1] ?? "";
      const typed = typedVariable.exec(structural);
      const assignment = goAssignment(structural);
      const names =
        typed !== null
          ? [typed[1]!]
          : assignment?.names ??
            (/\b(?:const|type)\s+([A-Za-z_]\w*)\b/u.exec(structural)?.[1] ===
            undefined
              ? []
              : [/\b(?:const|type)\s+([A-Za-z_]\w*)\b/u.exec(structural)![1]!]);
      if (names.length === 0) continue;
      if (lineNestingDepth(caller, candidateLine) !== 1) {
        for (const name of names) bindings.delete(name);
        continue;
      }
      if (typed !== null) {
        const declared = typeReference(typed[2]!);
        const initializer = typed[3];
        if (declared === undefined) {
          bindings.delete(typed[1]!);
          declaredInterfaces.delete(typed[1]!);
          continue;
        }
        const interface_ = interfaceForType(caller, declared, candidateLine);
        if (interface_ === undefined) {
          declaredInterfaces.delete(typed[1]!);
          declaredConcreteTypes.set(typed[1]!, declared);
        } else {
          declaredInterfaces.set(typed[1]!, interface_);
          declaredConcreteTypes.delete(typed[1]!);
        }
        if (initializer === undefined) {
          if (interface_ !== undefined || declared.pointer) {
            bindings.delete(typed[1]!);
            continue;
          }
          addStaticBinding(
            typed[1]!,
            declared,
            candidateLine,
            "go-method-receiver-binding",
          );
          continue;
        }
        const concrete = concreteExpression(
          caller,
          initializer,
          candidateLine,
          bindings,
        );
        if (
          concrete === undefined ||
          (interface_ !== undefined && !interface_.methods.has(methodName))
        ) {
          bindings.delete(typed[1]!);
          continue;
        }
        if (
          interface_ === undefined &&
          !sameType(declared, concrete.concrete)
        ) {
          bindings.delete(typed[1]!);
          continue;
        }
        bindings.set(typed[1]!, {
          concrete: concrete.concrete,
          ...(interface_ === undefined ? {} : { interface_ }),
          fields: concrete.fields ?? new Map(),
          aliasDepth: 0,
          propagators: [
            ...(concrete.propagators ?? []),
            {
              kind:
                interface_ === undefined
                  ? "go-method-receiver-binding"
                  : "go-interface-receiver-binding",
              line: candidateLine,
              symbol: `${typed[1]}:${typeSymbol(concrete.concrete)}`,
              path: caller.file.path,
            },
          ],
        });
        continue;
      }
      if (assignment === undefined || assignment.names.length !== 1) {
        for (const name of names) bindings.delete(name);
        continue;
      }
      const name = assignment.names[0]!;
      const shortDeclaration = new RegExp(
        `^\\s*${escapeRegularExpression(name)}\\s*:=`,
        "u",
      ).test(structural);
      if (shortDeclaration) {
        declaredInterfaces.delete(name);
        declaredConcreteTypes.delete(name);
      }
      const alias = /^([A-Za-z_]\w*)$/u.exec(assignment.value.trim())?.[1];
      const previous = alias === undefined ? undefined : bindings.get(alias);
      if (
        previous !== undefined &&
        previous.aliasDepth < MAX_OBJECT_RECEIVER_ALIAS_DEPTH
      ) {
        const interface_ = declaredInterfaces.get(name) ?? previous.interface_;
        const concreteType = declaredConcreteTypes.get(name);
        if (interface_ !== undefined && !interface_.methods.has(methodName)) {
          bindings.delete(name);
          continue;
        }
        if (
          concreteType !== undefined &&
          (previous.interface_ !== undefined ||
            !sameType(concreteType, previous.concrete))
        ) {
          bindings.delete(name);
          continue;
        }
        bindings.set(name, {
          ...previous,
          ...(interface_ === undefined ? {} : { interface_ }),
          aliasDepth: previous.aliasDepth + 1,
          propagators: [
            ...previous.propagators,
            {
              kind: "go-method-receiver-alias",
              line: candidateLine,
              symbol: name,
              path: caller.file.path,
            },
          ],
        });
        if (interface_ === undefined) declaredInterfaces.delete(name);
        else declaredInterfaces.set(name, interface_);
        continue;
      }
      const concrete = concreteExpression(
        caller,
        assignment.value,
        candidateLine,
        bindings,
      );
      const interface_ = concrete?.interface_ ?? declaredInterfaces.get(name);
      const concreteType = declaredConcreteTypes.get(name);
      if (
        concrete === undefined ||
        (interface_ !== undefined && !interface_.methods.has(methodName)) ||
        (concreteType !== undefined &&
          (interface_ !== undefined ||
            !sameType(concreteType, concrete.concrete)))
      ) {
        bindings.delete(name);
        continue;
      }
      if (interface_ === undefined) declaredInterfaces.delete(name);
      else declaredInterfaces.set(name, interface_);
      bindings.set(name, {
        concrete: concrete.concrete,
        ...(interface_ === undefined ? {} : { interface_ }),
        fields: concrete.fields ?? new Map(),
        aliasDepth: 0,
        propagators: [
          ...(concrete.propagators ?? []),
          {
            kind:
              interface_ === undefined
                ? "go-method-receiver-binding"
                : "go-interface-receiver-binding",
            line: candidateLine,
            symbol: `${name}:${typeSymbol(concrete.concrete)}`,
            path: caller.file.path,
          },
        ],
      });
    }
    return bindings;
  };

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
          callableKey: descriptor.key,
          functionName: descriptor.function_.name,
          ...(descriptor.receiver === undefined
            ? {}
            : {
                receiverTypeName: descriptor.receiver.typeName,
                receiverPointer: descriptor.receiver.pointer,
              }),
          objectParameterIndex: parameter.index,
          objectParameterName: parameter.name,
          objectParameterLine: descriptor.function_.startLine,
          principalParameterIndexes,
          sink,
          receiverRequirements: [],
          delegations: [],
          wrapperDepth: 0,
          wrapperKeys: [parameterKey(descriptor, parameter.index)],
        });
      }
    }
  }

  const targetDescriptors = (
    caller: Descriptor,
    call: GoCall,
  ): ResolvedTarget[] => {
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
    const selector = resolved.name.split(".");
    if (selector.length >= 3) {
      const fieldNames = selector.slice(1, -1);
      const methodName = selector.at(-1)!;
      if (fieldNames.length > MAX_OBJECT_RECEIVER_FIELD_DEPTH) return [];
      const binding = receiverBindings(
        caller.function_,
        call.line,
        methodName,
      ).get(selector[0]!);
      if (binding === undefined || binding.interface_ !== undefined) return [];
      let reference = binding.concrete;
      let contextFile = caller.function_.file;
      let contextPackageName = caller.function_.packageName;
      let contextFunction: GoFunction | undefined = caller.function_;
      let contextLine: number | undefined = resolved.targetLine;
      const propagators = [...binding.propagators];
      const receiverRequirements: ObjectReceiverRequirement[] = [];
      const receiverFieldPath: string[] = [];
      for (const [fieldIndex, fieldName] of fieldNames.entries()) {
        const matchingStructs = structs.filter(
          (descriptor) =>
            descriptor.name === reference.typeName &&
            typeMatchesIdentity(
              reference,
              contextFile,
              contextPackageName,
              descriptor.directory,
              descriptor.packageName,
              descriptor.importPath,
              contextFunction,
              contextLine,
            ),
        );
        if (matchingStructs.length !== 1) return [];
        const owner = matchingStructs[0]!;
        const field = owner.fields.get(fieldName);
        if (
          field === undefined ||
          (owner.packageName !== caller.function_.packageName &&
            !/^[A-Z]/u.test(fieldName))
        )
          return [];
        receiverFieldPath.push(fieldName);
        propagators.push({
          kind: "go-method-receiver-field",
          line: field.line,
          symbol: `${owner.name}.${field.name}:${
            field.type.qualifier === undefined ? "" : `${field.type.qualifier}.`
          }${field.type.typeName}`,
          path: field.file.path,
        });
        const fieldInterface = interfaceForReference(
          field.type,
          field.file,
          field.packageName,
        );
        if (fieldInterface !== undefined) {
          if (
            fieldIndex !== fieldNames.length - 1 ||
            !fieldInterface.methods.has(methodName)
          )
            return [];
          return [...descriptors.values()]
            .filter(
              (target) =>
                target.receiver !== undefined &&
                target.function_.name === methodName,
            )
            .map((descriptor) => ({
              descriptor,
              receiverPropagators: propagators,
              receiverRequirements: [
                ...receiverRequirements,
                {
                  fieldPath: [...receiverFieldPath],
                  directory: posix.dirname(descriptor.function_.file.path),
                  packageName: descriptor.function_.packageName,
                  typeName: descriptor.receiver!.typeName,
                  pointer: descriptor.receiver!.pointer ? "pointer" : "either",
                },
              ],
              receiverFieldPath: [...receiverFieldPath],
              receiverBinding: binding,
            }));
        }
        const canonical = canonicalConcreteReference(
          field.type,
          field.file,
          field.packageName,
        );
        if (canonical === undefined) return [];
        if (field.type.pointer)
          receiverRequirements.push({
            fieldPath: [...receiverFieldPath],
            directory: canonical.resolvedDirectory!,
            packageName: canonical.resolvedPackageName!,
            typeName: canonical.typeName,
            pointer: "pointer",
          });
        reference = canonical;
        contextFile = field.file;
        contextPackageName = field.packageName;
        contextFunction = undefined;
        contextLine = undefined;
      }
      return [...descriptors.values()]
        .filter(
          (target) =>
            target.receiver !== undefined &&
            target.function_.name === methodName &&
            target.receiver.typeName === reference.typeName &&
            typeMatchesIdentity(
              reference,
              contextFile,
              contextPackageName,
              posix.dirname(target.function_.file.path),
              target.function_.packageName,
              target.importPath,
              contextFunction,
              contextLine,
            ),
        )
        .map((descriptor) => ({
          descriptor,
          receiverPropagators: propagators,
          receiverRequirements,
          receiverFieldPath,
          receiverBinding: binding,
        }));
    }
    const plain = /^([A-Za-z_]\w*)$/u.exec(resolved.name);
    if (plain !== null) {
      const targets = [...descriptors.values()].filter(
        (target) =>
          target.receiver === undefined &&
          target.function_.name === plain[1] &&
          posix.dirname(target.function_.file.path) ===
            posix.dirname(caller.function_.file.path) &&
          target.function_.packageName === caller.function_.packageName,
      );
      return targets.map((descriptor) => ({
        descriptor,
        receiverPropagators: [],
        receiverRequirements: [],
        receiverFieldPath: [],
      }));
    }
    const qualified = /^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$/u.exec(resolved.name);
    if (qualified === null) return [];
    const targets: ResolvedTarget[] = [];
    if (
      /^[A-Z]/u.test(qualified[2]!) &&
      packageAliasIsAvailable(
        caller.function_,
        qualified[1]!,
        resolved.targetLine,
      )
    ) {
      for (const target of descriptors.values()) {
        if (
          target.receiver !== undefined ||
          target.importPath === undefined ||
          target.function_.name !== qualified[2]
        )
          continue;
        const alias = goImportAlias(
          caller.function_.file.lines,
          target.importPath,
          target.function_.packageName,
        );
        if (alias === qualified[1])
          targets.push({
            descriptor: target,
            receiverPropagators: [],
            receiverRequirements: [],
            receiverFieldPath: [],
          });
      }
    }
    const binding = receiverBindings(
      caller.function_,
      call.line,
      qualified[2]!,
    ).get(qualified[1]!);
    if (
      binding !== undefined &&
      (binding.interface_ === undefined ||
        binding.interface_.methods.has(qualified[2]!))
    ) {
      for (const target of descriptors.values()) {
        if (
          target.function_.name !== qualified[2] ||
          !typeMatchesDescriptor(
            caller.function_,
            binding.concrete,
            target,
            resolved.targetLine,
            binding.interface_ !== undefined,
          )
        )
          continue;
        targets.push({
          descriptor: target,
          receiverPropagators: binding.propagators,
          receiverRequirements: [],
          receiverFieldPath: [],
          receiverBinding: binding,
        });
      }
    }
    const unique = new Map<string, ResolvedTarget>();
    for (const target of targets) {
      if (unique.has(target.descriptor.key)) {
        unique.delete(target.descriptor.key);
        continue;
      }
      unique.set(target.descriptor.key, target);
    }
    return [...unique.values()];
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
      if (
        targets.length === 0 ||
        (targets.length > 1 &&
          targets.some((target) => target.receiverRequirements.length === 0))
      )
        continue;
      for (const resolvedTarget of targets) {
        const target = resolvedTarget.descriptor;
        for (const sourceParameter of source.parameters) {
          const sourceKey = parameterKey(source, sourceParameter.index);
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
              targetKey: parameterKey(target, targetParameter.index),
              target,
              call,
              receiverPropagators: resolvedTarget.receiverPropagators,
              receiverRequirements: resolvedTarget.receiverRequirements,
              receiverFieldPath: resolvedTarget.receiverFieldPath,
              objectPropagators: reaching[0]!.propagators,
            });
          }
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
      receiverRequirements: summary.receiverRequirements,
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
            callableKey: edge.source.key,
            functionName: edge.source.function_.name,
            ...(edge.source.receiver === undefined
              ? {}
              : {
                  receiverTypeName: edge.source.receiver.typeName,
                  receiverPointer: edge.source.receiver.pointer,
                }),
            objectParameterIndex: edge.sourceParameter.index,
            objectParameterName: edge.sourceParameter.name,
            objectParameterLine: edge.source.function_.startLine,
            principalParameterIndexes: [...principalParameterIndexes].sort(
              (left, right) => left - right,
            ),
            sink: child.sink,
            receiverRequirements: [
              ...edge.receiverRequirements,
              ...child.receiverRequirements.map((requirement) => ({
                ...requirement,
                fieldPath: [
                  ...edge.receiverFieldPath,
                  ...requirement.fieldPath,
                ],
              })),
            ],
            delegations: [
              ...edge.receiverPropagators,
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

  const summaries = overflow
    ? direct
    : [...groups.values()]
        .flatMap((group) => {
          const candidates = [...group.values()];
          return candidates.length === 1 ||
            candidates.every(
              (candidate) => candidate.receiverRequirements.length > 0,
            )
            ? candidates
            : [];
        })
        .sort(
          (left, right) =>
            left.file.path.localeCompare(right.file.path) ||
            left.functionName.localeCompare(right.functionName) ||
            left.objectParameterIndex - right.objectParameterIndex ||
            left.sinkFile.path.localeCompare(right.sinkFile.path) ||
            left.sink.line - right.sink.line,
        );
  const satisfyReceiverRequirements = (
    binding: ReceiverBinding | undefined,
    requirements: readonly ObjectReceiverRequirement[],
  ): EvidencePropagator[] | undefined => {
    if (requirements.length === 0) return [];
    if (binding === undefined) return undefined;
    const propagators: EvidencePropagator[] = [];
    for (const requirement of requirements) {
      let current = binding;
      for (const fieldName of requirement.fieldPath) {
        const field = current.fields.get(fieldName);
        if (field === undefined) return undefined;
        current = field;
      }
      if (
        current.concrete.resolvedDirectory !== requirement.directory ||
        current.concrete.resolvedPackageName !== requirement.packageName ||
        current.concrete.typeName !== requirement.typeName ||
        (requirement.pointer === "pointer" && !current.concrete.pointer) ||
        (requirement.pointer === "value" && current.concrete.pointer)
      )
        return undefined;
      propagators.push(...current.propagators);
    }
    const unique = new Map<string, EvidencePropagator>();
    for (const propagator of propagators)
      unique.set(
        `${propagator.kind}\0${propagator.path}\0${propagator.line}\0${propagator.symbol}`,
        propagator,
      );
    return [...unique.values()];
  };
  const matches = (caller: GoFunction, call: GoCall): ObjectWrapperMatch[] => {
    const callerReceiver = receiverOf(caller);
    const callerDescriptor: Descriptor = {
      key: callableKey(caller, callerReceiver),
      function_: caller,
      parameters: [],
      ...(localPackageImportPath(caller, modules) === undefined
        ? {}
        : { importPath: localPackageImportPath(caller, modules) }),
      ...(callerReceiver === undefined ? {} : { receiver: callerReceiver }),
    };
    const targets = targetDescriptors(callerDescriptor, call);
    if (
      targets.length > 1 &&
      targets.some((target) => target.receiverRequirements.length === 0)
    )
      return [];
    const matched: ObjectWrapperMatch[] = [];
    const emitted = new Set<string>();
    for (const target of targets) {
      for (const summary of summaries) {
        if (summary.callableKey !== target.descriptor.key) continue;
        const requirementPropagators = satisfyReceiverRequirements(
          target.receiverBinding,
          summary.receiverRequirements,
        );
        if (requirementPropagators === undefined) continue;
        const identity = candidateIdentity(summary);
        if (emitted.has(identity)) continue;
        emitted.add(identity);
        matched.push({
          summary,
          receiverPropagators: [
            ...target.receiverPropagators,
            ...requirementPropagators,
          ],
        });
      }
    }
    return matched;
  };
  return { summaries, matches };
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

  const wrapperGraph = objectWrapperSummaries(
    files,
    functions,
    finalizers,
    creators,
  );

  for (const caller of functions) {
    if (requestParameters(caller).length === 0) continue;
    const calls = goCalls(caller);
    for (const call of calls) {
      for (const match of wrapperGraph.matches(caller, call)) {
        const summary = match.summary;
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
              ...match.receiverPropagators,
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
