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
const MAX_TRANSACTION_FINALIZER_HELPER_DEPTH = 32;
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
  packageName: string;
  functionName: string;
  objectParameterIndex: number;
  objectParameterName: string;
  principalParameterIndexes: number[];
  sink: ObjectSink;
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

interface LocalGoModule {
  root: string;
  importPath: string;
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

function transactionFinalizerCallMatches(
  function_: GoFunction,
  callName: string,
  line: number,
  summary: TransactionFinalizerSummary,
): boolean {
  if (
    summary.functionName === callName &&
    summary.packageName === function_.packageName &&
    posix.dirname(summary.file.path) === posix.dirname(function_.file.path)
  )
    return true;
  if (
    summary.packageImportPath === undefined ||
    !/^[A-Z]/u.test(summary.functionName)
  )
    return false;
  const qualified = /^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$/u.exec(callName);
  if (qualified?.[2] !== summary.functionName) return false;
  const alias = goImportAlias(
    function_.file.lines,
    summary.packageImportPath,
    summary.packageName,
  );
  return (
    alias !== undefined &&
    alias === qualified[1] &&
    packageAliasIsAvailable(function_, alias, line)
  );
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
): ObjectSink[] {
  const alias = sqlAlias(function_);
  if (alias === undefined) return [];
  const requests = requestParameters(function_);
  const receivers = typedReceivers(function_, alias);
  const typedTransactions = typedTransactionReceivers(function_, alias);
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
    transactions.set(receiver, { active: true, pending: [] });
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
      const matchingFinalizers = finalizers.filter((summary) =>
        transactionFinalizerCallMatches(function_, call.name, line, summary),
      );
      if (matchingFinalizers.length === 1) {
        const summary = matchingFinalizers[0]!;
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
      const receiverCall =
        /^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.([A-Za-z_]\w*)$/u.exec(call.name);
      if (receiverCall === null) continue;
      const receiver = receiverCall[1]!;
      const method = receiverCall[2]!;
      if (
        result !== undefined &&
        receiverIsTyped(receiver) &&
        /^(?:Begin|BeginTx)$/u.test(method)
      ) {
        inferredReceivers.add(result);
        transactions.set(result, { active: true, pending: [] });
        continue;
      }
      if (
        result !== undefined &&
        receiverIsTyped(receiver) &&
        method === "Conn"
      ) {
        inferredReceivers.add(result);
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
    if (depth >= MAX_TRANSACTION_FINALIZER_HELPER_DEPTH || visiting.has(key))
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
      const plainCall = /^([A-Za-z_]\w*)$/u.exec(call.name);
      const qualifiedCall = /^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$/u.exec(call.name);
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
          call.line,
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

  for (const function_ of functions) {
    if (requestParameters(function_).length === 0) continue;
    for (const sink of analyzeFunction(
      function_,
      new Map(),
      new Map(),
      finalizers,
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

  const summaries: WrapperSummary[] = [];
  for (const function_ of functions) {
    if (function_.receiver !== undefined || sqlAlias(function_) === undefined)
      continue;
    function_.parameters.forEach((parameter, objectParameterIndex) => {
      if (parameter.type.replace(/\s+/gu, "") !== "string") return;
      const objectTaint: GoTaint = {
        kind: "go-string-parameter",
        line: function_.startLine,
        propagators: [],
      };
      const allPrincipalParameters = new Map<string, GoTaint>();
      function_.parameters.forEach((candidate, index) => {
        if (
          index !== objectParameterIndex &&
          candidate.type.replace(/\s+/gu, "") === "string"
        ) {
          allPrincipalParameters.set(candidate.name, {
            kind: "go-principal-parameter",
            line: function_.startLine,
            propagators: [],
          });
        }
      });
      for (const sink of analyzeFunction(
        function_,
        new Map([[parameter.name, objectTaint]]),
        allPrincipalParameters,
        finalizers,
      )) {
        const principalParameterIndexes: number[] = [];
        if (
          sink.controls.some(
            (control) => control.kind === "principal-bound-object-query",
          )
        ) {
          function_.parameters.forEach((candidate, index) => {
            if (
              index === objectParameterIndex ||
              !allPrincipalParameters.has(candidate.name)
            )
              return;
            const isolated = analyzeFunction(
              function_,
              new Map([[parameter.name, objectTaint]]),
              new Map([
                [
                  candidate.name,
                  {
                    kind: "go-principal-parameter",
                    line: function_.startLine,
                    propagators: [],
                  },
                ],
              ]),
              finalizers,
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
            ) {
              principalParameterIndexes.push(index);
            }
          });
        }
        summaries.push({
          file: function_.file,
          packageName: function_.packageName,
          functionName: function_.name,
          objectParameterIndex,
          objectParameterName: parameter.name,
          principalParameterIndexes,
          sink,
        });
      }
    });
  }

  for (const caller of functions) {
    if (requestParameters(caller).length === 0) continue;
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
        const identity = `${caller.file.path}:${call.line}:${summary.file.path}:${sink.line}:${sink.kind}`;
        if (emitted.has(identity)) continue;
        emitted.add(identity);
        records.push(
          record(
            caller.file,
            summary.file,
            caller.file.path === summary.file.path
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
                line: summary.sink.source.line,
                symbol: summary.objectParameterName,
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
