const CONTEXT_LINES_BEFORE = 5;
const CONTEXT_LINES_AFTER = 7;
const MAX_JAVA_TOKENS = 131_072;
const MAX_JAVA_NESTING = 128;
const MAX_RECORDS = 64;
const MAX_EXCERPT_LINE_CHARACTERS = 2_048;

type JavaTokenKind = "identifier" | "number" | "string" | "symbol";

interface JavaToken {
  kind: JavaTokenKind;
  value: string;
  line: number;
}

interface JavaSource {
  kind: "spring-bound-parameter";
  line: number;
  symbol: string;
}

interface JavaPropagator {
  kind:
    | "java-caller-command-list-binding"
    | "java-command-list-mutation"
    | "java-local-assignment"
    | "java-process-command-replacement"
    | "java-process-delegated-launcher"
    | "java-process-execution"
    | "java-runtime-exec"
    | "java-string-concatenation";
  line: number;
  symbol?: string;
}

interface JavaTaint {
  source: JavaSource;
  propagators: JavaPropagator[];
  controls: Array<{ kind: string; line: number }>;
}

interface ProcessArgument {
  line: number;
  literal?: string;
  mutationLine?: number;
  taint?: JavaTaint;
}

type CommandListCapability = "fixed-size" | "mutable" | "unmodifiable";

interface CommandListState {
  arguments: ProcessArgument[];
  capability: CommandListCapability;
  origin: "builder-owned" | "caller-owned";
}

interface ProcessState {
  command: CommandListState;
  commandSetKind: "constructor" | "replacement";
  commandSetLine: number;
  commandSourceKind: "builder-owned" | "caller-list";
}

interface CommandListMutation {
  argument?: ProcessArgument;
  arguments?: ProcessArgument[];
  index?: number;
  kind:
    | "append"
    | "append-many"
    | "clear"
    | "insert"
    | "insert-many"
    | "remove"
    | "remove-first"
    | "remove-last"
    | "set";
  line: number;
  noOpOnEmpty?: boolean;
}

interface UnsupportedCommandListMutation {
  kind: "unsupported";
  line: number;
}

type CommandListMutationResult =
  | CommandListMutation
  | UnsupportedCommandListMutation;

interface JavaCollectionFactories {
  arrayList: boolean;
  arraysAsList: boolean;
  collections: boolean;
  linkedList: boolean;
  listOf: boolean;
}

type InlineListFactory =
  | {
      arguments: JavaToken[][];
      capability: "fixed-size" | "unmodifiable";
      kind: "owned";
    }
  | { kind: "foreign" };

type MutableListConstructor =
  | {
      arguments: JavaToken[][];
      capacityArgument: boolean;
      kind: "owned";
    }
  | { kind: "foreign" };

interface BoundCommandListMutation {
  command: CommandListState;
  mutation: CommandListMutationResult;
}

interface ProcessCommandResolution {
  command: CommandListState;
  sourceKind: "builder-owned" | "caller-list";
}

type JavaProcessSinkKind =
  | "java-process-executable-selection"
  | "java-process-interpreter-command"
  | "java-process-split-command"
  | "java-process-shell-command";

interface JavaRisk {
  kind: JavaProcessSinkKind;
  taint: JavaTaint;
  argumentIndex: number;
  delegated?: string;
}

export interface JavaSpringCommandInjectionRecord {
  path: string;
  line: number;
  categories: ["spring-java-command-injection"];
  priority: number;
  startLine: number;
  endLine: number;
  excerpt: string;
  sourceExcerpt: string;
  frameworkModel: {
    schemaVersion: "1.2";
    id: "spring-java-command-injection";
    language: "java";
    scope: "same-file";
    source: JavaSource & { path: string };
    sink: {
      kind: JavaProcessSinkKind;
      path: string;
      line: number;
      symbol: string;
      cweIds: readonly ["CWE-78", "CWE-88"];
    };
    propagators: Array<JavaPropagator & { path: string }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

const SOURCE_ANNOTATIONS = new Set([
  "CookieValue",
  "MatrixVariable",
  "PathVariable",
  "RequestBody",
  "RequestHeader",
  "RequestParam",
]);
const ROUTE_ANNOTATIONS = new Set([
  "DeleteMapping",
  "GetMapping",
  "PatchMapping",
  "PostMapping",
  "PutMapping",
  "RequestMapping",
]);
const POSIX_SHELLS = new Set([
  "ash",
  "bash",
  "csh",
  "dash",
  "fish",
  "ksh",
  "mksh",
  "sh",
  "tcsh",
  "yash",
  "zsh",
]);
const POWERSHELLS = new Set(["powershell", "powershell.exe", "pwsh"]);
const INTERPRETER_FLAGS = new Map<string, ReadonlySet<string>>([
  ["node", new Set(["--eval", "--print", "-e", "-p"])],
  ["nodejs", new Set(["--eval", "--print", "-e", "-p"])],
  ["perl", new Set(["-e"])],
  ["php", new Set(["-r"])],
  ["python", new Set(["-c"])],
  ["python3", new Set(["-c"])],
  ["ruby", new Set(["-e"])],
]);

function javaTokens(source: string): JavaToken[] | undefined {
  const tokens: JavaToken[] = [];
  const delimiters: string[] = [];
  let index = 0;
  let line = 1;
  const add = (
    kind: JavaTokenKind,
    value: string,
    tokenLine: number,
  ): boolean => {
    tokens.push({ kind, value, line: tokenLine });
    return tokens.length <= MAX_JAVA_TOKENS;
  };
  while (index < source.length) {
    const character = source[index] ?? "";
    if (/\s/u.test(character)) {
      if (character === "\n") line += 1;
      index += 1;
      continue;
    }
    if (source.startsWith("//", index)) {
      const end = source.indexOf("\n", index + 2);
      index = end < 0 ? source.length : end;
      continue;
    }
    if (source.startsWith("/*", index)) {
      const end = source.indexOf("*/", index + 2);
      const value = source.slice(index, end < 0 ? source.length : end + 2);
      line += (value.match(/\n/gu) ?? []).length;
      index += value.length;
      continue;
    }
    if (character === '"' || character === "'") {
      const quote = character;
      const tokenLine = line;
      let value = "";
      index += 1;
      let closed = false;
      while (index < source.length) {
        const next = source[index] ?? "";
        if (next === "\\") {
          const escaped = source[index + 1] ?? "";
          value += escaped === "n" ? "\n" : escaped === "r" ? "\r" : escaped;
          index += Math.min(2, source.length - index);
          continue;
        }
        if (next === quote) {
          index += 1;
          closed = true;
          break;
        }
        if (next === "\n") line += 1;
        value += next;
        index += 1;
      }
      if (!closed || !add("string", value, tokenLine)) return undefined;
      continue;
    }
    if (/[A-Za-z_$]/u.test(character)) {
      const tokenLine = line;
      let value = character;
      index += 1;
      while (
        index < source.length &&
        /[A-Za-z0-9_$]/u.test(source[index] ?? "")
      ) {
        value += source[index] ?? "";
        index += 1;
      }
      if (!add("identifier", value, tokenLine)) return undefined;
      continue;
    }
    if (/[0-9]/u.test(character)) {
      const tokenLine = line;
      let value = character;
      index += 1;
      while (
        index < source.length &&
        /[A-Za-z0-9_.]/u.test(source[index] ?? "")
      ) {
        value += source[index] ?? "";
        index += 1;
      }
      if (!add("number", value, tokenLine)) return undefined;
      continue;
    }
    if ("([{".includes(character)) {
      delimiters.push(character);
      if (delimiters.length > MAX_JAVA_NESTING) return undefined;
    } else if (")]}".includes(character)) {
      const expected = new Map([
        [")", "("],
        ["]", "["],
        ["}", "{"],
      ]).get(character);
      if (delimiters.at(-1) === expected) delimiters.pop();
    }
    if (!add("symbol", character, line)) return undefined;
    index += 1;
  }
  return tokens;
}

function matchingForward(
  tokens: readonly JavaToken[],
  start: number,
  open: string,
  close: string,
): number | undefined {
  let depth = 0;
  for (let index = start; index < tokens.length; index += 1) {
    const value = tokens[index]?.value;
    if (value === open) depth += 1;
    if (value === close) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return undefined;
}

function matchingBackward(
  tokens: readonly JavaToken[],
  start: number,
  open: string,
  close: string,
): number | undefined {
  let depth = 0;
  for (let index = start; index >= 0; index -= 1) {
    const value = tokens[index]?.value;
    if (value === close) depth += 1;
    if (value === open) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return undefined;
}

function splitArguments(tokens: readonly JavaToken[]): JavaToken[][] {
  const arguments_: JavaToken[][] = [];
  let current: JavaToken[] = [];
  let round = 0;
  let square = 0;
  let curly = 0;
  let angle = 0;
  for (const token of tokens) {
    if (token.value === "(") round += 1;
    else if (token.value === ")") round -= 1;
    else if (token.value === "[") square += 1;
    else if (token.value === "]") square -= 1;
    else if (token.value === "{") curly += 1;
    else if (token.value === "}") curly -= 1;
    else if (token.value === "<") angle += 1;
    else if (token.value === ">") angle = Math.max(0, angle - 1);
    if (
      token.value === "," &&
      round === 0 &&
      square === 0 &&
      curly === 0 &&
      angle === 0
    ) {
      arguments_.push(current);
      current = [];
    } else {
      current.push(token);
    }
  }
  if (current.length > 0) arguments_.push(current);
  return arguments_;
}

function statementSlices(tokens: readonly JavaToken[]): JavaToken[][] {
  const statements: JavaToken[][] = [];
  let start = 0;
  let round = 0;
  let square = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    const value = tokens[index]?.value;
    if (value === "(") round += 1;
    else if (value === ")") round -= 1;
    else if (value === "[") square += 1;
    else if (value === "]") square -= 1;
    if (value === ";" && round === 0 && square === 0) {
      statements.push(tokens.slice(start, index));
      start = index + 1;
    }
  }
  if (start < tokens.length) statements.push(tokens.slice(start));
  return statements.filter((statement) => statement.length > 0);
}

function annotationNames(tokens: readonly JavaToken[]): Set<string> {
  const names = new Set<string>();
  for (let index = 0; index < tokens.length - 1; index += 1) {
    if (tokens[index]?.value !== "@") continue;
    let cursor = index + 1;
    let name = tokens[cursor]?.value ?? "";
    while (
      tokens[cursor + 1]?.value === "." &&
      tokens[cursor + 2]?.kind === "identifier"
    ) {
      cursor += 2;
      name = tokens[cursor]?.value ?? name;
    }
    if (name !== "") names.add(name);
  }
  return names;
}

interface JavaMethodScope {
  body: JavaToken[];
  sources: JavaSource[];
}

function javaMethodScopes(
  tokens: readonly JavaToken[],
  importedSourceAnnotations: ReadonlySet<string>,
  importedRouteAnnotations: ReadonlySet<string>,
): JavaMethodScope[] {
  const scopes: JavaMethodScope[] = [];
  for (let brace = 0; brace < tokens.length; brace += 1) {
    if (tokens[brace]?.value !== "{") continue;
    let closeParen = brace - 1;
    while (closeParen >= 0 && tokens[closeParen]?.value !== ")") {
      if (new Set([";", "}", "{"]).has(tokens[closeParen]?.value ?? "")) break;
      closeParen -= 1;
    }
    if (tokens[closeParen]?.value !== ")") continue;
    const openParen = matchingBackward(tokens, closeParen, "(", ")");
    if (openParen === undefined) continue;
    const methodName = tokens[openParen - 1];
    if (
      methodName?.kind !== "identifier" ||
      new Set(["catch", "for", "if", "switch", "while"]).has(methodName.value)
    )
      continue;
    let headerStart = openParen - 2;
    while (
      headerStart >= 0 &&
      !new Set([";", "}", "{"]).has(tokens[headerStart]?.value ?? "")
    )
      headerStart -= 1;
    const header = tokens.slice(headerStart + 1, brace);
    if (
      ![...annotationNames(header)].some((name) =>
        importedRouteAnnotations.has(name),
      )
    )
      continue;
    const closeBrace = matchingForward(tokens, brace, "{", "}");
    if (closeBrace === undefined) continue;
    const parameters = splitArguments(tokens.slice(openParen + 1, closeParen));
    const sources: JavaSource[] = [];
    for (const parameter of parameters) {
      const sourceAnnotation = [...annotationNames(parameter)].find((name) =>
        importedSourceAnnotations.has(name),
      );
      if (sourceAnnotation === undefined) continue;
      const identifiers = parameter.filter(
        (token) => token.kind === "identifier",
      );
      const name = identifiers.at(-1);
      if (name === undefined || SOURCE_ANNOTATIONS.has(name.value)) continue;
      sources.push({
        kind: "spring-bound-parameter",
        line: name.line,
        symbol: `${sourceAnnotation}:${name.value}`,
      });
    }
    if (sources.length > 0)
      scopes.push({ body: tokens.slice(brace + 1, closeBrace), sources });
    brace = closeBrace;
  }
  return scopes;
}

function cloneTaint(taint: JavaTaint): JavaTaint {
  return {
    source: taint.source,
    propagators: [...taint.propagators],
    controls: [...taint.controls],
  };
}

function expressionTaint(
  tokens: readonly JavaToken[],
  taints: ReadonlyMap<string, JavaTaint>,
): JavaTaint | undefined {
  for (const token of tokens) {
    if (token.kind !== "identifier") continue;
    const taint = taints.get(token.value);
    if (taint === undefined) continue;
    const result = cloneTaint(taint);
    if (tokens.some((candidate) => candidate.value === "+")) {
      result.propagators.push({
        kind: "java-string-concatenation",
        line: token.line,
      });
    }
    if (tokens.some((candidate) => candidate.value === "matches")) {
      result.controls.push({
        kind: "candidate-regex-validation",
        line: token.line,
      });
    }
    if (tokens.some((candidate) => candidate.value === "contains")) {
      result.controls.push({
        kind: "candidate-membership-validation",
        line: token.line,
      });
    }
    return result;
  }
  return undefined;
}

function literalValue(tokens: readonly JavaToken[]): string | undefined {
  const meaningful = tokens.filter(
    (token) => token.value !== "(" && token.value !== ")",
  );
  return meaningful.length === 1 && meaningful[0]?.kind === "string"
    ? meaningful[0].value
    : undefined;
}

function processArguments(
  arguments_: readonly (readonly JavaToken[])[],
  taints: ReadonlyMap<string, JavaTaint>,
): ProcessArgument[] {
  return arguments_.map((argument) => ({
    line: argument[0]?.line ?? 1,
    literal: literalValue(argument),
    taint: expressionTaint(argument, taints),
  }));
}

function inlineListFactoryArguments(
  tokens: readonly JavaToken[],
  factories: JavaCollectionFactories,
): InlineListFactory | undefined {
  const compact = tokens.map((token) => token.value).join("");
  const qualifiedList = compact.startsWith("java.util.List.of(");
  const qualifiedArrays = compact.startsWith("java.util.Arrays.asList(");
  const unqualifiedList = compact.startsWith("List.of(");
  const unqualifiedArrays = compact.startsWith("Arrays.asList(");
  if (
    !qualifiedList &&
    !qualifiedArrays &&
    !unqualifiedList &&
    !unqualifiedArrays
  )
    return undefined;
  if (
    (unqualifiedList && !factories.listOf) ||
    (unqualifiedArrays && !factories.arraysAsList)
  )
    return { kind: "foreign" };
  const method = tokens.findIndex(
    (token) => token.value === "of" || token.value === "asList",
  );
  if (method < 0 || tokens[method + 1]?.value !== "(") return undefined;
  const call = callArgumentsAt(tokens, method + 1);
  if (call === undefined || call.closeParen !== tokens.length - 1)
    return undefined;
  return {
    arguments: call.arguments,
    capability:
      qualifiedArrays || unqualifiedArrays ? "fixed-size" : "unmodifiable",
    kind: "owned",
  };
}

function commandListState(
  arguments_: ProcessArgument[],
  capability: CommandListCapability,
  origin: CommandListState["origin"],
): CommandListState {
  return { arguments: arguments_, capability, origin };
}

function cloneProcessArgument(argument: ProcessArgument): ProcessArgument {
  return {
    ...argument,
    taint:
      argument.taint === undefined ? undefined : cloneTaint(argument.taint),
  };
}

function processCommandState(
  arguments_: readonly (readonly JavaToken[])[],
  taints: ReadonlyMap<string, JavaTaint>,
  factories: JavaCollectionFactories,
  commandLists?: ReadonlyMap<string, CommandListState>,
): ProcessCommandResolution {
  if (arguments_.length === 1 && arguments_[0] !== undefined) {
    const only = arguments_[0];
    if (only.length === 1 && only[0]?.kind === "identifier") {
      const referenced = commandLists?.get(only[0].value);
      if (referenced !== undefined)
        return { command: referenced, sourceKind: "caller-list" };
    }
    const arrayArguments = inlineStringArrayArguments(arguments_[0]);
    if (arrayArguments !== undefined)
      return {
        command: commandListState(
          processArguments(arrayArguments, taints),
          "mutable",
          "builder-owned",
        ),
        sourceKind: "builder-owned",
      };
    const listFactory = inlineListFactoryArguments(arguments_[0], factories);
    if (listFactory?.kind === "owned")
      return {
        command: commandListState(
          processArguments(listFactory.arguments, taints),
          listFactory.capability,
          "caller-owned",
        ),
        sourceKind: "caller-list",
      };
    if (listFactory?.kind === "foreign")
      return {
        command: commandListState([], "unmodifiable", "caller-owned"),
        sourceKind: "caller-list",
      };
  }
  return {
    command: commandListState(
      processArguments(arguments_, taints),
      "mutable",
      "builder-owned",
    ),
    sourceKind: "builder-owned",
  };
}

function callArgumentsAt(
  tokens: readonly JavaToken[],
  openParen: number,
): { arguments: JavaToken[][]; closeParen: number } | undefined {
  const closeParen = matchingForward(tokens, openParen, "(", ")");
  if (closeParen === undefined) return undefined;
  return {
    arguments: splitArguments(tokens.slice(openParen + 1, closeParen)),
    closeParen,
  };
}

function simpleNameBefore(
  tokens: readonly JavaToken[],
  index: number,
): string | undefined {
  const token = tokens[index];
  return token?.kind === "identifier" ? token.value : undefined;
}

function assignmentTarget(tokens: readonly JavaToken[]): string | undefined {
  const equals = tokens.findIndex((token) => token.value === "=");
  if (equals < 1 || tokens[equals + 1]?.value === "=") return undefined;
  return simpleNameBefore(tokens, equals - 1);
}

function assignmentExpression(
  tokens: readonly JavaToken[],
): JavaToken[] | undefined {
  const equals = tokens.findIndex((token) => token.value === "=");
  return equals >= 1 && tokens[equals + 1] !== undefined
    ? [...tokens.slice(equals + 1)]
    : undefined;
}

function singleIdentifier(tokens: readonly JavaToken[]): string | undefined {
  return tokens.length === 1 && tokens[0]?.kind === "identifier"
    ? tokens[0].value
    : undefined;
}

function commandListExpression(
  tokens: readonly JavaToken[],
  builders: ReadonlyMap<string, ProcessState>,
  commandLists: ReadonlyMap<string, CommandListState>,
): CommandListState | undefined {
  const alias = singleIdentifier(tokens);
  if (alias !== undefined) return commandLists.get(alias);
  if (
    tokens.length === 5 &&
    tokens[0]?.kind === "identifier" &&
    tokens[1]?.value === "." &&
    tokens[2]?.value === "command" &&
    tokens[3]?.value === "(" &&
    tokens[4]?.value === ")"
  ) {
    return builders.get(tokens[0].value)?.command;
  }
  return undefined;
}

function mutableListConstructorArguments(
  tokens: readonly JavaToken[],
  factories: JavaCollectionFactories,
): MutableListConstructor | undefined {
  if (tokens[0]?.value !== "new") return undefined;
  let cursor: number;
  let capacityArgument: boolean;
  if (
    tokens[1]?.value === "java" &&
    tokens[2]?.value === "." &&
    tokens[3]?.value === "util" &&
    tokens[4]?.value === "." &&
    (tokens[5]?.value === "ArrayList" || tokens[5]?.value === "LinkedList")
  ) {
    capacityArgument = tokens[5]?.value === "ArrayList";
    cursor = 6;
  } else if (
    tokens[1]?.value === "ArrayList" ||
    tokens[1]?.value === "LinkedList"
  ) {
    capacityArgument = tokens[1]?.value === "ArrayList";
    if (
      (capacityArgument && !factories.arrayList) ||
      (!capacityArgument && !factories.linkedList)
    )
      return { kind: "foreign" };
    cursor = 2;
  } else {
    return undefined;
  }
  if (tokens[cursor]?.value === "<") {
    const closeType = matchingForward(tokens, cursor, "<", ">");
    if (closeType === undefined) return undefined;
    cursor = closeType + 1;
  }
  if (tokens[cursor]?.value !== "(") return undefined;
  const call = callArgumentsAt(tokens, cursor);
  if (call === undefined || call.closeParen !== tokens.length - 1)
    return undefined;
  return { arguments: call.arguments, capacityArgument, kind: "owned" };
}

function localCommandListExpression(
  tokens: readonly JavaToken[],
  taints: ReadonlyMap<string, JavaTaint>,
  factories: JavaCollectionFactories,
  builders: ReadonlyMap<string, ProcessState>,
  commandLists: ReadonlyMap<string, CommandListState>,
): CommandListState | undefined {
  const alias = commandListExpression(tokens, builders, commandLists);
  if (alias !== undefined) return alias;
  const listFactory = inlineListFactoryArguments(tokens, factories);
  if (listFactory?.kind === "owned") {
    return commandListState(
      processArguments(listFactory.arguments, taints),
      listFactory.capability,
      "caller-owned",
    );
  }
  if (listFactory?.kind === "foreign") return undefined;
  const constructor = mutableListConstructorArguments(tokens, factories);
  if (constructor?.kind !== "owned") return undefined;
  if (constructor.arguments.length === 0) {
    return commandListState([], "mutable", "caller-owned");
  }
  if (constructor.arguments.length !== 1) return undefined;
  const argument = constructor.arguments[0] ?? [];
  if (constructor.capacityArgument && commandIndex(argument) !== undefined) {
    return commandListState([], "mutable", "caller-owned");
  }
  const source = commandListExpression(argument, builders, commandLists);
  if (source !== undefined) {
    return commandListState(
      source.arguments.map(cloneProcessArgument),
      "mutable",
      "caller-owned",
    );
  }
  const inline = inlineListFactoryArguments(argument, factories);
  if (inline?.kind === "owned") {
    return commandListState(
      processArguments(inline.arguments, taints),
      "mutable",
      "caller-owned",
    );
  }
  return undefined;
}

function commandIndex(tokens: readonly JavaToken[]): number | undefined {
  if (tokens.length !== 1 || tokens[0]?.kind !== "number") return undefined;
  const normalized = tokens[0].value.replaceAll("_", "");
  if (!/^(?:0|[1-9][0-9]*)$/u.test(normalized)) return undefined;
  const index = Number(normalized);
  return Number.isSafeInteger(index) && index <= MAX_JAVA_TOKENS
    ? index
    : undefined;
}

function mutatedArgument(
  tokens: readonly JavaToken[],
  taints: ReadonlyMap<string, JavaTaint>,
  mutationLine: number,
): ProcessArgument | undefined {
  if (tokens.length === 0) return undefined;
  const argument = processArguments([tokens], taints)[0];
  return argument === undefined ? undefined : { ...argument, mutationLine };
}

function mutatedArguments(
  tokens: readonly JavaToken[],
  taints: ReadonlyMap<string, JavaTaint>,
  factories: JavaCollectionFactories,
  commandLists: ReadonlyMap<string, CommandListState>,
  mutationLine: number,
): ProcessArgument[] | undefined {
  const alias = singleIdentifier(tokens);
  const known = alias === undefined ? undefined : commandLists.get(alias);
  if (known !== undefined) {
    return known.arguments.map((argument) => ({
      ...cloneProcessArgument(argument),
      mutationLine,
    }));
  }
  const inline = inlineListFactoryArguments(tokens, factories);
  if (inline?.kind !== "owned") return undefined;
  return processArguments(inline.arguments, taints).map((argument) => ({
    ...argument,
    mutationLine,
  }));
}

const READ_ONLY_LIST_METHODS = new Set([
  "contains",
  "containsAll",
  "equals",
  "forEach",
  "get",
  "getFirst",
  "getLast",
  "hashCode",
  "indexOf",
  "isEmpty",
  "iterator",
  "lastIndexOf",
  "listIterator",
  "parallelStream",
  "size",
  "spliterator",
  "stream",
  "subList",
  "toArray",
  "toString",
]);

function mutationAfterPrefix(
  tokens: readonly JavaToken[],
  prefixLength: number,
  taints: ReadonlyMap<string, JavaTaint>,
  factories: JavaCollectionFactories,
  commandLists: ReadonlyMap<string, CommandListState>,
): CommandListMutationResult | undefined {
  const suffix = tokens.slice(prefixLength);
  if (
    suffix[0]?.value !== "." ||
    suffix[1]?.kind !== "identifier" ||
    suffix[2]?.value !== "("
  ) {
    return undefined;
  }
  const close = matchingForward(suffix, 2, "(", ")");
  if (close === undefined || close !== suffix.length - 1) return undefined;
  const method = suffix[1].value;
  const arguments_ = splitArguments(suffix.slice(3, close));
  const line = suffix[1].line;
  if (READ_ONLY_LIST_METHODS.has(method)) return undefined;
  if (method === "clear" && arguments_.length === 0)
    return { kind: "clear", line };
  if (method === "set" && arguments_.length === 2) {
    const index = commandIndex(arguments_[0] ?? []);
    const argument = mutatedArgument(arguments_[1] ?? [], taints, line);
    return index === undefined || argument === undefined
      ? { kind: "unsupported", line }
      : { argument, index, kind: "set", line };
  }
  if (method === "add" && arguments_.length === 1) {
    const argument = mutatedArgument(arguments_[0] ?? [], taints, line);
    return argument === undefined
      ? { kind: "unsupported", line }
      : { argument, kind: "append", line };
  }
  if (method === "addLast" && arguments_.length === 1) {
    const argument = mutatedArgument(arguments_[0] ?? [], taints, line);
    return argument === undefined
      ? { kind: "unsupported", line }
      : { argument, kind: "append", line };
  }
  if (method === "addFirst" && arguments_.length === 1) {
    const argument = mutatedArgument(arguments_[0] ?? [], taints, line);
    return argument === undefined
      ? { kind: "unsupported", line }
      : { argument, index: 0, kind: "insert", line };
  }
  if (method === "add" && arguments_.length === 2) {
    const index = commandIndex(arguments_[0] ?? []);
    const argument = mutatedArgument(arguments_[1] ?? [], taints, line);
    return index === undefined || argument === undefined
      ? { kind: "unsupported", line }
      : { argument, index, kind: "insert", line };
  }
  if (method === "addAll" && arguments_.length === 1) {
    const values = mutatedArguments(
      arguments_[0] ?? [],
      taints,
      factories,
      commandLists,
      line,
    );
    return values === undefined
      ? { kind: "unsupported", line }
      : { arguments: values, kind: "append-many", line };
  }
  if (method === "addAll" && arguments_.length === 2) {
    const index = commandIndex(arguments_[0] ?? []);
    const values = mutatedArguments(
      arguments_[1] ?? [],
      taints,
      factories,
      commandLists,
      line,
    );
    return index === undefined || values === undefined
      ? { kind: "unsupported", line }
      : { arguments: values, index, kind: "insert-many", line };
  }
  if (method === "remove" && arguments_.length === 1) {
    const index = commandIndex(arguments_[0] ?? []);
    return index === undefined
      ? { kind: "unsupported", line }
      : { index, kind: "remove", line };
  }
  if (method === "removeFirst" && arguments_.length === 0) {
    return { kind: "remove-first", line };
  }
  if (method === "removeLast" && arguments_.length === 0) {
    return { kind: "remove-last", line };
  }
  return { kind: "unsupported", line };
}

function commandListMutation(
  tokens: readonly JavaToken[],
  receiver: string,
  taints: ReadonlyMap<string, JavaTaint>,
  factories: JavaCollectionFactories,
  commandLists: ReadonlyMap<string, CommandListState>,
): CommandListMutationResult | undefined {
  if (tokens[0]?.value !== receiver) return undefined;
  return mutationAfterPrefix(tokens, 1, taints, factories, commandLists);
}

function builderCommandListMutation(
  tokens: readonly JavaToken[],
  receiver: string,
  taints: ReadonlyMap<string, JavaTaint>,
  factories: JavaCollectionFactories,
  commandLists: ReadonlyMap<string, CommandListState>,
): CommandListMutationResult | undefined {
  if (
    tokens[0]?.value !== receiver ||
    tokens[1]?.value !== "." ||
    tokens[2]?.value !== "command" ||
    tokens[3]?.value !== "(" ||
    tokens[4]?.value !== ")"
  ) {
    return undefined;
  }
  return mutationAfterPrefix(tokens, 5, taints, factories, commandLists);
}

function collectionsAddAllMutation(
  tokens: readonly JavaToken[],
  taints: ReadonlyMap<string, JavaTaint>,
  factories: JavaCollectionFactories,
  builders: ReadonlyMap<string, ProcessState>,
  commandLists: ReadonlyMap<string, CommandListState>,
): BoundCommandListMutation | undefined {
  for (let index = 0; index < tokens.length; index += 1) {
    const qualified =
      tokens[index]?.value === "java" &&
      tokens[index + 1]?.value === "." &&
      tokens[index + 2]?.value === "util" &&
      tokens[index + 3]?.value === "." &&
      tokens[index + 4]?.value === "Collections" &&
      tokens[index + 5]?.value === "." &&
      tokens[index + 6]?.value === "addAll" &&
      tokens[index + 7]?.value === "(";
    const unqualified =
      tokens[index]?.value === "Collections" &&
      tokens[index + 1]?.value === "." &&
      tokens[index + 2]?.value === "addAll" &&
      tokens[index + 3]?.value === "(";
    if (!qualified && !unqualified) continue;
    const methodIndex = index + (qualified ? 6 : 2);
    const call = callArgumentsAt(tokens, methodIndex + 1);
    if (
      call === undefined ||
      call.closeParen !== tokens.length - 1 ||
      call.arguments.length === 0
    )
      return undefined;
    const command = commandListExpression(
      call.arguments[0] ?? [],
      builders,
      commandLists,
    );
    if (command === undefined) return undefined;
    const line = tokens[methodIndex]?.line ?? 1;
    if (unqualified && !factories.collections) {
      return { command, mutation: { kind: "unsupported", line } };
    }
    const arguments_ = processArguments(call.arguments.slice(1), taints).map(
      (argument) => ({ ...argument, mutationLine: line }),
    );
    return {
      command,
      mutation: {
        arguments: arguments_,
        kind: "append-many",
        line,
        noOpOnEmpty: true,
      },
    };
  }
  return undefined;
}

function applyCommandListMutation(
  command: CommandListState,
  mutation: CommandListMutationResult,
): boolean {
  if (mutation.kind === "unsupported") return false;
  if (
    mutation.noOpOnEmpty === true &&
    mutation.kind === "append-many" &&
    mutation.arguments?.length === 0
  )
    return true;
  if (command.capability === "unmodifiable") return false;
  if (command.capability === "fixed-size" && mutation.kind !== "set")
    return false;
  const arguments_ = command.arguments;
  if (mutation.kind === "clear") {
    arguments_.splice(0, arguments_.length);
    return true;
  }
  if (mutation.kind === "append" && mutation.argument !== undefined) {
    arguments_.push(mutation.argument);
    return true;
  }
  if (mutation.kind === "append-many" && mutation.arguments !== undefined) {
    arguments_.push(...mutation.arguments);
    return true;
  }
  if (
    mutation.kind === "insert" &&
    mutation.argument !== undefined &&
    mutation.index !== undefined &&
    mutation.index <= arguments_.length
  ) {
    arguments_.splice(mutation.index, 0, mutation.argument);
    for (const argument of arguments_) argument.mutationLine = mutation.line;
    return true;
  }
  if (
    mutation.kind === "insert-many" &&
    mutation.arguments !== undefined &&
    mutation.index !== undefined &&
    mutation.index <= arguments_.length
  ) {
    arguments_.splice(mutation.index, 0, ...mutation.arguments);
    for (const argument of arguments_) argument.mutationLine = mutation.line;
    return true;
  }
  if (
    mutation.kind === "remove" &&
    mutation.index !== undefined &&
    mutation.index < arguments_.length
  ) {
    arguments_.splice(mutation.index, 1);
    for (const argument of arguments_) argument.mutationLine = mutation.line;
    return true;
  }
  if (mutation.kind === "remove-first" && arguments_.length > 0) {
    arguments_.splice(0, 1);
    for (const argument of arguments_) argument.mutationLine = mutation.line;
    return true;
  }
  if (mutation.kind === "remove-last" && arguments_.length > 0) {
    arguments_.splice(arguments_.length - 1, 1);
    for (const argument of arguments_) argument.mutationLine = mutation.line;
    return true;
  }
  if (
    mutation.kind === "set" &&
    mutation.argument !== undefined &&
    mutation.index !== undefined &&
    mutation.index < arguments_.length
  ) {
    arguments_[mutation.index] = mutation.argument;
    for (const argument of arguments_) argument.mutationLine = mutation.line;
    return true;
  }
  return false;
}

function invocationIndex(
  tokens: readonly JavaToken[],
  name: string,
  from = 0,
): number | undefined {
  for (let index = from; index < tokens.length - 1; index += 1) {
    if (tokens[index]?.value === name && tokens[index + 1]?.value === "(")
      return index;
  }
  return undefined;
}

function processBuilderConstructor(
  tokens: readonly JavaToken[],
): { index: number; openParen: number } | undefined {
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index]?.value !== "new") continue;
    if (
      tokens[index + 1]?.value === "ProcessBuilder" &&
      tokens[index + 2]?.value === "("
    ) {
      return { index, openParen: index + 2 };
    }
    const qualified = tokens
      .slice(index + 1, index + 7)
      .map((token) => token.value)
      .join("");
    if (qualified === "java.lang.ProcessBuilder(")
      return { index, openParen: index + 6 };
  }
  return undefined;
}

function runtimeExecInvocation(
  tokens: readonly JavaToken[],
): number | undefined {
  const compact = tokens.map((token) => token.value);
  for (let index = 0; index < compact.length - 7; index += 1) {
    const suffix = compact.slice(index).join("");
    if (suffix.startsWith("Runtime.getRuntime().exec(")) {
      return index + 7;
    }
    if (suffix.startsWith("java.lang.Runtime.getRuntime().exec(")) {
      return index + 11;
    }
  }
  return undefined;
}

function inlineStringArrayArguments(
  tokens: readonly JavaToken[],
): JavaToken[][] | undefined {
  const compactPrefix = tokens
    .slice(0, 5)
    .map((token) => token.value)
    .join("");
  if (!compactPrefix.startsWith("newString[]")) return undefined;
  const open = tokens.findIndex((token) => token.value === "{");
  if (open < 0) return undefined;
  const close = matchingForward(tokens, open, "{", "}");
  if (close === undefined) return undefined;
  return splitArguments(tokens.slice(open + 1, close));
}

function executableBase(value: string): string {
  return (
    value.replaceAll("\\", "/").split("/").at(-1)?.toLowerCase() ??
    value.toLowerCase()
  );
}

function taintedArgumentRisk(
  arguments_: readonly ProcessArgument[],
  commandString = false,
  mutationSymbol = "ProcessBuilder.command live list",
): JavaRisk | undefined {
  if (arguments_.length === 0) return undefined;
  const argumentTaint = (
    argument: ProcessArgument | undefined,
  ): JavaTaint | undefined => {
    const taint = argument?.taint;
    if (
      taint !== undefined &&
      argument?.mutationLine !== undefined &&
      !taint.propagators.some(
        ({ kind, line }) =>
          kind === "java-command-list-mutation" &&
          line === argument.mutationLine,
      )
    ) {
      taint.propagators.push({
        kind: "java-command-list-mutation",
        line: argument.mutationLine,
        symbol: mutationSymbol,
      });
    }
    return taint;
  };
  if (commandString) {
    const taint = argumentTaint(arguments_[0]);
    return taint === undefined
      ? undefined
      : { kind: "java-process-split-command", taint, argumentIndex: 1 };
  }
  const executableTaint = argumentTaint(arguments_[0]);
  if (executableTaint !== undefined) {
    return {
      kind: "java-process-executable-selection",
      taint: executableTaint,
      argumentIndex: 1,
    };
  }
  const program = arguments_[0]?.literal;
  if (program === undefined) return undefined;
  const base = executableBase(program);
  const literals = arguments_.map((argument) =>
    argument.literal?.toLowerCase(),
  );
  const taints = arguments_.map(argumentTaint);
  const riskAfterFlag = (
    flags: ReadonlySet<string>,
    kind: JavaProcessSinkKind,
    start = 1,
  ): JavaRisk | undefined => {
    for (let index = start; index < arguments_.length - 1; index += 1) {
      if (!flags.has(literals[index] ?? "")) continue;
      const taint = taints[index + 1];
      if (taint !== undefined) return { kind, taint, argumentIndex: index + 2 };
    }
    return undefined;
  };
  if (base === "env" || base === "env.exe") {
    let afterOptions = false;
    for (let index = 1; index < arguments_.length; index += 1) {
      const literal = literals[index];
      const taint = taints[index];
      if (
        !afterOptions &&
        (literal === "-s" ||
          literal === "--split-string" ||
          literal?.startsWith("--split-string="))
      ) {
        if (taint !== undefined) {
          taint.propagators.push({
            kind: "java-process-delegated-launcher",
            line: arguments_[index]?.line ?? 1,
            symbol: "env split-string",
          });
          return {
            kind: "java-process-split-command",
            taint,
            argumentIndex: index + 1,
            delegated: "env",
          };
        }
        continue;
      }
      if (!afterOptions && literal === "--") {
        afterOptions = true;
        continue;
      }
      if (!afterOptions && (literal === "-u" || literal === "--unset")) {
        index += 1;
        continue;
      }
      if (!afterOptions && literal?.startsWith("-")) continue;
      if (literal !== undefined && /^[A-Za-z_][A-Za-z0-9_]*=/u.test(literal))
        continue;
      if (taint !== undefined) {
        taint.propagators.push({
          kind: "java-process-delegated-launcher",
          line: arguments_[index]?.line ?? 1,
          symbol: "env executable selection",
        });
        return {
          kind: "java-process-executable-selection",
          taint,
          argumentIndex: index + 1,
          delegated: "env",
        };
      }
      if (literal === undefined) return undefined;
      const nested = taintedArgumentRisk(
        arguments_.slice(index),
        false,
        mutationSymbol,
      );
      if (nested !== undefined) {
        nested.argumentIndex += index;
        nested.delegated = "env";
        nested.taint.propagators.push({
          kind: "java-process-delegated-launcher",
          line: arguments_[index]?.line ?? 1,
          symbol: "env nested command",
        });
      }
      return nested;
    }
    return undefined;
  }
  if (POSIX_SHELLS.has(base)) {
    const risk = riskAfterFlag(new Set(["-c"]), "java-process-shell-command");
    if (risk !== undefined) return risk;
  }
  if (base === "cmd" || base === "cmd.exe") {
    const risk = riskAfterFlag(
      new Set(["/c", "/k"]),
      "java-process-shell-command",
    );
    if (risk !== undefined) return risk;
  }
  if (POWERSHELLS.has(base)) {
    const risk = riskAfterFlag(
      new Set(["-c", "-command"]),
      "java-process-shell-command",
    );
    if (risk !== undefined) return risk;
  }
  const interpreterFlags = INTERPRETER_FLAGS.get(base);
  if (interpreterFlags !== undefined) {
    const risk = riskAfterFlag(
      interpreterFlags,
      "java-process-interpreter-command",
    );
    if (risk !== undefined) return risk;
  }
  if (base.endsWith(".bat") || base.endsWith(".cmd")) {
    const index = taints.findIndex(
      (taint, argumentIndex) => argumentIndex > 0 && taint !== undefined,
    );
    const taint = taints[index];
    if (index > 0 && taint !== undefined) {
      return {
        kind: "java-process-shell-command",
        taint,
        argumentIndex: index + 1,
      };
    }
  }
  return undefined;
}

function processStateRisk(state: ProcessState): JavaRisk | undefined {
  const risk = taintedArgumentRisk(
    state.command.arguments,
    false,
    state.command.origin === "caller-owned"
      ? "caller-owned command list"
      : "ProcessBuilder.command live list",
  );
  if (risk === undefined) return undefined;
  if (state.commandSetKind === "replacement") {
    risk.taint.propagators.push({
      kind: "java-process-command-replacement",
      line: state.commandSetLine,
      symbol: "effective command",
    });
  }
  if (state.commandSourceKind === "caller-list") {
    risk.taint.propagators.push({
      kind: "java-caller-command-list-binding",
      line: state.commandSetLine,
      symbol:
        state.commandSetKind === "constructor"
          ? "ProcessBuilder(List) shared command list"
          : "ProcessBuilder.command(List) shared command list",
    });
  }
  return risk;
}

function boundedLine(value: string): string {
  return value.length <= MAX_EXCERPT_LINE_CHARACTERS
    ? value
    : `${value.slice(0, MAX_EXCERPT_LINE_CHARACTERS)}…[truncated]`;
}

function excerpt(
  lines: readonly string[],
  startLine: number,
  endLine: number,
): string {
  return lines
    .slice(startLine - 1, endLine)
    .map(boundedLine)
    .join("\n");
}

function recordForRisk(
  path: string,
  lines: readonly string[],
  executionLine: number,
  risk: JavaRisk,
  owner: "java.lang.ProcessBuilder" | "java.lang.Runtime",
  method: "exec" | "start",
): JavaSpringCommandInjectionRecord {
  const startLine = Math.max(1, executionLine - CONTEXT_LINES_BEFORE);
  const endLine = Math.min(lines.length, executionLine + CONTEXT_LINES_AFTER);
  const sourceStart = Math.max(1, risk.taint.source.line - 1);
  const sourceEnd = Math.min(lines.length, risk.taint.source.line + 1);
  const controls = risk.taint.controls.filter(
    (control, index, all) =>
      all.findIndex(
        (candidate) =>
          candidate.kind === control.kind && candidate.line === control.line,
      ) === index,
  );
  return {
    path,
    line: executionLine,
    categories: ["spring-java-command-injection"],
    priority: 12,
    startLine,
    endLine,
    excerpt: excerpt(lines, startLine, endLine),
    sourceExcerpt: excerpt(lines, sourceStart, sourceEnd),
    frameworkModel: {
      schemaVersion: "1.2",
      id: "spring-java-command-injection",
      language: "java",
      scope: "same-file",
      source: { ...risk.taint.source, path },
      sink: {
        kind: risk.kind,
        path,
        line: executionLine,
        symbol: `${owner};method=${method};argument=${risk.argumentIndex}`,
        cweIds: ["CWE-78", "CWE-88"],
      },
      propagators: risk.taint.propagators.map((propagator) => ({
        ...propagator,
        path,
      })),
      candidateControls: controls
        .slice(0, 8)
        .map((control) => ({ ...control, path })),
    },
  };
}

function productionJavaPath(path: string): boolean {
  const normalized = path.replaceAll("\\", "/").toLowerCase();
  if (!normalized.endsWith(".java")) return false;
  if (
    /(?:^|\/)(?:build|examples|fixtures|generated|out|target|test|tests)(?:\/|$)/u.test(
      normalized,
    )
  )
    return false;
  return !/(?:test|tests|spec)\.java$/u.test(normalized);
}

function springAnnotationImports(text: string): Set<string> {
  const imports = new Set<string>();
  for (const match of text.matchAll(
    /^\s*import\s+org\.springframework\.web\.bind\.annotation\.([A-Za-z_$][\w$]*|\*)\s*;/gmu,
  )) {
    const name = match[1] ?? "";
    if (name === "*") {
      SOURCE_ANNOTATIONS.forEach((candidate) => imports.add(candidate));
      ROUTE_ANNOTATIONS.forEach((candidate) => imports.add(candidate));
    } else {
      imports.add(name);
    }
  }
  return imports;
}

function shadowsJavaLangType(
  text: string,
  name: "ProcessBuilder" | "Runtime",
): boolean {
  const local = new RegExp(
    `\\b(?:class|enum|interface|record)\\s+${name}\\b`,
    "u",
  ).test(text);
  const conflictingImport = new RegExp(
    `^\\s*import\\s+(?!java\\.lang\\.${name}\\s*;)[A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*\\.${name}\\s*;`,
    "mu",
  ).test(text);
  return local || conflictingImport;
}

function importedJavaUtilType(
  text: string,
  name: "ArrayList" | "Arrays" | "Collections" | "LinkedList" | "List",
): boolean {
  const exactOrWildcardImport = new RegExp(
    `^\\s*import\\s+java\\.util\\.(?:${name}|\\*)\\s*;`,
    "mu",
  ).test(text);
  if (!exactOrWildcardImport) return false;
  const local = new RegExp(
    `\\b(?:class|enum|interface|record)\\s+${name}\\b`,
    "u",
  ).test(text);
  const conflictingImport = new RegExp(
    `^\\s*import\\s+(?!java\\.util\\.${name}\\s*;)[A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*\\.${name}\\s*;`,
    "mu",
  ).test(text);
  return !local && !conflictingImport;
}

export function javaSpringCommandModelOwnsFile(
  path: string,
  text: string,
): boolean {
  if (!productionJavaPath(path)) return false;
  const imports = springAnnotationImports(text);
  return (
    [...SOURCE_ANNOTATIONS].some((name) => imports.has(name)) &&
    [...ROUTE_ANNOTATIONS].some((name) => imports.has(name))
  );
}

export function javaSpringCommandInjectionRecords(
  path: string,
  lines: readonly string[],
  text: string,
): JavaSpringCommandInjectionRecord[] {
  if (!javaSpringCommandModelOwnsFile(path, text)) return [];
  const processBuilderAvailable = !shadowsJavaLangType(text, "ProcessBuilder");
  const runtimeAvailable = !shadowsJavaLangType(text, "Runtime");
  if (!processBuilderAvailable && !runtimeAvailable) return [];
  const collectionFactories: JavaCollectionFactories = {
    arrayList: importedJavaUtilType(text, "ArrayList"),
    arraysAsList: importedJavaUtilType(text, "Arrays"),
    collections: importedJavaUtilType(text, "Collections"),
    linkedList: importedJavaUtilType(text, "LinkedList"),
    listOf: importedJavaUtilType(text, "List"),
  };
  const tokens = javaTokens(text);
  if (tokens === undefined) return [];
  const records: JavaSpringCommandInjectionRecord[] = [];
  const annotationImports = springAnnotationImports(text);
  const importedSourceAnnotations = new Set(
    [...SOURCE_ANNOTATIONS].filter((name) => annotationImports.has(name)),
  );
  const importedRouteAnnotations = new Set(
    [...ROUTE_ANNOTATIONS].filter((name) => annotationImports.has(name)),
  );
  for (const scope of javaMethodScopes(
    tokens,
    importedSourceAnnotations,
    importedRouteAnnotations,
  )) {
    const taints = new Map<string, JavaTaint>();
    for (const source of scope.sources) {
      const name = source.symbol.split(":").at(-1) ?? "";
      if (name !== "")
        taints.set(name, { source, propagators: [], controls: [] });
    }
    const builders = new Map<string, ProcessState>();
    const commandLists = new Map<string, CommandListState>();
    let scopeAborted = false;
    for (const statement of statementSlices(scope.body)) {
      const target = assignmentTarget(statement);
      const constructor = processBuilderAvailable
        ? processBuilderConstructor(statement)
        : undefined;
      if (constructor !== undefined) {
        const constructorCall = callArgumentsAt(
          statement,
          constructor.openParen,
        );
        if (constructorCall !== undefined) {
          const initial = processCommandState(
            constructorCall.arguments,
            taints,
            collectionFactories,
            commandLists,
          );
          let state: ProcessState = {
            command: initial.command,
            commandSetKind: "constructor",
            commandSetLine: statement[constructor.index]?.line ?? 1,
            commandSourceKind: initial.sourceKind,
          };
          let cursor = constructorCall.closeParen + 1;
          while (cursor < statement.length) {
            const command = invocationIndex(statement, "command", cursor);
            if (command === undefined || statement[command - 1]?.value !== ".")
              break;
            const commandCall = callArgumentsAt(statement, command + 1);
            if (commandCall === undefined) break;
            if (commandCall.arguments.length === 0) {
              cursor = commandCall.closeParen + 1;
              break;
            }
            const replacement = processCommandState(
              commandCall.arguments,
              taints,
              collectionFactories,
              commandLists,
            );
            state = {
              command: replacement.command,
              commandSetKind: "replacement",
              commandSetLine: statement[command]?.line ?? state.commandSetLine,
              commandSourceKind: replacement.sourceKind,
            };
            cursor = commandCall.closeParen + 1;
          }
          if (target !== undefined) builders.set(target, state);
          const start = invocationIndex(
            statement,
            "start",
            constructorCall.closeParen + 1,
          );
          if (start !== undefined && statement[start - 1]?.value === ".") {
            const risk = processStateRisk(state);
            if (risk !== undefined) {
              risk.taint.propagators.push({
                kind: "java-process-execution",
                line: statement[start]?.line ?? 1,
                symbol: "ProcessBuilder.start",
              });
              records.push(
                recordForRisk(
                  path,
                  lines,
                  statement[start]?.line ?? 1,
                  risk,
                  "java.lang.ProcessBuilder",
                  "start",
                ),
              );
            }
          }
        }
      } else if (processBuilderAvailable) {
        const command = invocationIndex(statement, "command");
        if (command !== undefined && statement[command - 1]?.value === ".") {
          const receiver = simpleNameBefore(statement, command - 2);
          const commandCall = callArgumentsAt(statement, command + 1);
          if (
            receiver !== undefined &&
            commandCall !== undefined &&
            commandCall.arguments.length > 0 &&
            builders.has(receiver)
          ) {
            const state = builders.get(receiver)!;
            const replacement = processCommandState(
              commandCall.arguments,
              taints,
              collectionFactories,
              commandLists,
            );
            state.command = replacement.command;
            state.commandSourceKind = replacement.sourceKind;
            state.commandSetKind = "replacement";
            state.commandSetLine = statement[command]?.line ?? 1;
          }
        }
        const leadingReceiver = statement[0]?.value ?? "";
        const builderState = builders.get(leadingReceiver);
        const liveCommand = commandLists.get(leadingReceiver);
        const mutation =
          builderState !== undefined
            ? builderCommandListMutation(
                statement,
                leadingReceiver,
                taints,
                collectionFactories,
                commandLists,
              )
            : liveCommand !== undefined
              ? commandListMutation(
                  statement,
                  leadingReceiver,
                  taints,
                  collectionFactories,
                  commandLists,
                )
              : undefined;
        const staticMutation = collectionsAddAllMutation(
          statement,
          taints,
          collectionFactories,
          builders,
          commandLists,
        );
        if (mutation !== undefined) {
          const commandState = builderState?.command ?? liveCommand;
          if (
            commandState === undefined ||
            !applyCommandListMutation(commandState, mutation)
          ) {
            scopeAborted = true;
          }
        }
        if (
          staticMutation !== undefined &&
          !applyCommandListMutation(
            staticMutation.command,
            staticMutation.mutation,
          )
        ) {
          scopeAborted = true;
        }
        if (scopeAborted) break;
        const start = invocationIndex(statement, "start");
        if (start !== undefined && statement[start - 1]?.value === ".") {
          const receiver = simpleNameBefore(statement, start - 2);
          const state =
            receiver === undefined ? undefined : builders.get(receiver);
          const risk =
            state === undefined ? undefined : processStateRisk(state);
          if (risk !== undefined && state !== undefined) {
            risk.taint.propagators.push({
              kind: "java-process-execution",
              line: statement[start]?.line ?? 1,
              symbol: "ProcessBuilder.start",
            });
            records.push(
              recordForRisk(
                path,
                lines,
                statement[start]?.line ?? 1,
                risk,
                "java.lang.ProcessBuilder",
                "start",
              ),
            );
          }
        }
      }
      if (runtimeAvailable) {
        const execOpen = runtimeExecInvocation(statement);
        if (execOpen !== undefined) {
          const call = callArgumentsAt(statement, execOpen);
          const first = call?.arguments[0];
          if (first !== undefined) {
            const arrayArguments = inlineStringArrayArguments(first);
            const arguments_ =
              arrayArguments === undefined
                ? processArguments([first], taints)
                : processArguments(arrayArguments, taints);
            const risk = taintedArgumentRisk(
              arguments_,
              arrayArguments === undefined,
            );
            if (risk !== undefined) {
              const line = statement[execOpen - 1]?.line ?? first[0]?.line ?? 1;
              risk.taint.propagators.push({
                kind: "java-runtime-exec",
                line,
                symbol:
                  arrayArguments === undefined
                    ? "Runtime.exec(String)"
                    : "Runtime.exec(String[])",
              });
              records.push(
                recordForRisk(
                  path,
                  lines,
                  line,
                  risk,
                  "java.lang.Runtime",
                  "exec",
                ),
              );
            }
          }
        }
      }
      if (target !== undefined) {
        const expression = assignmentExpression(statement) ?? [];
        const builderAliasName = singleIdentifier(expression);
        const builderAlias =
          constructor === undefined && builderAliasName !== undefined
            ? builders.get(builderAliasName)
            : undefined;
        const commandListAlias =
          constructor === undefined && builderAlias === undefined
            ? localCommandListExpression(
                expression,
                taints,
                collectionFactories,
                builders,
                commandLists,
              )
            : undefined;
        if (constructor !== undefined) {
          commandLists.delete(target);
          taints.delete(target);
        } else if (builderAlias !== undefined) {
          builders.set(target, builderAlias);
          commandLists.delete(target);
          taints.delete(target);
        } else if (commandListAlias !== undefined) {
          commandLists.set(target, commandListAlias);
          builders.delete(target);
          taints.delete(target);
        } else {
          builders.delete(target);
          commandLists.delete(target);
          const taint = expressionTaint(expression, taints);
          if (taint === undefined) {
            taints.delete(target);
            continue;
          }
          taint.propagators.push({
            kind: "java-local-assignment",
            line: expression[0]?.line ?? taint.source.line,
            symbol: target,
          });
          taints.set(target, taint);
        }
      }
    }
    if (scopeAborted) continue;
  }
  const seen = new Set<string>();
  return records.filter((record) => {
    const key = `${record.path}\0${record.line}\0${record.frameworkModel.sink.kind}\0${record.frameworkModel.source.line}`;
    if (seen.has(key) || seen.size >= MAX_RECORDS) return false;
    seen.add(key);
    return true;
  });
}
