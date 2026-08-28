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
  taint?: JavaTaint;
}

interface ProcessState {
  arguments: ProcessArgument[];
  commandSetLine: number;
}

interface JavaCollectionFactories {
  arraysAsList: boolean;
  listOf: boolean;
}

type InlineListFactory =
  | { arguments: JavaToken[][]; kind: "owned" }
  | { kind: "foreign" };

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
  arguments_: readonly JavaToken[][],
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
  return { arguments: call.arguments, kind: "owned" };
}

function processCommandArguments(
  arguments_: readonly JavaToken[][],
  taints: ReadonlyMap<string, JavaTaint>,
  factories: JavaCollectionFactories,
): ProcessArgument[] {
  if (arguments_.length === 1 && arguments_[0] !== undefined) {
    const arrayArguments = inlineStringArrayArguments(arguments_[0]);
    if (arrayArguments !== undefined)
      return processArguments(arrayArguments, taints);
    const listFactory = inlineListFactoryArguments(arguments_[0], factories);
    if (listFactory?.kind === "owned")
      return processArguments(listFactory.arguments, taints);
    if (listFactory?.kind === "foreign") return [];
  }
  return processArguments(arguments_, taints);
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
): JavaRisk | undefined {
  if (arguments_.length === 0) return undefined;
  if (commandString) {
    const taint = arguments_[0]?.taint;
    return taint === undefined
      ? undefined
      : { kind: "java-process-split-command", taint, argumentIndex: 1 };
  }
  const executableTaint = arguments_[0]?.taint;
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
  const taints = arguments_.map((argument) => argument.taint);
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
      const nested = taintedArgumentRisk(arguments_.slice(index));
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

function importedJavaUtilType(text: string, name: "Arrays" | "List"): boolean {
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
    arraysAsList: importedJavaUtilType(text, "Arrays"),
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
          let state: ProcessState = {
            arguments: processCommandArguments(
              constructorCall.arguments,
              taints,
              collectionFactories,
            ),
            commandSetLine: statement[constructor.index]?.line ?? 1,
          };
          let cursor = constructorCall.closeParen + 1;
          while (cursor < statement.length) {
            const command = invocationIndex(statement, "command", cursor);
            if (command === undefined || statement[command - 1]?.value !== ".")
              break;
            const commandCall = callArgumentsAt(statement, command + 1);
            if (commandCall === undefined) break;
            state = {
              arguments: processCommandArguments(
                commandCall.arguments,
                taints,
                collectionFactories,
              ),
              commandSetLine: statement[command]?.line ?? state.commandSetLine,
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
            const risk = taintedArgumentRisk(state.arguments);
            if (risk !== undefined) {
              risk.taint.propagators.push(
                {
                  kind: "java-process-command-replacement",
                  line: state.commandSetLine,
                  symbol: "effective command",
                },
                {
                  kind: "java-process-execution",
                  line: statement[start]?.line ?? 1,
                  symbol: "ProcessBuilder.start",
                },
              );
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
            builders.has(receiver)
          ) {
            builders.set(receiver, {
              arguments: processCommandArguments(
                commandCall.arguments,
                taints,
                collectionFactories,
              ),
              commandSetLine: statement[command]?.line ?? 1,
            });
          }
        }
        const start = invocationIndex(statement, "start");
        if (start !== undefined && statement[start - 1]?.value === ".") {
          const receiver = simpleNameBefore(statement, start - 2);
          const state =
            receiver === undefined ? undefined : builders.get(receiver);
          const risk =
            state === undefined
              ? undefined
              : taintedArgumentRisk(state.arguments);
          if (risk !== undefined && state !== undefined) {
            risk.taint.propagators.push(
              {
                kind: "java-process-command-replacement",
                line: state.commandSetLine,
                symbol: "effective command",
              },
              {
                kind: "java-process-execution",
                line: statement[start]?.line ?? 1,
                symbol: "ProcessBuilder.start",
              },
            );
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
      if (constructor === undefined && target !== undefined) {
        const equals = statement.findIndex((token) => token.value === "=");
        const taint = expressionTaint(statement.slice(equals + 1), taints);
        if (taint !== undefined) {
          taint.propagators.push({
            kind: "java-local-assignment",
            line: statement[equals]?.line ?? taint.source.line,
            symbol: target,
          });
          taints.set(target, taint);
        } else {
          taints.delete(target);
          const alias = statement
            .slice(equals + 1)
            .find((token) => token.kind === "identifier")?.value;
          const state = alias === undefined ? undefined : builders.get(alias);
          if (state !== undefined) builders.set(target, state);
        }
      }
    }
  }
  const seen = new Set<string>();
  return records.filter((record) => {
    const key = `${record.path}\0${record.line}\0${record.frameworkModel.sink.kind}\0${record.frameworkModel.source.line}`;
    if (seen.has(key) || seen.size >= MAX_RECORDS) return false;
    seen.add(key);
    return true;
  });
}
