const CONTEXT_LINES_BEFORE = 4;
const CONTEXT_LINES_AFTER = 6;
const MAX_KOTLIN_TOKENS = 131_072;
const MAX_KOTLIN_NESTING = 128;
const MAX_RECORDS = 64;
const MAX_EXCERPT_LINE_CHARACTERS = 2_048;

type KotlinTokenKind =
  | "identifier"
  | "newline"
  | "number"
  | "string"
  | "symbol";

interface KotlinToken {
  kind: KotlinTokenKind;
  value: string;
  line: number;
  column: number;
  references: string[];
}

interface KotlinSource {
  kind:
    | "ktor-header"
    | "ktor-path-parameter"
    | "ktor-query-parameter"
    | "ktor-query-string"
    | "ktor-request-body";
  line: number;
  symbol: string;
}

interface KotlinPropagator {
  kind:
    | "kotlin-local-assignment"
    | "kotlin-string-concatenation"
    | "kotlin-string-interpolation";
  line: number;
  symbol?: string;
}

interface KotlinTaint {
  source: KotlinSource;
  propagators: KotlinPropagator[];
  controls: Array<{ kind: string; line: number }>;
}

interface ProcessArgument {
  tokens: KotlinToken[];
  line: number;
}

interface ProcessBuilderState {
  arguments: ProcessArgument[];
  constructorLine: number;
}

type KotlinProcessSinkKind =
  | "kotlin-process-executable-selection"
  | "kotlin-process-interpreter-command"
  | "kotlin-process-shell-command";

interface KotlinRisk {
  kind: KotlinProcessSinkKind;
  taint: KotlinTaint;
  argumentIndex: number;
}

export interface KotlinKtorCommandInjectionRecord {
  path: string;
  line: number;
  categories: ["kotlin-ktor-command-injection"];
  priority: number;
  startLine: number;
  endLine: number;
  excerpt: string;
  sourceExcerpt: string;
  frameworkModel: {
    schemaVersion: "1.2";
    id: "kotlin-ktor-command-injection";
    language: "kotlin";
    scope: "same-file";
    source: {
      kind: KotlinSource["kind"];
      path: string;
      line: number;
      symbol: string;
    };
    sink: {
      kind: KotlinProcessSinkKind;
      path: string;
      line: number;
      symbol: string;
      cweIds: readonly ["CWE-78", "CWE-88"];
    };
    propagators: Array<KotlinPropagator & { path: string }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

const ROUTE_METHODS = new Set([
  "delete",
  "get",
  "head",
  "options",
  "patch",
  "post",
  "put",
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

function identifierStart(character: string): boolean {
  return /[A-Za-z_\u0080-\uffff]/u.test(character);
}

function identifierPart(character: string): boolean {
  return /[A-Za-z0-9_\u0080-\uffff]/u.test(character);
}

function stringReferences(value: string): string[] {
  const references = new Set<string>();
  for (const match of value.matchAll(/\$([A-Za-z_][A-Za-z0-9_]*)/gu)) {
    references.add(match[1] ?? "");
  }
  for (const match of value.matchAll(/\$\{([^{}]{1,2048})\}/gu)) {
    const expression = match[1] ?? "";
    for (const identifier of expression.matchAll(
      /\b([A-Za-z_][A-Za-z0-9_]*)\b/gu,
    )) {
      const name = identifier[1] ?? "";
      if (!new Set(["false", "null", "this", "true"]).has(name))
        references.add(name);
    }
  }
  return [...references].filter(Boolean);
}

function kotlinTokens(source: string): KotlinToken[] | undefined {
  const tokens: KotlinToken[] = [];
  const delimiters: string[] = [];
  let index = 0;
  let line = 1;
  let column = 1;
  let previousWasCarriageReturn = false;

  const advance = (value: string): void => {
    for (const character of value) {
      if (character === "\r") {
        line += 1;
        column = 1;
        previousWasCarriageReturn = true;
      } else if (character === "\n") {
        if (!previousWasCarriageReturn) line += 1;
        column = 1;
        previousWasCarriageReturn = false;
      } else {
        column += 1;
        previousWasCarriageReturn = false;
      }
    }
  };
  const consume = (length: number): string => {
    const value = source.slice(index, index + length);
    index += length;
    advance(value);
    return value;
  };
  const add = (
    kind: KotlinTokenKind,
    value: string,
    tokenLine: number,
    tokenColumn: number,
    references: string[] = [],
  ): boolean => {
    tokens.push({
      kind,
      value,
      line: tokenLine,
      column: tokenColumn,
      references,
    });
    return tokens.length <= MAX_KOTLIN_TOKENS;
  };

  while (index < source.length) {
    const character = source[index] ?? "";
    if (character === "\r" || character === "\n") {
      const tokenLine = line;
      const tokenColumn = column;
      consume(character === "\r" && source[index + 1] === "\n" ? 2 : 1);
      if (!add("newline", "\n", tokenLine, tokenColumn)) return undefined;
      continue;
    }
    if (/\s/u.test(character)) {
      consume(1);
      continue;
    }
    if (character === "/" && source[index + 1] === "/") {
      const newline = source.slice(index).search(/[\r\n]/u);
      consume(newline < 0 ? source.length - index : newline);
      continue;
    }
    if (character === "/" && source[index + 1] === "*") {
      let cursor = index + 2;
      let depth = 1;
      while (cursor < source.length && depth > 0) {
        if (source.startsWith("/*", cursor)) {
          depth += 1;
          if (depth > MAX_KOTLIN_NESTING) return undefined;
          cursor += 2;
        } else if (source.startsWith("*/", cursor)) {
          depth -= 1;
          cursor += 2;
        } else {
          cursor += 1;
        }
      }
      if (depth !== 0) return undefined;
      consume(cursor - index);
      continue;
    }
    if (source.startsWith('"""', index)) {
      const tokenLine = line;
      const tokenColumn = column;
      const end = source.indexOf('"""', index + 3);
      if (end < 0) return undefined;
      const value = source.slice(index + 3, end);
      consume(end + 3 - index);
      if (
        !add("string", value, tokenLine, tokenColumn, stringReferences(value))
      )
        return undefined;
      continue;
    }
    if (character === '"' || character === "'") {
      const quote = character;
      const tokenLine = line;
      const tokenColumn = column;
      let cursor = index + 1;
      let escaped = false;
      while (cursor < source.length) {
        const current = source[cursor] ?? "";
        if (!escaped && current === quote) break;
        if (!escaped && current === "\\") escaped = true;
        else escaped = false;
        cursor += 1;
      }
      if (cursor >= source.length) return undefined;
      const value = source.slice(index + 1, cursor);
      consume(cursor + 1 - index);
      if (
        !add(
          "string",
          value,
          tokenLine,
          tokenColumn,
          quote === '"' ? stringReferences(value) : [],
        )
      )
        return undefined;
      continue;
    }
    if (identifierStart(character)) {
      const tokenLine = line;
      const tokenColumn = column;
      let cursor = index + 1;
      while (identifierPart(source[cursor] ?? "")) cursor += 1;
      const value = source.slice(index, cursor);
      consume(cursor - index);
      if (!add("identifier", value, tokenLine, tokenColumn)) return undefined;
      continue;
    }
    if (/\d/u.test(character)) {
      const tokenLine = line;
      const tokenColumn = column;
      let cursor = index + 1;
      while (/[\d._]/u.test(source[cursor] ?? "")) cursor += 1;
      const value = source.slice(index, cursor);
      consume(cursor - index);
      if (!add("number", value, tokenLine, tokenColumn)) return undefined;
      continue;
    }

    const tokenLine = line;
    const tokenColumn = column;
    const operator =
      [
        "?.",
        "?:",
        "::",
        "!!",
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "+=",
        "-=",
        "*=",
        "/=",
        "->",
      ]
        .sort((left, right) => right.length - left.length)
        .find((value) => source.startsWith(value, index)) ?? character;
    consume(operator.length);
    if (["(", "[", "{"].includes(operator)) {
      delimiters.push(operator);
      if (delimiters.length > MAX_KOTLIN_NESTING) return undefined;
    } else if ([")", "]", "}"].includes(operator)) {
      const expected = new Map([
        [")", "("],
        ["]", "["],
        ["}", "{"],
      ]).get(operator);
      if (delimiters.pop() !== expected) return undefined;
    }
    if (!add("symbol", operator, tokenLine, tokenColumn)) return undefined;
  }
  return delimiters.length === 0 ? tokens : undefined;
}

function compact(tokens: readonly KotlinToken[]): string {
  return tokens
    .filter(({ kind }) => kind !== "newline")
    .map(({ value }) => value)
    .join("");
}

function matchingDelimiter(
  tokens: readonly KotlinToken[],
  openIndex: number,
): number | undefined {
  const opening = tokens[openIndex]?.value;
  const closing = new Map([
    ["(", ")"],
    ["[", "]"],
    ["{", "}"],
  ]).get(opening ?? "");
  if (closing === undefined) return undefined;
  let depth = 0;
  for (let index = openIndex; index < tokens.length; index += 1) {
    if (tokens[index]?.value === opening) depth += 1;
    if (tokens[index]?.value === closing) depth -= 1;
    if (depth === 0) return index;
  }
  return undefined;
}

function splitArguments(tokens: readonly KotlinToken[]): KotlinToken[][] {
  const arguments_: KotlinToken[][] = [];
  let current: KotlinToken[] = [];
  let depth = 0;
  for (const token of tokens) {
    if (["(", "[", "{"].includes(token.value)) depth += 1;
    if ([")", "]", "}"].includes(token.value)) depth -= 1;
    if (token.value === "," && depth === 0) {
      arguments_.push(current.filter(({ kind }) => kind !== "newline"));
      current = [];
    } else {
      current.push(token);
    }
  }
  const final = current.filter(({ kind }) => kind !== "newline");
  if (final.length > 0) arguments_.push(final);
  return arguments_;
}

function statementTokens(tokens: readonly KotlinToken[]): KotlinToken[][] {
  const statements: KotlinToken[][] = [];
  let current: KotlinToken[] = [];
  let expressionDepth = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token === undefined) continue;
    if (["(", "["].includes(token.value)) expressionDepth += 1;
    if ([")", "]"].includes(token.value)) expressionDepth -= 1;
    const next = tokens.slice(index + 1).find(({ kind }) => kind !== "newline");
    const continuedChain =
      token.kind === "newline" &&
      (new Set([".", "?."]).has(next?.value ?? "") ||
        new Set([".", "?."]).has(current.at(-1)?.value ?? ""));
    if (
      (token.value === ";" || (token.kind === "newline" && !continuedChain)) &&
      expressionDepth === 0
    ) {
      if (current.length > 0) statements.push(current);
      current = [];
    } else {
      current.push(token);
    }
  }
  if (current.length > 0) statements.push(current);
  return statements;
}

function routeScopes(tokens: readonly KotlinToken[]): KotlinToken[][] {
  const scopes: KotlinToken[][] = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token?.kind !== "identifier" || !ROUTE_METHODS.has(token.value))
      continue;
    if (tokens[index - 1]?.value === ".") continue;
    let braceIndex = index + 1;
    if (tokens[braceIndex]?.value === "(") {
      const close = matchingDelimiter(tokens, braceIndex);
      if (close === undefined) continue;
      braceIndex = close + 1;
    }
    while (tokens[braceIndex]?.kind === "newline") braceIndex += 1;
    if (tokens[braceIndex]?.value !== "{") continue;
    const close = matchingDelimiter(tokens, braceIndex);
    if (close === undefined) continue;
    scopes.push(tokens.slice(braceIndex + 1, close));
  }
  return scopes;
}

function sourceFromExpression(
  tokens: readonly KotlinToken[],
): KotlinSource | undefined {
  const text = compact(tokens);
  const keyedSources: Array<{
    expression: RegExp;
    kind: KotlinSource["kind"];
    prefix: string;
  }> = [
    {
      expression: /call\.request\.queryParameters\[([^\]]+)\]/u,
      kind: "ktor-query-parameter",
      prefix: "call.request.queryParameters",
    },
    {
      expression: /call\.parameters\[([^\]]+)\]/u,
      kind: "ktor-path-parameter",
      prefix: "call.parameters",
    },
    {
      expression: /call\.request\.headers\[([^\]]+)\]/u,
      kind: "ktor-header",
      prefix: "call.request.headers",
    },
  ];
  for (const source of keyedSources) {
    const match = source.expression.exec(text);
    if (match !== null) {
      return {
        kind: source.kind,
        line:
          tokens.find(({ value }) => value === "call")?.line ??
          tokens[0]?.line ??
          1,
        symbol: `${source.prefix}[${match[1] ?? "unknown"}]`,
      };
    }
  }
  if (/call\.request\.queryString\(\)/u.test(text)) {
    return {
      kind: "ktor-query-string",
      line:
        tokens.find(({ value }) => value === "call")?.line ??
        tokens[0]?.line ??
        1,
      symbol: "call.request.queryString()",
    };
  }
  if (
    /call\.receiveText\(\)|call\.receive(?:Nullable)?<[^>]+>\(\)/u.test(text)
  ) {
    return {
      kind: "ktor-request-body",
      line:
        tokens.find(({ value }) => value === "call")?.line ??
        tokens[0]?.line ??
        1,
      symbol: /receiveText/u.test(text)
        ? "call.receiveText()"
        : "call.receive<T>()",
    };
  }
  return undefined;
}

function expressionTaint(
  tokens: readonly KotlinToken[],
  taints: ReadonlyMap<string, KotlinTaint>,
): KotlinTaint | undefined {
  const text = compact(tokens);
  if (
    /\.(?:toByte|toDouble|toFloat|toInt|toLong|toShort|toUByte|toUInt|toULong|toUShort)(?:OrNull)?\(\)/u.test(
      text,
    )
  ) {
    return undefined;
  }
  const direct = sourceFromExpression(tokens);
  let taint: KotlinTaint | undefined =
    direct === undefined
      ? undefined
      : { source: direct, propagators: [], controls: [] };
  if (taint === undefined) {
    for (const token of tokens) {
      const names = token.kind === "string" ? token.references : [token.value];
      for (const name of names) {
        const candidate = taints.get(name);
        if (candidate !== undefined) {
          taint = {
            source: candidate.source,
            propagators: [...candidate.propagators],
            controls: [...candidate.controls],
          };
          break;
        }
      }
      if (taint !== undefined) break;
    }
  }
  if (taint === undefined) return undefined;
  const interpolation = tokens.find(
    ({ kind, references }) => kind === "string" && references.length > 0,
  );
  if (interpolation !== undefined) {
    taint.propagators.push({
      kind: "kotlin-string-interpolation",
      line: interpolation.line,
    });
  }
  const concatenation = tokens.find(({ value }) => value === "+");
  if (concatenation !== undefined) {
    taint.propagators.push({
      kind: "kotlin-string-concatenation",
      line: concatenation.line,
    });
  }
  const validation = tokens.find(
    (token, index) =>
      new Set(["matches", "contains", "in"]).has(token.value) ||
      (token.value === "Regex" && tokens[index + 1]?.value === "("),
  );
  if (validation !== undefined) {
    taint.controls.push({
      kind: "process-input-validation-candidate",
      line: validation.line,
    });
  }
  return taint;
}

function assignment(
  statement: readonly KotlinToken[],
): { name: string; expression: KotlinToken[] } | undefined {
  let index = 0;
  if (new Set(["val", "var"]).has(statement[index]?.value ?? "")) index += 1;
  const name = statement[index];
  if (name?.kind !== "identifier") return undefined;
  index += 1;
  if (statement[index]?.value === ":") {
    while (index < statement.length && statement[index]?.value !== "=")
      index += 1;
  }
  if (statement[index]?.value !== "=" || statement[index + 1] === undefined)
    return undefined;
  return { name: name.value, expression: [...statement.slice(index + 1)] };
}

function processConstructor(
  tokens: readonly KotlinToken[],
  aliases: ReadonlySet<string>,
): ProcessBuilderState | undefined {
  for (let index = 0; index < tokens.length; index += 1) {
    let openIndex: number | undefined;
    if (
      aliases.has(tokens[index]?.value ?? "") &&
      tokens[index + 1]?.value === "("
    ) {
      openIndex = index + 1;
    } else if (
      compact(tokens.slice(index, index + 6)) === "java.lang.ProcessBuilder(" &&
      tokens[index + 5]?.value === "("
    ) {
      openIndex = index + 5;
    }
    if (openIndex === undefined) continue;
    const close = matchingDelimiter(tokens, openIndex);
    if (close === undefined) return undefined;
    let arguments_ = splitArguments(tokens.slice(openIndex + 1, close));
    if (arguments_.length === 1) {
      const only = arguments_[0] ?? [];
      if (
        new Set(["arrayOf", "listOf", "mutableListOf"]).has(
          only[0]?.value ?? "",
        ) &&
        only[1]?.value === "("
      ) {
        const collectionClose = matchingDelimiter(only, 1);
        if (collectionClose === only.length - 1)
          arguments_ = splitArguments(only.slice(2, collectionClose));
      }
    }
    if (arguments_.length === 0) return undefined;
    return {
      constructorLine: tokens[index]?.line ?? 1,
      arguments: arguments_.map((argument) => ({
        tokens: argument,
        line: argument[0]?.line ?? tokens[index]?.line ?? 1,
      })),
    };
  }
  return undefined;
}

function startLine(
  tokens: readonly KotlinToken[],
  receiver?: string,
): number | undefined {
  for (let index = 0; index < tokens.length - 2; index += 1) {
    if (
      (receiver === undefined || tokens[index]?.value === receiver) &&
      tokens[index + 1]?.value === "." &&
      tokens[index + 2]?.value === "start" &&
      tokens[index + 3]?.value === "("
    ) {
      return tokens[index + 2]?.line;
    }
  }
  return undefined;
}

function literalArgument(
  tokens: readonly KotlinToken[],
  literals: ReadonlyMap<string, string>,
): string | undefined {
  const meaningful = tokens.filter(({ kind }) => kind !== "newline");
  if (
    meaningful.length === 1 &&
    meaningful[0]?.kind === "string" &&
    meaningful[0].references.length === 0
  ) {
    return meaningful[0].value;
  }
  if (meaningful.length === 1 && meaningful[0]?.kind === "identifier")
    return literals.get(meaningful[0].value);
  return undefined;
}

function executableBase(value: string): string {
  return value.split(/[\\/]/u).at(-1)?.toLowerCase() ?? value.toLowerCase();
}

function processRisk(
  state: ProcessBuilderState,
  taints: ReadonlyMap<string, KotlinTaint>,
  literals: ReadonlyMap<string, string>,
): KotlinRisk | undefined {
  const programTaint = expressionTaint(
    state.arguments[0]?.tokens ?? [],
    taints,
  );
  if (programTaint !== undefined) {
    return {
      kind: "kotlin-process-executable-selection",
      taint: programTaint,
      argumentIndex: 1,
    };
  }
  const program = literalArgument(state.arguments[0]?.tokens ?? [], literals);
  if (program === undefined) return undefined;
  const base = executableBase(program);
  const literalsByIndex = state.arguments.map(({ tokens }) =>
    literalArgument(tokens, literals),
  );
  const taintsByIndex = state.arguments.map(({ tokens }) =>
    expressionTaint(tokens, taints),
  );
  const commandAfter = (
    flags: ReadonlySet<string>,
    kind: KotlinProcessSinkKind,
  ): KotlinRisk | undefined => {
    for (let index = 1; index < state.arguments.length - 1; index += 1) {
      if (!flags.has((literalsByIndex[index] ?? "").toLowerCase())) continue;
      const taint = taintsByIndex[index + 1];
      if (taint !== undefined) return { kind, taint, argumentIndex: index + 2 };
    }
    return undefined;
  };
  if (POSIX_SHELLS.has(base)) {
    const risk = commandAfter(new Set(["-c"]), "kotlin-process-shell-command");
    if (risk !== undefined) return risk;
  }
  if (base === "cmd" || base === "cmd.exe") {
    const risk = commandAfter(
      new Set(["/c", "/k"]),
      "kotlin-process-shell-command",
    );
    if (risk !== undefined) return risk;
  }
  if (POWERSHELLS.has(base)) {
    const risk = commandAfter(
      new Set(["-c", "-command"]),
      "kotlin-process-shell-command",
    );
    if (risk !== undefined) return risk;
  }
  const interpreterFlags = INTERPRETER_FLAGS.get(base);
  if (interpreterFlags !== undefined) {
    const risk = commandAfter(
      interpreterFlags,
      "kotlin-process-interpreter-command",
    );
    if (risk !== undefined) return risk;
  }
  if (base.endsWith(".bat") || base.endsWith(".cmd")) {
    const index = taintsByIndex.findIndex(
      (taint, argumentIndex) => argumentIndex > 0 && taint !== undefined,
    );
    const taint = taintsByIndex[index];
    if (index > 0 && taint !== undefined) {
      return {
        kind: "kotlin-process-shell-command",
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
    .map((line) => boundedLine(line))
    .join("\n");
}

function productionKotlinPath(path: string): boolean {
  const normalized = path.replaceAll("\\", "/").toLowerCase();
  if (!normalized.endsWith(".kt")) return false;
  if (
    /(?:^|\/)(?:build|examples|fixtures|generated|out|test|tests)(?:\/|$)/u.test(
      normalized,
    )
  )
    return false;
  return !/(?:test|spec)\.kt$/u.test(normalized);
}

function recordForRisk(
  path: string,
  lines: readonly string[],
  executionLine: number,
  risk: KotlinRisk,
): KotlinKtorCommandInjectionRecord {
  const startLine_ = Math.max(1, executionLine - CONTEXT_LINES_BEFORE);
  const endLine = Math.min(lines.length, executionLine + CONTEXT_LINES_AFTER);
  const sourceStart = Math.max(1, risk.taint.source.line - 1);
  const sourceEnd = Math.min(lines.length, risk.taint.source.line + 1);
  const candidateControls = risk.taint.controls
    .filter(
      (control, index, all) =>
        all.findIndex(
          (candidate) =>
            candidate.kind === control.kind && candidate.line === control.line,
        ) === index,
    )
    .slice(0, 8);
  return {
    path,
    line: executionLine,
    categories: ["kotlin-ktor-command-injection"],
    priority: 10,
    startLine: startLine_,
    endLine,
    excerpt: excerpt(lines, startLine_, endLine),
    sourceExcerpt: excerpt(lines, sourceStart, sourceEnd),
    frameworkModel: {
      schemaVersion: "1.2",
      id: "kotlin-ktor-command-injection",
      language: "kotlin",
      scope: "same-file",
      source: { ...risk.taint.source, path },
      sink: {
        kind: risk.kind,
        path,
        line: executionLine,
        symbol: `java.lang.ProcessBuilder;method=start;argument=${risk.argumentIndex}`,
        cweIds: ["CWE-78", "CWE-88"],
      },
      propagators: risk.taint.propagators.map((propagator) => ({
        ...propagator,
        path,
      })),
      candidateControls: candidateControls.map((control) => ({
        ...control,
        path,
      })),
    },
  };
}

export function kotlinKtorCommandInjectionRecords(
  path: string,
  lines: readonly string[],
  text: string,
): KotlinKtorCommandInjectionRecord[] {
  if (!productionKotlinPath(path)) return [];
  if (
    !/^\s*import\s+io\.ktor\.server\.routing\.(?:\*|delete|get|head|options|patch|post|put)\s*$/mu.test(
      text,
    )
  ) {
    return [];
  }
  const aliases = new Set<string>();
  for (const match of text.matchAll(
    /^\s*import\s+java\.lang\.ProcessBuilder(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*$/gmu,
  )) {
    aliases.add(match[1] ?? "ProcessBuilder");
  }
  const fullyQualified = /\bjava\.lang\.ProcessBuilder\s*\(/u.test(text);
  if (aliases.size === 0 && !fullyQualified) return [];
  for (const alias of aliases) {
    if (
      new RegExp(
        `\\b(?:class|interface|object|typealias)\\s+${alias}\\b`,
        "u",
      ).test(text)
    )
      return [];
  }
  const tokens = kotlinTokens(text);
  if (tokens === undefined) return [];
  const records: KotlinKtorCommandInjectionRecord[] = [];
  for (const scope of routeScopes(tokens)) {
    const taints = new Map<string, KotlinTaint>();
    const literals = new Map<string, string>();
    const builders = new Map<string, ProcessBuilderState>();
    for (const statement of statementTokens(scope)) {
      const assigned = assignment(statement);
      const constructor = processConstructor(statement, aliases);
      const directStart =
        constructor === undefined ? undefined : startLine(statement);
      if (constructor !== undefined && directStart !== undefined) {
        const risk = processRisk(constructor, taints, literals);
        if (risk !== undefined)
          records.push(recordForRisk(path, lines, directStart, risk));
      }
      if (assigned !== undefined && constructor !== undefined) {
        if (directStart === undefined) builders.set(assigned.name, constructor);
        else builders.delete(assigned.name);
        taints.delete(assigned.name);
        literals.delete(assigned.name);
      } else if (assigned !== undefined) {
        builders.delete(assigned.name);
        const taint = expressionTaint(assigned.expression, taints);
        if (taint === undefined) taints.delete(assigned.name);
        else {
          taints.set(assigned.name, {
            source: taint.source,
            propagators: [
              ...taint.propagators,
              {
                kind: "kotlin-local-assignment",
                line: statement[0]?.line ?? taint.source.line,
                symbol: assigned.name,
              },
            ],
            controls: [...taint.controls],
          });
        }
        const literal = literalArgument(assigned.expression, literals);
        if (literal === undefined) literals.delete(assigned.name);
        else literals.set(assigned.name, literal);
      }
      for (const [name, state] of builders) {
        const line = startLine(statement, name);
        if (line === undefined) continue;
        const risk = processRisk(state, taints, literals);
        if (risk !== undefined)
          records.push(recordForRisk(path, lines, line, risk));
      }
      if (records.length >= MAX_RECORDS) return records;
    }
  }
  return records;
}
