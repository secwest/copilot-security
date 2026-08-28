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
    | "ktor-request-body"
    | "ktor-typed-resource";
  line: number;
  symbol: string;
}

interface KotlinPropagator {
  kind:
    | "kotlin-command-list-mutation"
    | "kotlin-local-assignment"
    | "kotlin-process-builder-factory"
    | "kotlin-process-command-helper"
    | "kotlin-process-delegated-launcher"
    | "kotlin-process-helper-call"
    | "kotlin-process-pipeline-assembly"
    | "kotlin-process-pipeline-list-mutation"
    | "kotlin-process-command-replacement"
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
  mutationLine?: number;
  resolvedTaint?: KotlinTaint;
}

interface ProcessBuilderState {
  arguments: ProcessArgument[];
  commandSetLine?: number;
  commandHelperPropagators?: KotlinPropagator[];
  constructorLine: number;
  factoryPropagators?: KotlinPropagator[];
}

interface KotlinFunctionParameter {
  name: string;
  type: KotlinToken[];
}

interface KotlinTopLevelFunction {
  body: KotlinToken[];
  bodyKind: "block" | "expression";
  line: number;
  name: string;
  parameters: KotlinFunctionParameter[];
  returnType?: KotlinToken[];
}

interface ProcessBuilderFactorySummary {
  name: string;
  parameters: string[];
  state: ProcessBuilderState;
}

interface ProcessCommandHelperSummary {
  builderParameterIndex: number;
  name: string;
  parameters: string[];
  replacement: CommandReplacement;
}

interface KotlinProcessHelperSummaries {
  commandHelpers: ReadonlyMap<string, ProcessCommandHelperSummary>;
  factories: ReadonlyMap<string, ProcessBuilderFactorySummary>;
}

interface ProcessPipelineInvocation {
  builders: ProcessBuilderState[];
  line: number;
}

interface ProcessBuilderListMutation {
  builder?: ProcessBuilderState;
  index?: number;
  kind: "append" | "clear" | "insert" | "remove" | "set";
  line: number;
}

interface CommandReplacement {
  arguments: ProcessArgument[];
  line: number;
}

interface CommandListMutation {
  argument?: ProcessArgument;
  index?: number;
  kind: "append" | "clear" | "insert" | "remove" | "set";
  line: number;
}

interface KotlinRouteScope {
  body: KotlinToken[];
  resourceSource?: KotlinSource;
}

type KotlinProcessSinkKind =
  | "kotlin-process-executable-selection"
  | "kotlin-process-interpreter-command"
  | "kotlin-process-split-command"
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

function topLevelFunctions(
  tokens: readonly KotlinToken[],
): KotlinTopLevelFunction[] {
  const functions: KotlinTopLevelFunction[] = [];
  let braceDepth = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token?.value === "{") braceDepth += 1;
    if (token?.value === "}") braceDepth -= 1;
    if (braceDepth !== 0 || token?.value !== "fun") continue;

    let cursor = index + 1;
    while (tokens[cursor]?.kind === "newline") cursor += 1;
    const name = tokens[cursor];
    if (name?.kind !== "identifier" || tokens[cursor + 1]?.value !== "(")
      continue;
    const parameterClose = matchingDelimiter(tokens, cursor + 1);
    if (parameterClose === undefined) continue;
    const parameters: KotlinFunctionParameter[] = [];
    let validParameters = true;
    for (const parameterTokens of splitArguments(
      tokens.slice(cursor + 2, parameterClose),
    )) {
      const meaningful = meaningfulTokens(parameterTokens);
      const colon = meaningful.findIndex(({ value }) => value === ":");
      if (
        colon !== 1 ||
        meaningful[0]?.kind !== "identifier" ||
        meaningful.slice(colon + 1).length === 0 ||
        meaningful.some(({ value }) => value === "=")
      ) {
        validParameters = false;
        break;
      }
      parameters.push({
        name: meaningful[0].value,
        type: meaningful.slice(colon + 1),
      });
    }
    if (!validParameters) continue;

    cursor = parameterClose + 1;
    while (tokens[cursor]?.kind === "newline") cursor += 1;
    let returnType: KotlinToken[] | undefined;
    if (tokens[cursor]?.value === ":") {
      const start = cursor + 1;
      cursor = start;
      while (
        cursor < tokens.length &&
        !new Set(["=", "{"]).has(tokens[cursor]?.value ?? "")
      ) {
        cursor += 1;
      }
      returnType = meaningfulTokens(tokens.slice(start, cursor));
      if (returnType.length === 0) continue;
    }
    while (tokens[cursor]?.kind === "newline") cursor += 1;
    if (tokens[cursor]?.value === "{") {
      const bodyClose = matchingDelimiter(tokens, cursor);
      if (bodyClose === undefined) continue;
      functions.push({
        body: [...tokens.slice(cursor + 1, bodyClose)],
        bodyKind: "block",
        line: token.line,
        name: name.value,
        parameters,
        ...(returnType === undefined ? {} : { returnType }),
      });
      index = bodyClose;
      continue;
    }
    if (tokens[cursor]?.value !== "=") continue;
    const body: KotlinToken[] = [];
    let expressionDepth = 0;
    for (cursor += 1; cursor < tokens.length; cursor += 1) {
      const current = tokens[cursor];
      if (current === undefined) break;
      if (["(", "["].includes(current.value)) expressionDepth += 1;
      if ([")", "]"].includes(current.value)) expressionDepth -= 1;
      const next = tokens
        .slice(cursor + 1)
        .find(({ kind }) => kind !== "newline");
      const continuedChain =
        current.kind === "newline" &&
        (new Set([".", "?."]).has(next?.value ?? "") ||
          new Set([".", "?."]).has(body.at(-1)?.value ?? ""));
      if (
        expressionDepth === 0 &&
        (current.value === ";" ||
          (current.kind === "newline" &&
            body.some(({ kind }) => kind !== "newline") &&
            !continuedChain))
      ) {
        break;
      }
      if (current.value === "{") {
        body.length = 0;
        break;
      }
      body.push(current);
    }
    const expression = meaningfulTokens(body);
    if (expression.length === 0) continue;
    functions.push({
      body: expression,
      bodyKind: "expression",
      line: token.line,
      name: name.value,
      parameters,
      ...(returnType === undefined ? {} : { returnType }),
    });
    index = Math.max(index, cursor - 1);
  }
  return functions;
}

function routeScopes(
  tokens: readonly KotlinToken[],
  typedResourceTypes: ReadonlySet<string>,
  hasTypedResourceRoutes: boolean,
): KotlinRouteScope[] {
  const scopes: KotlinRouteScope[] = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token?.kind !== "identifier" || !ROUTE_METHODS.has(token.value))
      continue;
    if (tokens[index - 1]?.value === ".") continue;
    let braceIndex = index + 1;
    while (tokens[braceIndex]?.kind === "newline") braceIndex += 1;
    let resourceType: string | undefined;
    if (hasTypedResourceRoutes && tokens[braceIndex]?.value === "<") {
      let depth = 0;
      let closeIndex: number | undefined;
      for (
        let cursor = braceIndex;
        cursor < Math.min(tokens.length, braceIndex + 32);
        cursor += 1
      ) {
        if (tokens[cursor]?.value === "<") depth += 1;
        if (tokens[cursor]?.value === ">") depth -= 1;
        if (depth === 0) {
          closeIndex = cursor;
          break;
        }
      }
      if (closeIndex === undefined) continue;
      const declaredType = compact(tokens.slice(braceIndex + 1, closeIndex));
      const simpleType = declaredType.split(".").at(-1);
      if (
        simpleType === undefined ||
        !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(simpleType) ||
        !typedResourceTypes.has(simpleType)
      ) {
        continue;
      }
      resourceType = simpleType;
      braceIndex = closeIndex + 1;
      while (tokens[braceIndex]?.kind === "newline") braceIndex += 1;
    }
    if (tokens[braceIndex]?.value === "(") {
      const close = matchingDelimiter(tokens, braceIndex);
      if (close === undefined) continue;
      braceIndex = close + 1;
    }
    while (tokens[braceIndex]?.kind === "newline") braceIndex += 1;
    if (tokens[braceIndex]?.value !== "{") continue;
    const close = matchingDelimiter(tokens, braceIndex);
    if (close === undefined) continue;
    let bodyStart = braceIndex + 1;
    let parameter: KotlinToken | undefined;
    if (resourceType !== undefined) {
      let prefixStart = bodyStart;
      while (tokens[prefixStart]?.kind === "newline") prefixStart += 1;
      const prefixLimit = Math.min(close, prefixStart + 16);
      for (let cursor = prefixStart; cursor < prefixLimit; cursor += 1) {
        if (tokens[cursor]?.kind === "newline") break;
        if (tokens[cursor]?.value !== "->") continue;
        parameter = tokens
          .slice(prefixStart, cursor)
          .find(({ kind }) => kind === "identifier");
        if (parameter === undefined) break;
        bodyStart = cursor + 1;
        break;
      }
      parameter ??= {
        kind: "identifier",
        value: "it",
        line: token.line,
        column: token.column,
        references: [],
      };
    }
    scopes.push({
      body: tokens.slice(bodyStart, close),
      resourceSource:
        resourceType === undefined || parameter === undefined
          ? undefined
          : {
              kind: "ktor-typed-resource",
              line: parameter.line,
              symbol: `${parameter.value}:${resourceType}`,
            },
    });
  }
  return scopes;
}

function regexpEscape(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function typedResourceClassNames(text: string): Set<string> {
  const annotations = new Set<string>();
  for (const match of text.matchAll(
    /^\s*import\s+io\.ktor\.resources\.Resource(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*$/gmu,
  )) {
    annotations.add(match[1] ?? "Resource");
  }
  if (/\bio\.ktor\.resources\.Resource\b/u.test(text))
    annotations.add("io.ktor.resources.Resource");
  const types = new Set<string>();
  for (const annotation of annotations) {
    const expression = new RegExp(
      `@${regexpEscape(annotation)}\\b(?:\\s*\\([^)]*\\))?\\s*(?:(?:public|internal|private|protected|data|value|sealed)\\s+)*class\\s+([A-Za-z_][A-Za-z0-9_]*)\\b`,
      "gu",
    );
    for (const match of text.matchAll(expression)) {
      const name = match[1];
      if (name !== undefined) types.add(name);
    }
  }
  return types;
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

function processArguments(
  tokens: readonly KotlinToken[],
  fallbackLine: number,
  commandLists?: ReadonlyMap<string, ProcessArgument[]>,
): ProcessArgument[] | undefined {
  let arguments_ = splitArguments(tokens);
  if (arguments_.length === 1) {
    const only = arguments_[0] ?? [];
    if (only.length === 1 && only[0]?.kind === "identifier") {
      const referenced = commandLists?.get(only[0].value);
      if (referenced !== undefined) return referenced;
    }
    if (
      new Set(["arrayListOf", "arrayOf", "listOf", "mutableListOf"]).has(
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
  return arguments_.map((argument) => ({
    tokens: argument,
    line: argument[0]?.line ?? fallbackLine,
  }));
}

function commandReplacement(
  tokens: readonly KotlinToken[],
  receiver?: string,
  commandLists?: ReadonlyMap<string, ProcessArgument[]>,
): CommandReplacement | undefined {
  let replacement: CommandReplacement | undefined;
  for (let index = 0; index < tokens.length - 3; index += 1) {
    const methodIndex = receiver === undefined ? index + 1 : index + 2;
    if (
      (receiver === undefined
        ? tokens[index]?.value === "."
        : tokens[index]?.value === receiver &&
          tokens[index + 1]?.value === ".") &&
      tokens[methodIndex]?.value === "command" &&
      tokens[methodIndex + 1]?.value === "("
    ) {
      const close = matchingDelimiter(tokens, methodIndex + 1);
      if (close === undefined) continue;
      const arguments_ = processArguments(
        tokens.slice(methodIndex + 2, close),
        tokens[methodIndex]?.line ?? 1,
        commandLists,
      );
      if (arguments_ !== undefined) {
        replacement = {
          arguments: arguments_,
          line: tokens[methodIndex]?.line ?? 1,
        };
      }
    }
  }
  return replacement;
}

function meaningfulTokens(tokens: readonly KotlinToken[]): KotlinToken[] {
  return tokens.filter(({ kind }) => kind !== "newline");
}

function commandListExpression(
  tokens: readonly KotlinToken[],
  builders: ReadonlyMap<string, ProcessBuilderState>,
  commandLists: ReadonlyMap<string, ProcessArgument[]>,
): ProcessArgument[] | undefined {
  const meaningful = meaningfulTokens(tokens);
  if (meaningful.length === 1 && meaningful[0]?.kind === "identifier") {
    return commandLists.get(meaningful[0].value);
  }
  if (
    meaningful.length === 5 &&
    meaningful[0]?.kind === "identifier" &&
    meaningful[1]?.value === "." &&
    meaningful[2]?.value === "command" &&
    meaningful[3]?.value === "(" &&
    meaningful[4]?.value === ")"
  ) {
    return builders.get(meaningful[0].value)?.arguments;
  }
  if (
    new Set(["arrayListOf", "arrayOf", "listOf", "mutableListOf"]).has(
      meaningful[0]?.value ?? "",
    ) &&
    meaningful[1]?.value === "(" &&
    matchingDelimiter(meaningful, 1) === meaningful.length - 1
  ) {
    return processArguments(meaningful, meaningful[0]?.line ?? 1, commandLists);
  }
  return undefined;
}

function builderExpression(
  tokens: readonly KotlinToken[],
  builders: ReadonlyMap<string, ProcessBuilderState>,
): ProcessBuilderState | undefined {
  const meaningful = meaningfulTokens(tokens);
  if (meaningful.length !== 1 || meaningful[0]?.kind !== "identifier")
    return undefined;
  return builders.get(meaningful[0].value);
}

function exactBuilderExpression(
  tokens: readonly KotlinToken[],
  aliases: ReadonlySet<string>,
  builders: ReadonlyMap<string, ProcessBuilderState>,
  commandLists: ReadonlyMap<string, ProcessArgument[]>,
): ProcessBuilderState | undefined {
  const meaningful = meaningfulTokens(tokens);
  const referenced = builderExpression(meaningful, builders);
  if (referenced !== undefined) return referenced;
  let openIndex: number | undefined;
  if (aliases.has(meaningful[0]?.value ?? "") && meaningful[1]?.value === "(") {
    openIndex = 1;
  } else if (
    compact(meaningful.slice(0, 6)) === "java.lang.ProcessBuilder(" &&
    meaningful[5]?.value === "("
  ) {
    openIndex = 5;
  }
  if (openIndex === undefined) return undefined;
  const close = matchingDelimiter(meaningful, openIndex);
  if (close === undefined) return undefined;
  const tail = meaningful.slice(close + 1);
  if (tail.length > 0) {
    if (
      tail[0]?.value !== "." ||
      tail[1]?.value !== "command" ||
      tail[2]?.value !== "("
    ) {
      return undefined;
    }
    const commandClose = matchingDelimiter(tail, 2);
    if (commandClose !== tail.length - 1) return undefined;
  }
  return processConstructor(meaningful, aliases, commandLists);
}

function builderListExpression(
  tokens: readonly KotlinToken[],
  aliases: ReadonlySet<string>,
  builders: ReadonlyMap<string, ProcessBuilderState>,
  builderLists: ReadonlyMap<string, ProcessBuilderState[]>,
  commandLists: ReadonlyMap<string, ProcessArgument[]>,
): ProcessBuilderState[] | undefined {
  const meaningful = meaningfulTokens(tokens);
  if (meaningful.length === 1 && meaningful[0]?.kind === "identifier") {
    return builderLists.get(meaningful[0].value);
  }
  if (
    !new Set(["arrayListOf", "listOf", "mutableListOf"]).has(
      meaningful[0]?.value ?? "",
    ) ||
    meaningful[1]?.value !== "(" ||
    matchingDelimiter(meaningful, 1) !== meaningful.length - 1
  ) {
    return undefined;
  }
  const elements = splitArguments(meaningful.slice(2, -1));
  const result: ProcessBuilderState[] = [];
  for (const element of elements) {
    const builder = exactBuilderExpression(
      element,
      aliases,
      builders,
      commandLists,
    );
    if (builder === undefined) return undefined;
    result.push(builder);
  }
  return result;
}

function builderListMutation(
  tokens: readonly KotlinToken[],
  receiver: string,
  aliases: ReadonlySet<string>,
  builders: ReadonlyMap<string, ProcessBuilderState>,
  commandLists: ReadonlyMap<string, ProcessArgument[]>,
): ProcessBuilderListMutation | undefined {
  const meaningful = meaningfulTokens(tokens);
  if (meaningful[0]?.value !== receiver) return undefined;
  const suffix = meaningful.slice(1);
  if (suffix[0]?.value === "[") {
    const close = matchingDelimiter(suffix, 0);
    if (
      close === undefined ||
      suffix[close + 1]?.value !== "=" ||
      suffix[close + 2] === undefined
    ) {
      return undefined;
    }
    const index = commandIndex(suffix.slice(1, close));
    const builder = exactBuilderExpression(
      suffix.slice(close + 2),
      aliases,
      builders,
      commandLists,
    );
    const line = suffix[close + 1]?.line ?? suffix[0]?.line ?? 1;
    return index === undefined || builder === undefined
      ? undefined
      : { builder, index, kind: "set", line };
  }
  if (
    suffix[0]?.value !== "." ||
    suffix[1]?.kind !== "identifier" ||
    suffix[2]?.value !== "("
  ) {
    return undefined;
  }
  const close = matchingDelimiter(suffix, 2);
  if (close === undefined || close !== suffix.length - 1) return undefined;
  const method = suffix[1].value;
  const arguments_ = splitArguments(suffix.slice(3, close));
  const line = suffix[1].line;
  if (method === "clear" && arguments_.length === 0)
    return { kind: "clear", line };
  if (method === "removeAt" && arguments_.length === 1) {
    const index = commandIndex(arguments_[0] ?? []);
    return index === undefined ? undefined : { index, kind: "remove", line };
  }
  if (method === "set" && arguments_.length === 2) {
    const index = commandIndex(arguments_[0] ?? []);
    const builder = exactBuilderExpression(
      arguments_[1] ?? [],
      aliases,
      builders,
      commandLists,
    );
    return index === undefined || builder === undefined
      ? undefined
      : { builder, index, kind: "set", line };
  }
  if (method === "add" && arguments_.length === 1) {
    const builder = exactBuilderExpression(
      arguments_[0] ?? [],
      aliases,
      builders,
      commandLists,
    );
    return builder === undefined
      ? undefined
      : { builder, kind: "append", line };
  }
  if (method === "add" && arguments_.length === 2) {
    const index = commandIndex(arguments_[0] ?? []);
    const builder = exactBuilderExpression(
      arguments_[1] ?? [],
      aliases,
      builders,
      commandLists,
    );
    return index === undefined || builder === undefined
      ? undefined
      : { builder, index, kind: "insert", line };
  }
  return undefined;
}

function applyBuilderListMutation(
  builders: ProcessBuilderState[],
  mutation: ProcessBuilderListMutation,
  mutationLines: WeakMap<
    ProcessBuilderState[],
    Map<ProcessBuilderState, number>
  >,
): boolean {
  const recordMutation = (builder: ProcessBuilderState): void => {
    let lines = mutationLines.get(builders);
    if (lines === undefined) {
      lines = new Map<ProcessBuilderState, number>();
      mutationLines.set(builders, lines);
    }
    lines.set(builder, mutation.line);
  };
  if (mutation.kind === "clear") {
    builders.splice(0, builders.length);
    mutationLines.get(builders)?.clear();
    return true;
  }
  if (mutation.kind === "append" && mutation.builder !== undefined) {
    builders.push(mutation.builder);
    recordMutation(mutation.builder);
    return true;
  }
  if (
    mutation.kind === "insert" &&
    mutation.builder !== undefined &&
    mutation.index !== undefined &&
    mutation.index <= builders.length
  ) {
    builders.splice(mutation.index, 0, mutation.builder);
    recordMutation(mutation.builder);
    return true;
  }
  if (
    mutation.kind === "remove" &&
    mutation.index !== undefined &&
    mutation.index < builders.length
  ) {
    builders.splice(mutation.index, 1);
    return true;
  }
  if (
    mutation.kind === "set" &&
    mutation.builder !== undefined &&
    mutation.index !== undefined &&
    mutation.index < builders.length
  ) {
    builders[mutation.index] = mutation.builder;
    recordMutation(mutation.builder);
    return true;
  }
  return false;
}

function commandIndex(tokens: readonly KotlinToken[]): number | undefined {
  const meaningful = meaningfulTokens(tokens);
  if (meaningful.length !== 1 || meaningful[0]?.kind !== "number")
    return undefined;
  const normalized = meaningful[0].value.replaceAll("_", "");
  if (!/^(?:0|[1-9][0-9]*)$/u.test(normalized)) return undefined;
  const index = Number(normalized);
  return Number.isSafeInteger(index) && index <= MAX_KOTLIN_TOKENS
    ? index
    : undefined;
}

function mutatedArgument(
  tokens: readonly KotlinToken[],
  mutationLine: number,
): ProcessArgument | undefined {
  const meaningful = meaningfulTokens(tokens);
  if (meaningful.length === 0) return undefined;
  return {
    tokens: meaningful,
    line: meaningful[0]?.line ?? mutationLine,
    mutationLine,
  };
}

function mutationAfterPrefix(
  tokens: readonly KotlinToken[],
  prefixLength: number,
): CommandListMutation | undefined {
  const suffix = tokens.slice(prefixLength);
  if (suffix[0]?.value === "[") {
    const close = matchingDelimiter(suffix, 0);
    if (
      close === undefined ||
      suffix[close + 1]?.value !== "=" ||
      suffix[close + 2] === undefined
    ) {
      return undefined;
    }
    const index = commandIndex(suffix.slice(1, close));
    const mutationLine = suffix[close + 1]?.line ?? suffix[0]?.line ?? 1;
    const argument = mutatedArgument(suffix.slice(close + 2), mutationLine);
    return index === undefined || argument === undefined
      ? undefined
      : { argument, index, kind: "set", line: mutationLine };
  }
  if (
    suffix[0]?.value !== "." ||
    suffix[1]?.kind !== "identifier" ||
    suffix[2]?.value !== "("
  ) {
    return undefined;
  }
  const close = matchingDelimiter(suffix, 2);
  if (close === undefined || close !== suffix.length - 1) return undefined;
  const method = suffix[1].value;
  const arguments_ = splitArguments(suffix.slice(3, close));
  const mutationLine = suffix[1].line;
  if (method === "clear" && arguments_.length === 0)
    return { kind: "clear", line: mutationLine };
  if (method === "removeAt" && arguments_.length === 1) {
    const index = commandIndex(arguments_[0] ?? []);
    return index === undefined
      ? undefined
      : { index, kind: "remove", line: mutationLine };
  }
  if (method === "set" && arguments_.length === 2) {
    const index = commandIndex(arguments_[0] ?? []);
    const argument = mutatedArgument(arguments_[1] ?? [], mutationLine);
    return index === undefined || argument === undefined
      ? undefined
      : { argument, index, kind: "set", line: mutationLine };
  }
  if (method === "add" && arguments_.length === 1) {
    const argument = mutatedArgument(arguments_[0] ?? [], mutationLine);
    return argument === undefined
      ? undefined
      : { argument, kind: "append", line: mutationLine };
  }
  if (method === "add" && arguments_.length === 2) {
    const index = commandIndex(arguments_[0] ?? []);
    const argument = mutatedArgument(arguments_[1] ?? [], mutationLine);
    return index === undefined || argument === undefined
      ? undefined
      : { argument, index, kind: "insert", line: mutationLine };
  }
  return undefined;
}

function commandListMutation(
  tokens: readonly KotlinToken[],
  receiver: string,
): CommandListMutation | undefined {
  const meaningful = meaningfulTokens(tokens);
  if (meaningful[0]?.value !== receiver) return undefined;
  return mutationAfterPrefix(meaningful, 1);
}

function builderCommandListMutation(
  tokens: readonly KotlinToken[],
  receiver: string,
): CommandListMutation | undefined {
  const meaningful = meaningfulTokens(tokens);
  if (
    meaningful[0]?.value !== receiver ||
    meaningful[1]?.value !== "." ||
    meaningful[2]?.value !== "command" ||
    meaningful[3]?.value !== "(" ||
    meaningful[4]?.value !== ")"
  ) {
    return undefined;
  }
  return mutationAfterPrefix(meaningful, 5);
}

function applyCommandListMutation(
  arguments_: ProcessArgument[],
  mutation: CommandListMutation,
): boolean {
  if (mutation.kind === "clear") {
    arguments_.splice(0, arguments_.length);
    return true;
  }
  if (mutation.kind === "append" && mutation.argument !== undefined) {
    arguments_.push(mutation.argument);
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
    mutation.kind === "remove" &&
    mutation.index !== undefined &&
    mutation.index < arguments_.length
  ) {
    arguments_.splice(mutation.index, 1);
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
    return true;
  }
  return false;
}

function processConstructor(
  tokens: readonly KotlinToken[],
  aliases: ReadonlySet<string>,
  commandLists: ReadonlyMap<string, ProcessArgument[]>,
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
    const initial = processArguments(
      tokens.slice(openIndex + 1, close),
      tokens[index]?.line ?? 1,
      commandLists,
    );
    if (initial === undefined) return undefined;
    const replacement = commandReplacement(
      tokens.slice(close + 1),
      undefined,
      commandLists,
    );
    return {
      constructorLine: tokens[index]?.line ?? 1,
      arguments: replacement?.arguments ?? initial,
      ...(replacement === undefined
        ? {}
        : { commandSetLine: replacement.line }),
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

function pipelineInvocation(
  tokens: readonly KotlinToken[],
  aliases: ReadonlySet<string>,
  builders: ReadonlyMap<string, ProcessBuilderState>,
  builderLists: ReadonlyMap<string, ProcessBuilderState[]>,
  commandLists: ReadonlyMap<string, ProcessArgument[]>,
): ProcessPipelineInvocation | undefined {
  for (let index = 0; index < tokens.length - 2; index += 1) {
    if (
      tokens[index]?.value !== "startPipeline" ||
      tokens[index + 1]?.value !== "("
    ) {
      continue;
    }
    const aliasReceiver =
      tokens[index - 1]?.value === "." &&
      aliases.has(tokens[index - 2]?.value ?? "");
    const qualifiedReceiver =
      compact(tokens.slice(Math.max(0, index - 6), index)) ===
      "java.lang.ProcessBuilder.";
    if (!aliasReceiver && !qualifiedReceiver) continue;
    const close = matchingDelimiter(tokens, index + 1);
    if (close === undefined) continue;
    const arguments_ = splitArguments(tokens.slice(index + 2, close));
    if (arguments_.length !== 1) continue;
    const pipelineBuilders = builderListExpression(
      arguments_[0] ?? [],
      aliases,
      builders,
      builderLists,
      commandLists,
    );
    if (pipelineBuilders !== undefined)
      return { builders: pipelineBuilders, line: tokens[index]?.line ?? 1 };
  }
  return undefined;
}

function processBuilderType(
  tokens: readonly KotlinToken[],
  aliases: ReadonlySet<string>,
): boolean {
  const type = compact(tokens);
  return aliases.has(type) || type === "java.lang.ProcessBuilder";
}

function helperExpression(
  declaration: KotlinTopLevelFunction,
): KotlinToken[] | undefined {
  if (declaration.bodyKind === "expression") return declaration.body;
  const statements = statementTokens(declaration.body).map(meaningfulTokens);
  if (statements.length !== 1 || statements[0]?.[0]?.value !== "return")
    return undefined;
  const expression = statements[0].slice(1);
  return expression.length === 0 ? undefined : expression;
}

function processHelperSummaries(
  tokens: readonly KotlinToken[],
  aliases: ReadonlySet<string>,
): KotlinProcessHelperSummaries {
  const declarations = topLevelFunctions(tokens);
  const counts = new Map<string, number>();
  for (const declaration of declarations) {
    counts.set(declaration.name, (counts.get(declaration.name) ?? 0) + 1);
  }
  const factories = new Map<string, ProcessBuilderFactorySummary>();
  const commandHelpers = new Map<string, ProcessCommandHelperSummary>();
  const emptyBuilders = new Map<string, ProcessBuilderState>();
  const emptyCommandLists = new Map<string, ProcessArgument[]>();
  for (const declaration of declarations) {
    if (counts.get(declaration.name) !== 1) continue;
    const parameters = declaration.parameters.map(({ name }) => name);
    if (
      declaration.returnType !== undefined &&
      processBuilderType(declaration.returnType, aliases)
    ) {
      const expression = helperExpression(declaration);
      const state =
        expression === undefined
          ? undefined
          : exactBuilderExpression(
              expression,
              aliases,
              emptyBuilders,
              emptyCommandLists,
            );
      if (state !== undefined) {
        factories.set(declaration.name, {
          name: declaration.name,
          parameters,
          state,
        });
      }
    }

    if (declaration.bodyKind !== "block") continue;
    const builderParameters = declaration.parameters
      .map((parameter, index) => ({ index, parameter }))
      .filter(({ parameter }) => processBuilderType(parameter.type, aliases));
    if (builderParameters.length !== 1) continue;
    if (
      declaration.returnType !== undefined &&
      !new Set(["Unit", "kotlin.Unit"]).has(compact(declaration.returnType))
    ) {
      continue;
    }
    const statements = statementTokens(declaration.body).map(meaningfulTokens);
    if (statements.length !== 1) continue;
    const builderParameter = builderParameters[0];
    const statement = statements[0] ?? [];
    if (
      builderParameter === undefined ||
      statement[0]?.value !== builderParameter.parameter.name ||
      statement[1]?.value !== "." ||
      statement[2]?.value !== "command" ||
      statement[3]?.value !== "(" ||
      matchingDelimiter(statement, 3) !== statement.length - 1
    ) {
      continue;
    }
    const replacement = commandReplacement(
      statement,
      builderParameter.parameter.name,
      emptyCommandLists,
    );
    if (replacement === undefined) continue;
    commandHelpers.set(declaration.name, {
      builderParameterIndex: builderParameter.index,
      name: declaration.name,
      parameters,
      replacement,
    });
  }
  return { commandHelpers, factories };
}

interface KotlinHelperCall {
  arguments: KotlinToken[][];
  line: number;
  tail: KotlinToken[];
}

function helperCall(
  tokens: readonly KotlinToken[],
  name: string,
  parameterCount: number,
): KotlinHelperCall | undefined {
  const meaningful = meaningfulTokens(tokens);
  if (meaningful[0]?.value !== name || meaningful[1]?.value !== "(")
    return undefined;
  const close = matchingDelimiter(meaningful, 1);
  if (close === undefined) return undefined;
  const arguments_ = splitArguments(meaningful.slice(2, close));
  if (
    arguments_.length !== parameterCount ||
    arguments_.some((argument) =>
      meaningfulTokens(argument).some(({ value }) => value === "="),
    )
  ) {
    return undefined;
  }
  return {
    arguments: arguments_.map(meaningfulTokens),
    line: meaningful[0]?.line ?? 1,
    tail: meaningful.slice(close + 1),
  };
}

function substitutedTokens(
  tokens: readonly KotlinToken[],
  parameters: readonly string[],
  arguments_: readonly KotlinToken[][],
): KotlinToken[] {
  const argumentByParameter = new Map<string, KotlinToken[]>();
  for (let index = 0; index < parameters.length; index += 1) {
    const parameter = parameters[index];
    const argument = arguments_[index];
    if (parameter !== undefined && argument !== undefined)
      argumentByParameter.set(parameter, argument);
  }
  const result: KotlinToken[] = [];
  for (const token of tokens) {
    const direct =
      token.kind === "identifier"
        ? argumentByParameter.get(token.value)
        : undefined;
    if (direct !== undefined) {
      result.push(...direct.map((candidate) => ({ ...candidate })));
      continue;
    }
    if (token.kind !== "string" || token.references.length === 0) {
      result.push({ ...token });
      continue;
    }
    const references = token.references.flatMap((reference) => {
      const argument = argumentByParameter.get(reference);
      if (argument === undefined) return [reference];
      const names = argument.flatMap((candidate) =>
        candidate.kind === "string"
          ? candidate.references
          : candidate.kind === "identifier"
            ? [candidate.value]
            : [],
      );
      return names.length === 0 ? ["__helper_literal__"] : names;
    });
    result.push({ ...token, references: [...new Set(references)] });
  }
  return result;
}

function instantiatedProcessArguments(
  templates: readonly ProcessArgument[],
  parameters: readonly string[],
  arguments_: readonly KotlinToken[][],
  taints: ReadonlyMap<string, KotlinTaint>,
): ProcessArgument[] {
  const parameterTaints = new Map<string, KotlinTaint>();
  for (let index = 0; index < parameters.length; index += 1) {
    const parameter = parameters[index];
    const argument = arguments_[index];
    if (parameter === undefined || argument === undefined) continue;
    const taint = expressionTaint(argument, taints);
    if (taint !== undefined) parameterTaints.set(parameter, taint);
  }
  return templates.map((template) => {
    const tokens_ = substitutedTokens(template.tokens, parameters, arguments_);
    const resolvedTaint = expressionTaint(template.tokens, parameterTaints);
    return {
      ...template,
      tokens: tokens_,
      ...(resolvedTaint === undefined ? {} : { resolvedTaint }),
    };
  });
}

function factoryExpression(
  tokens: readonly KotlinToken[],
  summaries: KotlinProcessHelperSummaries,
  taints: ReadonlyMap<string, KotlinTaint>,
): ProcessBuilderState | undefined {
  const meaningful = meaningfulTokens(tokens);
  const summary = summaries.factories.get(meaningful[0]?.value ?? "");
  if (summary === undefined) return undefined;
  const call = helperCall(meaningful, summary.name, summary.parameters.length);
  if (
    call === undefined ||
    (call.tail.length > 0 && compact(call.tail) !== ".start()")
  ) {
    return undefined;
  }
  return {
    ...summary.state,
    arguments: instantiatedProcessArguments(
      summary.state.arguments,
      summary.parameters,
      call.arguments,
      taints,
    ),
    factoryPropagators: [
      {
        kind: "kotlin-process-builder-factory",
        line: summary.state.constructorLine,
        symbol: summary.name,
      },
      {
        kind: "kotlin-process-helper-call",
        line: call.line,
        symbol: summary.name,
      },
    ],
  };
}

function commandHelperInvocation(
  tokens: readonly KotlinToken[],
  summaries: KotlinProcessHelperSummaries,
  builders: ReadonlyMap<string, ProcessBuilderState>,
  taints: ReadonlyMap<string, KotlinTaint>,
):
  | {
      propagators: KotlinPropagator[];
      replacement: CommandReplacement;
      state: ProcessBuilderState;
    }
  | undefined {
  const meaningful = meaningfulTokens(tokens);
  const summary = summaries.commandHelpers.get(meaningful[0]?.value ?? "");
  if (summary === undefined) return undefined;
  const call = helperCall(meaningful, summary.name, summary.parameters.length);
  if (call === undefined || call.tail.length > 0) return undefined;
  const builderArgument = meaningfulTokens(
    call.arguments[summary.builderParameterIndex] ?? [],
  );
  if (
    builderArgument.length !== 1 ||
    builderArgument[0]?.kind !== "identifier"
  ) {
    return undefined;
  }
  const state = builders.get(builderArgument[0].value);
  if (state === undefined) return undefined;
  return {
    propagators: [
      {
        kind: "kotlin-process-command-helper",
        line: summary.replacement.line,
        symbol: summary.name,
      },
      {
        kind: "kotlin-process-helper-call",
        line: call.line,
        symbol: summary.name,
      },
    ],
    replacement: {
      arguments: instantiatedProcessArguments(
        summary.replacement.arguments,
        summary.parameters,
        call.arguments,
        taints,
      ),
      line: summary.replacement.line,
    },
    state,
  };
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

interface EnvCommandResolution {
  commandIndex?: number;
  splitStringIndex?: number;
}

function singleStringValue(
  argument: ProcessArgument | undefined,
): string | undefined {
  const meaningful = (argument?.tokens ?? []).filter(
    ({ kind }) => kind !== "newline",
  );
  return meaningful.length === 1 && meaningful[0]?.kind === "string"
    ? meaningful[0].value
    : undefined;
}

function envCommandResolution(
  state: ProcessBuilderState,
  literalsByIndex: readonly (string | undefined)[],
  taintsByIndex: readonly (KotlinTaint | undefined)[],
): EnvCommandResolution {
  const noArgumentOptions = new Set([
    "-",
    "-i",
    "-v",
    "--debug",
    "--ignore-environment",
    "--list-signal-handling",
  ]);
  const argumentOptions = new Set([
    "-a",
    "-C",
    "-u",
    "--argv0",
    "--chdir",
    "--unset",
  ]);
  const terminalOptions = new Set(["-0", "--help", "--null", "--version"]);
  const joinedArgumentPrefixes = [
    "--argv0=",
    "--block-signal=",
    "--chdir=",
    "--default-signal=",
    "--ignore-signal=",
    "--unset=",
  ] as const;
  const optionalSignalOptions = new Set([
    "--block-signal",
    "--default-signal",
    "--ignore-signal",
  ]);
  let options = true;
  for (let index = 1; index < state.arguments.length; index += 1) {
    const literal = literalsByIndex[index];
    const staticString = singleStringValue(state.arguments[index]);
    if (options) {
      if (literal === "--") {
        options = false;
        continue;
      }
      if (terminalOptions.has(literal ?? "")) return {};
      if (
        noArgumentOptions.has(literal ?? "") ||
        optionalSignalOptions.has(literal ?? "") ||
        /^-(?:i|v)+$/u.test(literal ?? "")
      ) {
        continue;
      }
      if (
        joinedArgumentPrefixes.some((prefix) =>
          (staticString ?? "").startsWith(prefix),
        ) ||
        /^-[aCu].+/u.test(staticString ?? "")
      ) {
        continue;
      }
      if (literal === "-S" || literal === "--split-string") {
        const splitStringIndex = index + 1;
        return splitStringIndex < state.arguments.length &&
          taintsByIndex[splitStringIndex] !== undefined
          ? { splitStringIndex }
          : {};
      }
      if ((staticString ?? "").startsWith("-S") && staticString !== "-S") {
        return taintsByIndex[index] === undefined
          ? {}
          : { splitStringIndex: index };
      }
      if ((staticString ?? "").startsWith("--split-string=")) {
        return taintsByIndex[index] === undefined
          ? {}
          : { splitStringIndex: index };
      }
      if (argumentOptions.has(literal ?? "")) {
        if (index + 1 >= state.arguments.length) return {};
        index += 1;
        continue;
      }
      if (literal?.startsWith("-") === true) return {};
      if (literal === undefined && taintsByIndex[index] === undefined)
        return {};
      options = false;
    }
    if (
      literal?.includes("=") === true ||
      singleStringValue(state.arguments[index])?.includes("=") === true
    ) {
      continue;
    }
    return { commandIndex: index };
  }
  return {};
}

function processRisk(
  state: ProcessBuilderState,
  taints: ReadonlyMap<string, KotlinTaint>,
  literals: ReadonlyMap<string, string>,
): KotlinRisk | undefined {
  const argumentTaint = (
    argument: ProcessArgument | undefined,
  ): KotlinTaint | undefined => {
    const taint =
      argument?.resolvedTaint ??
      expressionTaint(argument?.tokens ?? [], taints);
    if (taint === undefined) return undefined;
    const propagators = [
      ...taint.propagators,
      ...(state.factoryPropagators ?? []),
      ...(state.commandHelperPropagators ?? []),
    ];
    if (state.commandSetLine !== undefined) {
      propagators.push({
        kind: "kotlin-process-command-replacement",
        line: state.commandSetLine,
      });
    }
    if (argument?.mutationLine !== undefined) {
      propagators.push({
        kind: "kotlin-command-list-mutation",
        line: argument.mutationLine,
      });
    }
    return { ...taint, propagators };
  };
  const programTaint = argumentTaint(state.arguments[0]);
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
  const taintsByIndex = state.arguments.map((argument) =>
    argumentTaint(argument),
  );
  if (base === "env") {
    const resolution = envCommandResolution(
      state,
      literalsByIndex,
      taintsByIndex,
    );
    const delegation: KotlinPropagator = {
      kind: "kotlin-process-delegated-launcher",
      line: state.commandSetLine ?? state.constructorLine,
      symbol: "env",
    };
    if (resolution.splitStringIndex !== undefined) {
      const taint = taintsByIndex[resolution.splitStringIndex];
      if (taint !== undefined) {
        return {
          kind: "kotlin-process-split-command",
          taint: {
            ...taint,
            propagators: [...taint.propagators, delegation],
          },
          argumentIndex: resolution.splitStringIndex + 1,
        };
      }
    }
    if (resolution.commandIndex !== undefined) {
      const nestedRisk = processRisk(
        {
          ...state,
          arguments: state.arguments.slice(resolution.commandIndex),
        },
        taints,
        literals,
      );
      if (nestedRisk !== undefined) {
        return {
          ...nestedRisk,
          taint: {
            ...nestedRisk.taint,
            propagators: [...nestedRisk.taint.propagators, delegation],
          },
          argumentIndex: nestedRisk.argumentIndex + resolution.commandIndex,
        };
      }
    }
    return undefined;
  }
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
  executionMethod = "start",
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
        symbol: `java.lang.ProcessBuilder;method=${executionMethod};argument=${risk.argumentIndex}`,
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
  const hasRoutingRoutes =
    /^\s*import\s+io\.ktor\.server\.routing\.(?:\*|delete|get|head|options|patch|post|put)\s*$/mu.test(
      text,
    );
  const hasTypedResourceRoutes =
    /^\s*import\s+io\.ktor\.server\.resources\.(?:\*|delete|get|head|options|patch|post|put)\s*$/mu.test(
      text,
    );
  if (!hasRoutingRoutes && !hasTypedResourceRoutes) return [];
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
  const helperSummaries = processHelperSummaries(tokens, aliases);
  const records: KotlinKtorCommandInjectionRecord[] = [];
  const resourceTypes = typedResourceClassNames(text);
  for (const scope of routeScopes(
    tokens,
    resourceTypes,
    hasTypedResourceRoutes,
  )) {
    const taints = new Map<string, KotlinTaint>();
    if (scope.resourceSource !== undefined) {
      taints.set(scope.resourceSource.symbol.split(":", 1)[0] ?? "it", {
        source: scope.resourceSource,
        propagators: [],
        controls: [],
      });
    }
    const literals = new Map<string, string>();
    const builders = new Map<string, ProcessBuilderState>();
    const builderLists = new Map<string, ProcessBuilderState[]>();
    const builderListMutationLines = new WeakMap<
      ProcessBuilderState[],
      Map<ProcessBuilderState, number>
    >();
    const commandLists = new Map<string, ProcessArgument[]>();
    let routeAborted = false;
    for (const statement of statementTokens(scope.body)) {
      const assigned = assignment(statement);
      const assignedBuilderList =
        assigned === undefined
          ? undefined
          : builderListExpression(
              assigned.expression,
              aliases,
              builders,
              builderLists,
              commandLists,
            );
      const pipeline = pipelineInvocation(
        statement,
        aliases,
        builders,
        builderLists,
        commandLists,
      );
      const directConstructor =
        assignedBuilderList !== undefined || pipeline !== undefined
          ? undefined
          : processConstructor(
              assigned?.expression ?? statement,
              aliases,
              commandLists,
            );
      const constructor =
        directConstructor ??
        (assignedBuilderList !== undefined || pipeline !== undefined
          ? undefined
          : factoryExpression(
              assigned?.expression ?? statement,
              helperSummaries,
              taints,
            ));
      const directStart =
        constructor === undefined ? undefined : startLine(statement);
      if (constructor !== undefined && directStart !== undefined) {
        const risk = processRisk(constructor, taints, literals);
        if (risk !== undefined)
          records.push(recordForRisk(path, lines, directStart, risk));
      }
      if (assigned !== undefined) {
        const referencedBuilder =
          constructor === undefined
            ? builderExpression(assigned.expression, builders)
            : undefined;
        const referencedCommandList =
          constructor === undefined &&
          referencedBuilder === undefined &&
          assignedBuilderList === undefined
            ? commandListExpression(assigned.expression, builders, commandLists)
            : undefined;
        if (constructor !== undefined && directStart === undefined) {
          builders.set(assigned.name, constructor);
        } else if (referencedBuilder !== undefined) {
          builders.set(assigned.name, referencedBuilder);
        } else {
          builders.delete(assigned.name);
        }
        if (referencedCommandList === undefined) {
          commandLists.delete(assigned.name);
        } else {
          commandLists.set(assigned.name, referencedCommandList);
        }
        if (assignedBuilderList === undefined) {
          builderLists.delete(assigned.name);
        } else {
          builderLists.set(assigned.name, assignedBuilderList);
        }
        if (
          constructor !== undefined ||
          referencedBuilder !== undefined ||
          referencedCommandList !== undefined ||
          assignedBuilderList !== undefined
        ) {
          taints.delete(assigned.name);
          literals.delete(assigned.name);
        } else {
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
      }
      const helperInvocation = commandHelperInvocation(
        statement,
        helperSummaries,
        builders,
        taints,
      );
      if (helperInvocation !== undefined) {
        helperInvocation.state.arguments =
          helperInvocation.replacement.arguments;
        helperInvocation.state.commandSetLine =
          helperInvocation.replacement.line;
        helperInvocation.state.commandHelperPropagators =
          helperInvocation.propagators;
      }
      for (const [name, state] of builders) {
        const replacement = commandReplacement(statement, name, commandLists);
        if (replacement !== undefined) {
          state.arguments = replacement.arguments;
          state.commandSetLine = replacement.line;
          state.commandHelperPropagators = undefined;
          builders.set(name, state);
        }
        const mutation = builderCommandListMutation(statement, name);
        if (
          mutation !== undefined &&
          !applyCommandListMutation(state.arguments, mutation)
        ) {
          routeAborted = true;
          break;
        }
        const line = startLine(statement, name);
        if (line !== undefined) {
          const risk = processRisk(state, taints, literals);
          if (risk !== undefined) {
            records.push(recordForRisk(path, lines, line, risk, "start"));
          }
        }
      }
      if (routeAborted) break;
      for (const [name, arguments_] of commandLists) {
        const mutation = commandListMutation(statement, name);
        if (
          mutation !== undefined &&
          !applyCommandListMutation(arguments_, mutation)
        ) {
          routeAborted = true;
          break;
        }
      }
      if (routeAborted) break;
      for (const [name, pipelineBuilders] of builderLists) {
        const mutation = builderListMutation(
          statement,
          name,
          aliases,
          builders,
          commandLists,
        );
        if (
          mutation !== undefined &&
          !applyBuilderListMutation(
            pipelineBuilders,
            mutation,
            builderListMutationLines,
          )
        ) {
          routeAborted = true;
          break;
        }
      }
      if (routeAborted) break;
      if (pipeline !== undefined) {
        for (const state of new Set(pipeline.builders)) {
          const risk = processRisk(state, taints, literals);
          if (risk !== undefined) {
            const mutationLine = builderListMutationLines
              .get(pipeline.builders)
              ?.get(state);
            if (mutationLine !== undefined) {
              risk.taint.propagators.push({
                kind: "kotlin-process-pipeline-list-mutation",
                line: mutationLine,
              });
            }
            risk.taint.propagators.push({
              kind: "kotlin-process-pipeline-assembly",
              line: pipeline.line,
              symbol: "ProcessBuilder.startPipeline",
            });
            records.push(
              recordForRisk(path, lines, pipeline.line, risk, "startPipeline"),
            );
          }
        }
      }
      if (records.length >= MAX_RECORDS) return records;
    }
  }
  return records;
}
