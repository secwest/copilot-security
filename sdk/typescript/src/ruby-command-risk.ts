const CONTEXT_LINES_BEFORE = 3;
const CONTEXT_LINES_AFTER = 5;
const MAX_RUBY_TOKENS = 131_072;
const MAX_RUBY_NESTING = 128;
const MAX_RECORDS = 64;
const MAX_EXCERPT_LINE_CHARACTERS = 2_048;

type RubyTokenKind =
  | "identifier"
  | "newline"
  | "number"
  | "string"
  | "symbol"
  | "variable";

interface RubySource {
  line: number;
  symbol: string;
}

interface RubyToken {
  kind: RubyTokenKind;
  value: string;
  line: number;
  column: number;
  references: string[];
  directSources: RubySource[];
  commandString: boolean;
  commandMethod?: "`" | "%x";
}

interface RubyPropagator {
  kind:
    | "ruby-local-assignment"
    | "ruby-shell-escaping"
    | "ruby-string-concatenation"
    | "ruby-string-interpolation";
  line: number;
  symbol?: string;
}

interface RubyTaint extends RubySource {
  propagators: RubyPropagator[];
  controls: Array<{ kind: string; line: number }>;
}

interface RubyCall {
  method: string;
  receiver?: string;
  line: number;
  arguments: RubyToken[][];
}

interface RubySink {
  kind:
    | "ruby-backtick-shell-command"
    | "ruby-explicit-shell-command"
    | "ruby-shell-command-string"
    | "ruby-tainted-executable";
  receiver: string;
  method: string;
  line: number;
  taint: RubyTaint;
}

export interface RubyCommandInjectionRecord {
  path: string;
  line: number;
  categories: ["ruby-rails-command-injection"];
  priority: number;
  startLine: number;
  endLine: number;
  excerpt: string;
  sourceExcerpt: string;
  frameworkModel: {
    schemaVersion: "1.2";
    id: "ruby-rails-command-injection";
    language: "ruby";
    scope: "same-file";
    source: {
      kind: "rails-request-parameter";
      path: string;
      line: number;
      symbol: string;
    };
    sink: {
      kind: RubySink["kind"];
      path: string;
      line: number;
      symbol: string;
      cweIds: readonly ["CWE-78", "CWE-88"];
    };
    propagators: Array<RubyPropagator & { path: string }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

const OPEN3_METHODS = new Set([
  "capture2",
  "capture2e",
  "capture3",
  "popen2",
  "popen2e",
  "popen3",
]);
const CORE_METHODS = new Set(["exec", "spawn", "system"]);
const SHELL_COMMAND_FLAGS = new Map<string, Set<string>>([
  ["bash", new Set(["-c"])],
  ["cmd", new Set(["/c", "/k"])],
  ["cmd.exe", new Set(["/c", "/k"])],
  ["dash", new Set(["-c"])],
  ["ksh", new Set(["-c"])],
  ["powershell", new Set(["-c", "-command"])],
  ["powershell.exe", new Set(["-c", "-command"])],
  ["pwsh", new Set(["-c", "-command"])],
  ["sh", new Set(["-c"])],
  ["zsh", new Set(["-c"])],
]);

function identifierStart(character: string): boolean {
  return /[A-Za-z_\u0080-\uffff]/u.test(character);
}

function identifierPart(character: string): boolean {
  return /[A-Za-z0-9_\u0080-\uffff]/u.test(character);
}

function interpolationMetadata(
  value: string,
  line: number,
): {
  references: string[];
  directSources: RubySource[];
} {
  const references = new Set<string>();
  const directSources: RubySource[] = [];
  for (const match of value.matchAll(/#\{([^{}]{1,1024})\}/gu)) {
    const expression = match[1] ?? "";
    for (const reference of expression.matchAll(
      /(?<![:.@$])\b([a-z_][A-Za-z0-9_]*)\b/gu,
    )) {
      const name = reference[1] ?? "";
      if (!new Set(["false", "nil", "params", "request", "true"]).has(name))
        references.add(name);
    }
    const parameter =
      /\bparams\s*\[\s*(?::([A-Za-z_][A-Za-z0-9_]*)|["']([^"']+)["'])\s*\]/u.exec(
        expression,
      );
    if (parameter !== null) {
      const key = parameter[1] ?? parameter[2] ?? "unknown";
      directSources.push({ line, symbol: `params[${key}]` });
    }
  }
  for (const match of value.matchAll(/#([@$]{1,2}[A-Za-z_]\w*)/gu)) {
    references.add(match[1] ?? "");
  }
  return { references: [...references], directSources };
}

function rubyTokens(source: string): RubyToken[] | undefined {
  const tokens: RubyToken[] = [];
  const delimiters: string[] = [];
  let index = 0;
  let line = 1;
  let column = 1;
  let previousWasCarriageReturn = false;

  const advance = (text: string): void => {
    for (const character of text) {
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
    kind: RubyTokenKind,
    value: string,
    tokenLine: number,
    tokenColumn: number,
    options: Partial<
      Pick<
        RubyToken,
        "commandMethod" | "commandString" | "directSources" | "references"
      >
    > = {},
  ): boolean => {
    tokens.push({
      kind,
      value,
      line: tokenLine,
      column: tokenColumn,
      references: options.references ?? [],
      directSources: options.directSources ?? [],
      commandString: options.commandString ?? false,
      commandMethod: options.commandMethod,
    });
    return tokens.length <= MAX_RUBY_TOKENS;
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
    if (character === "#") {
      const newline = source.slice(index).search(/[\r\n]/u);
      consume(newline < 0 ? source.length - index : newline);
      continue;
    }

    if (character === "'" || character === '"' || character === "`") {
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
      const raw = source.slice(index + 1, cursor);
      const interpolated = quote !== "'";
      const metadata = interpolated
        ? interpolationMetadata(raw, tokenLine)
        : { references: [], directSources: [] };
      consume(cursor + 1 - index);
      if (
        !add("string", raw, tokenLine, tokenColumn, {
          ...metadata,
          commandString: quote === "`",
          commandMethod: quote === "`" ? "`" : undefined,
        })
      )
        return undefined;
      continue;
    }

    if (character === "%" && /[qQx]/u.test(source[index + 1] ?? "")) {
      const style = source[index + 1] ?? "";
      const opening = source[index + 2] ?? "";
      const closing =
        new Map([
          ["(", ")"],
          ["[", "]"],
          ["{", "}"],
          ["<", ">"],
        ]).get(opening) ?? opening;
      if (opening === "" || /[A-Za-z0-9\s]/u.test(opening)) return undefined;
      const tokenLine = line;
      const tokenColumn = column;
      let cursor = index + 3;
      let depth = 1;
      let escaped = false;
      while (cursor < source.length && depth > 0) {
        const current = source[cursor] ?? "";
        if (!escaped && current === "\\") escaped = true;
        else {
          if (!escaped && opening !== closing && current === opening)
            depth += 1;
          if (!escaped && current === closing) depth -= 1;
          escaped = false;
        }
        cursor += 1;
      }
      if (depth !== 0) return undefined;
      const raw = source.slice(index + 3, cursor - 1);
      const interpolated = style !== "q";
      const metadata = interpolated
        ? interpolationMetadata(raw, tokenLine)
        : { references: [], directSources: [] };
      consume(cursor - index);
      if (
        !add("string", raw, tokenLine, tokenColumn, {
          ...metadata,
          commandString: style === "x",
          commandMethod: style === "x" ? "%x" : undefined,
        })
      )
        return undefined;
      continue;
    }

    if (
      character === ":" &&
      source[index + 1] !== ":" &&
      identifierStart(source[index + 1] ?? "")
    ) {
      const tokenLine = line;
      const tokenColumn = column;
      let cursor = index + 2;
      while (identifierPart(source[cursor] ?? "")) cursor += 1;
      const value = source.slice(index + 1, cursor);
      consume(cursor - index);
      if (!add("symbol", value, tokenLine, tokenColumn)) return undefined;
      continue;
    }

    if (character === "@" || character === "$") {
      const tokenLine = line;
      const tokenColumn = column;
      let cursor = index + 1;
      if (character === "@" && source[cursor] === "@") cursor += 1;
      if (!identifierStart(source[cursor] ?? "")) {
        consume(1);
        if (!add("symbol", character, tokenLine, tokenColumn)) return undefined;
        continue;
      }
      cursor += 1;
      while (identifierPart(source[cursor] ?? "")) cursor += 1;
      const value = source.slice(index, cursor);
      consume(cursor - index);
      if (!add("variable", value, tokenLine, tokenColumn)) return undefined;
      continue;
    }

    if (identifierStart(character)) {
      const tokenLine = line;
      const tokenColumn = column;
      let cursor = index + 1;
      while (identifierPart(source[cursor] ?? "")) cursor += 1;
      if (/[!?]/u.test(source[cursor] ?? "")) cursor += 1;
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
      ["::", "&.", "=>", "||=", "&&=", "+=", "<<", "=~", "!~", "==", "!="]
        .sort((left, right) => right.length - left.length)
        .find((value) => source.startsWith(value, index)) ?? character;
    consume(operator.length);
    if (["(", "[", "{"].includes(operator)) {
      delimiters.push(operator);
      if (delimiters.length > MAX_RUBY_NESTING) return undefined;
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

function statementTokens(tokens: readonly RubyToken[]): RubyToken[][] {
  const statements: RubyToken[][] = [];
  let current: RubyToken[] = [];
  let depth = 0;
  for (const token of tokens) {
    if (["(", "[", "{"].includes(token.value)) depth += 1;
    if ([")", "]", "}"].includes(token.value)) depth -= 1;
    if ((token.kind === "newline" || token.value === ";") && depth === 0) {
      if (current.length > 0) statements.push(current);
      current = [];
    } else {
      current.push(token);
    }
  }
  if (current.length > 0) statements.push(current);
  return statements;
}

function matchingDelimiter(
  tokens: readonly RubyToken[],
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

function splitArguments(tokens: readonly RubyToken[]): RubyToken[][] {
  const arguments_: RubyToken[][] = [];
  let current: RubyToken[] = [];
  let depth = 0;
  for (const token of tokens) {
    if (["(", "[", "{"].includes(token.value)) depth += 1;
    if ([")", "]", "}"].includes(token.value)) depth -= 1;
    if (token.value === "," && depth === 0) {
      arguments_.push(current);
      current = [];
    } else if (token.kind !== "newline") {
      current.push(token);
    }
  }
  if (current.length > 0) arguments_.push(current);
  return arguments_;
}

function calls(statement: readonly RubyToken[]): RubyCall[] {
  const found: RubyCall[] = [];
  const possibleSinkMethod = (method: string): boolean =>
    CORE_METHODS.has(method) || OPEN3_METHODS.has(method) || method === "popen";
  for (let index = 0; index < statement.length; index += 1) {
    const token = statement[index];
    if (token?.kind !== "identifier") continue;
    const receiver =
      statement[index - 1]?.value === "." ||
      statement[index - 1]?.value === "&."
        ? statement[index - 2]?.value
        : undefined;
    if (statement[index + 1]?.value === "(") {
      const close = matchingDelimiter(statement, index + 1);
      if (close === undefined) continue;
      found.push({
        method: token.value,
        receiver,
        line: token.line,
        arguments: splitArguments(statement.slice(index + 2, close)),
      });
      continue;
    }
    if (
      !possibleSinkMethod(token.value) ||
      statement[index + 1] === undefined ||
      [".", "&.", "::", "=", ":"].includes(statement[index + 1]?.value ?? "")
    )
      continue;
    found.push({
      method: token.value,
      receiver,
      line: token.line,
      arguments: splitArguments(statement.slice(index + 1)),
    });
  }
  return found;
}

interface RubyMethodScope {
  body: RubyToken[];
}

function isStatementStart(
  tokens: readonly RubyToken[],
  index: number,
): boolean {
  if (index === 0) return true;
  const previous = tokens[index - 1];
  return previous?.kind === "newline" || previous?.value === ";";
}

function controllerMethodScopes(
  tokens: readonly RubyToken[],
  path: string,
): RubyMethodScope[] | undefined {
  interface Block {
    kind: string;
    start: number;
    controller: boolean;
  }
  const stack: Block[] = [];
  const scopes: RubyMethodScope[] = [];
  const conventionalControllerPath =
    /(?:^|\/)app\/controllers\/[^/]+_controller\.rb$/iu.test(
      path.replaceAll("\\", "/"),
    );
  const leadingBlocks = new Set([
    "begin",
    "case",
    "for",
    "if",
    "unless",
    "until",
    "while",
  ]);

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token?.kind !== "identifier") continue;
    const value = token.value;
    if (value === "class" && isStatementStart(tokens, index)) {
      const lineEnd = tokens.findIndex(
        (candidate, candidateIndex) =>
          candidateIndex > index && candidate.kind === "newline",
      );
      const declaration = tokens.slice(
        index + 1,
        lineEnd < 0 ? tokens.length : lineEnd,
      );
      const className = declaration[0]?.value ?? "";
      const signature = declaration
        .map((candidate) => candidate.value)
        .join("");
      const controller =
        signature.includes("<ActionController::Base") ||
        (conventionalControllerPath &&
          className.endsWith("Controller") &&
          signature.includes("<ApplicationController"));
      stack.push({ kind: "class", start: index, controller });
      continue;
    }
    if (value === "module" && isStatementStart(tokens, index)) {
      stack.push({ kind: "module", start: index, controller: false });
      continue;
    }
    if (value === "def" && isStatementStart(tokens, index)) {
      const lineEnd = tokens.findIndex(
        (candidate, candidateIndex) =>
          candidateIndex > index && candidate.kind === "newline",
      );
      const declaration = tokens.slice(
        index + 1,
        lineEnd < 0 ? tokens.length : lineEnd,
      );
      if (declaration.some((candidate) => candidate.value === "=")) continue;
      const controller = stack.some(
        (candidate) => candidate.kind === "class" && candidate.controller,
      );
      stack.push({ kind: "def", start: index, controller });
      continue;
    }
    if (leadingBlocks.has(value) && isStatementStart(tokens, index)) {
      stack.push({ kind: value, start: index, controller: false });
      continue;
    }
    if (value === "do") {
      stack.push({ kind: "do", start: index, controller: false });
      continue;
    }
    if (value !== "end" || !isStatementStart(tokens, index)) continue;
    const block = stack.pop();
    if (block === undefined) return undefined;
    if (block.kind === "def" && block.controller) {
      scopes.push({ body: tokens.slice(block.start + 1, index) });
    }
  }
  return stack.length === 0 ? scopes : undefined;
}

function sourceFromExpression(
  tokens: readonly RubyToken[],
): RubySource | undefined {
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token?.value === "params") {
      if (tokens[index + 1]?.value === "[") {
        const key = tokens[index + 2];
        if (key?.kind === "symbol" || key?.kind === "string") {
          return { line: token.line, symbol: `params[${key.value}]` };
        }
      }
      if (
        [".", "&."].includes(tokens[index + 1]?.value ?? "") &&
        new Set(["dig", "expect", "fetch", "require"]).has(
          tokens[index + 2]?.value ?? "",
        ) &&
        tokens[index + 3]?.value === "("
      ) {
        const key = tokens[index + 4];
        if (key?.kind === "symbol" || key?.kind === "string") {
          return {
            line: token.line,
            symbol: `params.${tokens[index + 2]?.value}(${key.value})`,
          };
        }
      }
    }
    if (
      token?.value === "request" &&
      [".", "&."].includes(tokens[index + 1]?.value ?? "") &&
      new Set([
        "path_parameters",
        "query_parameters",
        "request_parameters",
      ]).has(tokens[index + 2]?.value ?? "") &&
      tokens[index + 3]?.value === "["
    ) {
      const key = tokens[index + 4];
      if (key?.kind === "symbol" || key?.kind === "string") {
        return {
          line: token.line,
          symbol: `request.${tokens[index + 2]?.value}[${key.value}]`,
        };
      }
    }
    if (token?.directSources[0] !== undefined) return token.directSources[0];
  }
  return undefined;
}

function expressionTaint(
  tokens: readonly RubyToken[],
  taints: ReadonlyMap<string, RubyTaint>,
): RubyTaint | undefined {
  const numericConversion =
    ((tokens[0]?.value === "Integer" || tokens[0]?.value === "Float") &&
      tokens[1]?.value === "(") ||
    tokens.some(
      (token, index) =>
        [".", "&."].includes(token.value) &&
        new Set(["to_f", "to_i"]).has(tokens[index + 1]?.value ?? ""),
    );
  if (numericConversion) return undefined;

  const direct = sourceFromExpression(tokens);
  let taint: RubyTaint | undefined =
    direct === undefined
      ? undefined
      : { ...direct, propagators: [], controls: [] };
  if (taint === undefined) {
    for (const token of tokens) {
      const candidate = taints.get(token.value);
      if (candidate !== undefined) {
        taint = {
          ...candidate,
          propagators: [...candidate.propagators],
          controls: [...candidate.controls],
        };
        break;
      }
      for (const reference of token.references) {
        const referenced = taints.get(reference);
        if (referenced !== undefined) {
          taint = {
            ...referenced,
            propagators: [...referenced.propagators],
            controls: [...referenced.controls],
          };
          break;
        }
      }
      if (taint !== undefined) break;
    }
  }
  if (taint === undefined) return undefined;

  const interpolation = tokens.find(
    (token) =>
      token.kind === "string" &&
      (token.references.length > 0 || token.directSources.length > 0),
  );
  if (interpolation !== undefined) {
    taint.propagators.push({
      kind: "ruby-string-interpolation",
      line: interpolation.line,
    });
  }
  const concatenation = tokens.find((token) =>
    new Set(["+", "<<"]).has(token.value),
  );
  if (concatenation !== undefined) {
    taint.propagators.push({
      kind: "ruby-string-concatenation",
      line: concatenation.line,
    });
  }
  const shellEscape = tokens.find(
    (token, index) =>
      token.value === "shellescape" ||
      (token.value === "Shellwords" &&
        [".", "::"].includes(tokens[index + 1]?.value ?? "") &&
        tokens[index + 2]?.value === "escape") ||
      (token.kind === "string" &&
        /(?:Shellwords\s*\.\s*escape|\.shellescape)\b/u.test(token.value)),
  );
  if (shellEscape !== undefined) {
    taint.propagators.push({
      kind: "ruby-shell-escaping",
      line: shellEscape.line,
    });
    taint.controls.push({
      kind: "bourne-shell-argument-escaping",
      line: shellEscape.line,
    });
  }
  taint.propagators = taint.propagators.slice(0, 16);
  taint.controls = taint.controls.slice(0, 8);
  return taint;
}

function fixedString(tokens: readonly RubyToken[]): string | undefined {
  if (tokens.length !== 1 || tokens[0]?.kind !== "string") return undefined;
  if (tokens[0].references.length > 0 || tokens[0].directSources.length > 0)
    return undefined;
  return tokens[0].value;
}

function hashArgument(tokens: readonly RubyToken[]): boolean {
  return tokens[0]?.value === "{" && tokens.at(-1)?.value === "}";
}

function keywordArgument(tokens: readonly RubyToken[]): boolean {
  return tokens[0]?.kind === "identifier" && tokens[1]?.value === ":";
}

function positionalArguments(call: RubyCall): RubyToken[][] {
  const result = [...call.arguments];
  if (result.length > 1 && hashArgument(result[0] ?? [])) result.shift();
  while (
    result.length > 1 &&
    (hashArgument(result.at(-1) ?? []) || keywordArgument(result.at(-1) ?? []))
  )
    result.pop();
  return result;
}

function executableName(value: string): string {
  return value.replaceAll("\\", "/").split("/").at(-1)?.toLowerCase() ?? "";
}

function callSink(
  call: RubyCall,
  taints: ReadonlyMap<string, RubyTaint>,
  hasOpen3: boolean,
  shadowedCoreMethods: ReadonlySet<string>,
): RubySink | undefined {
  const bareCore =
    call.receiver === undefined &&
    CORE_METHODS.has(call.method) &&
    !shadowedCoreMethods.has(call.method);
  const kernelCore =
    call.receiver === "Kernel" && CORE_METHODS.has(call.method);
  const processCore =
    call.receiver === "Process" && CORE_METHODS.has(call.method);
  const open3 =
    call.receiver === "Open3" && hasOpen3 && OPEN3_METHODS.has(call.method);
  const ioPopen = call.receiver === "IO" && call.method === "popen";
  if (!bareCore && !kernelCore && !processCore && !open3 && !ioPopen)
    return undefined;

  const arguments_ = positionalArguments(call);
  if (arguments_.length === 0) return undefined;
  const receiver = call.receiver ?? "Kernel";
  const firstTaint = expressionTaint(arguments_[0] ?? [], taints);
  if (firstTaint !== undefined) {
    return {
      kind:
        ioPopen || arguments_.length === 1
          ? "ruby-shell-command-string"
          : "ruby-tainted-executable",
      receiver,
      method: call.method,
      line: call.line,
      taint: firstTaint,
    };
  }

  const executable = fixedString(arguments_[0] ?? []);
  const flag = fixedString(arguments_[1] ?? [])?.toLowerCase();
  const acceptedFlags =
    executable === undefined
      ? undefined
      : SHELL_COMMAND_FLAGS.get(executableName(executable));
  if (
    acceptedFlags !== undefined &&
    flag !== undefined &&
    acceptedFlags.has(flag)
  ) {
    const commandTaint = expressionTaint(arguments_[2] ?? [], taints);
    if (commandTaint !== undefined) {
      return {
        kind: "ruby-explicit-shell-command",
        receiver,
        method: call.method,
        line: call.line,
        taint: commandTaint,
      };
    }
  }
  return undefined;
}

function assignment(
  statement: readonly RubyToken[],
):
  | { target: string; operator: string; expression: RubyToken[]; line: number }
  | undefined {
  const first = statement[0];
  if (
    first?.kind !== "identifier" ||
    !/^[a-z_][A-Za-z0-9_]*$/u.test(first.value)
  )
    return undefined;
  const operatorIndex = statement.findIndex((token) =>
    new Set(["=", "+=", "<<"]).has(token.value),
  );
  if (operatorIndex < 1) return undefined;
  return {
    target: first.value,
    operator: statement[operatorIndex]?.value ?? "=",
    expression: statement.slice(operatorIndex + 1),
    line: statement[operatorIndex]?.line ?? first.line,
  };
}

function scopeSinks(
  tokens: readonly RubyToken[],
  hasOpen3: boolean,
  shadowedCoreMethods: ReadonlySet<string>,
): RubySink[] {
  const taints = new Map<string, RubyTaint>();
  const sinks: RubySink[] = [];
  for (const statement of statementTokens(tokens)) {
    for (const token of statement) {
      if (!token.commandString) continue;
      const taint = expressionTaint([token], taints);
      if (taint !== undefined) {
        sinks.push({
          kind: "ruby-backtick-shell-command",
          receiver: "Kernel",
          method: token.commandMethod ?? "`",
          line: token.line,
          taint,
        });
      }
    }
    for (const call of calls(statement)) {
      const sink = callSink(call, taints, hasOpen3, shadowedCoreMethods);
      if (sink !== undefined) sinks.push(sink);
    }
    const assigned = assignment(statement);
    if (assigned === undefined) continue;
    if (assigned.operator !== "=" && taints.has(assigned.target)) {
      const existing = taints.get(assigned.target)!;
      const appended = expressionTaint(assigned.expression, taints);
      if (appended !== undefined) {
        taints.set(assigned.target, {
          ...existing,
          propagators: [
            ...existing.propagators,
            {
              kind: "ruby-string-concatenation" as const,
              line: assigned.line,
            },
          ].slice(0, 16),
          controls: [...existing.controls, ...appended.controls].slice(0, 8),
        });
      }
      continue;
    }
    const taint = expressionTaint(assigned.expression, taints);
    if (taint === undefined) {
      taints.delete(assigned.target);
      continue;
    }
    if (assigned.operator !== "=") {
      taint.propagators.push({
        kind: "ruby-string-concatenation",
        line: assigned.line,
      });
    }
    taints.set(assigned.target, {
      ...taint,
      propagators: [
        ...taint.propagators,
        {
          kind: "ruby-local-assignment" as const,
          line: assigned.line,
          symbol: assigned.target,
        },
      ].slice(0, 16),
    });
  }
  return sinks;
}

function requiredOpen3(tokens: readonly RubyToken[]): boolean {
  return statementTokens(tokens).some((statement) => {
    const requireIndex = statement.findIndex(
      (token) => token.kind === "identifier" && token.value === "require",
    );
    if (requireIndex < 0) return false;
    return statement
      .slice(requireIndex + 1)
      .some(
        (token) =>
          token.kind === "string" && new Set(["open3"]).has(token.value),
      );
  });
}

function shadowedCoreMethods(tokens: readonly RubyToken[]): Set<string> {
  const shadowed = new Set<string>();
  for (let index = 0; index + 1 < tokens.length; index += 1) {
    if (
      tokens[index]?.value === "def" &&
      CORE_METHODS.has(tokens[index + 1]?.value ?? "")
    )
      shadowed.add(tokens[index + 1]!.value);
  }
  return shadowed;
}

function excerpt(lines: readonly string[], line: number): string {
  return lines
    .slice(
      Math.max(0, line - 1 - CONTEXT_LINES_BEFORE),
      Math.min(lines.length, line + CONTEXT_LINES_AFTER),
    )
    .map((value) => {
      const characters = [...value];
      return characters.length <= MAX_EXCERPT_LINE_CHARACTERS
        ? value
        : `${characters.slice(0, MAX_EXCERPT_LINE_CHARACTERS).join("")}…[truncated]`;
    })
    .join("\n");
}

export function rubyCommandInjectionRecords(
  path: string,
  lines: readonly string[],
  source: string,
): RubyCommandInjectionRecord[] {
  if (!/\.rb$/iu.test(path)) return [];
  if (
    /(?:^|\/)(?:fixtures?|spec|test|tests)(?:\/|$)/iu.test(
      path.replaceAll("\\", "/"),
    )
  )
    return [];
  const tokens = rubyTokens(source);
  if (tokens === undefined || tokens.length === 0) return [];
  const scopes = controllerMethodScopes(tokens, path);
  if (scopes === undefined || scopes.length === 0) return [];
  const hasOpen3 = requiredOpen3(tokens);
  const shadowed = shadowedCoreMethods(tokens);
  const sinks = scopes.flatMap((scope) =>
    scopeSinks(scope.body, hasOpen3, shadowed),
  );
  const records: RubyCommandInjectionRecord[] = [];
  const seen = new Set<string>();
  for (const sink of sinks) {
    const key = `${sink.kind}:${sink.line}:${sink.taint.line}:${sink.taint.symbol}`;
    if (seen.has(key)) continue;
    seen.add(key);
    records.push({
      path,
      line: sink.line,
      categories: ["ruby-rails-command-injection"],
      priority: 128,
      startLine: Math.max(1, sink.line - CONTEXT_LINES_BEFORE),
      endLine: Math.min(lines.length, sink.line + CONTEXT_LINES_AFTER),
      excerpt: excerpt(lines, sink.line),
      sourceExcerpt: excerpt(lines, sink.taint.line),
      frameworkModel: {
        schemaVersion: "1.2",
        id: "ruby-rails-command-injection",
        language: "ruby",
        scope: "same-file",
        source: {
          kind: "rails-request-parameter",
          path,
          line: sink.taint.line,
          symbol: sink.taint.symbol,
        },
        sink: {
          kind: sink.kind,
          path,
          line: sink.line,
          symbol: `receiver=${sink.receiver};method=${sink.method}`,
          cweIds: ["CWE-78", "CWE-88"],
        },
        propagators: sink.taint.propagators.map((propagator) => ({
          ...propagator,
          path,
        })),
        candidateControls: sink.taint.controls.map((control) => ({
          ...control,
          path,
        })),
      },
    });
    if (records.length >= MAX_RECORDS) break;
  }
  return records;
}
