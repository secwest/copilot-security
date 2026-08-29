const CONTEXT_LINES_BEFORE = 4;
const CONTEXT_LINES_AFTER = 6;
const MAX_RUST_TOKENS = 131_072;
const MAX_RUST_NESTING = 128;
const MAX_RECORDS = 64;
const MAX_EXCERPT_LINE_CHARACTERS = 2_048;

type RustTokenKind = "identifier" | "number" | "string" | "symbol";

interface RustToken {
  kind: RustTokenKind;
  value: string;
  line: number;
  column: number;
}

interface RustSource {
  kind: "rust-http-extractor";
  framework: "actix-web" | "axum";
  extractor: "Form" | "Json" | "Path" | "Query";
  line: number;
  symbol: string;
}

interface RustPropagator {
  kind:
    | "rust-format-macro"
    | "rust-local-assignment"
    | "rust-shell-escape-candidate"
    | "rust-string-concatenation";
  line: number;
  symbol?: string;
}

interface RustTaint {
  source: RustSource;
  propagators: RustPropagator[];
  controls: Array<{ kind: string; line: number }>;
}

type RustCommandSinkKind =
  | "rust-process-executable-selection"
  | "rust-process-interpreter-command"
  | "rust-process-raw-command-line"
  | "rust-process-shell-command";

interface RustArgument {
  tokens: RustToken[];
  line: number;
  raw: boolean;
}

interface RustCommandState {
  runtime: "std" | "tokio";
  program: RustToken[];
  constructorLine: number;
  arguments: RustArgument[];
}

interface RustExecution extends RustCommandState {
  method: "exec" | "output" | "spawn" | "status";
  line: number;
}

interface RustImports {
  commandAliases: Map<string, RustCommandState["runtime"]>;
  processAliases: Map<string, RustCommandState["runtime"]>;
  unixCommandExt: boolean;
  windowsCommandExt: boolean;
  extractorAliases: Map<
    string,
    { framework: RustSource["framework"]; extractor: RustSource["extractor"] }
  >;
  actixWebAliases: Set<string>;
}

interface RustFunction {
  name: string;
  parameters: RustToken[][];
  body: RustToken[];
}

interface RustRisk {
  kind: RustCommandSinkKind;
  taint: RustTaint;
  argumentIndex: number;
}

export interface RustCommandInjectionRecord {
  path: string;
  line: number;
  categories: ["rust-web-command-injection"];
  priority: number;
  startLine: number;
  endLine: number;
  excerpt: string;
  sourceExcerpt: string;
  frameworkModel: {
    schemaVersion: "1.2";
    id: "rust-web-command-injection";
    language: "rust";
    scope: "same-file";
    source: {
      kind: "rust-http-extractor";
      path: string;
      line: number;
      symbol: string;
    };
    sink: {
      kind: RustCommandSinkKind;
      path: string;
      line: number;
      symbol: string;
      cweIds: readonly ["CWE-78", "CWE-88"];
    };
    propagators: Array<RustPropagator & { path: string }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

const EXTRACTORS = ["Form", "Json", "Path", "Query"] as const;
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
const EXECUTION_METHODS = new Set(["exec", "output", "spawn", "status"]);
const NUMERIC_TYPES =
  "(?:f32|f64|i8|i16|i32|i64|i128|isize|u8|u16|u32|u64|u128|usize)";

function identifierStart(character: string): boolean {
  return /[A-Za-z_]/u.test(character);
}

function identifierPart(character: string): boolean {
  return /[A-Za-z0-9_]/u.test(character);
}

function rustTokens(text: string): RustToken[] | undefined {
  const tokens: RustToken[] = [];
  const delimiters: string[] = [];
  let index = 0;
  let line = 1;
  let column = 1;

  const advance = (count = 1): void => {
    for (let offset = 0; offset < count; offset += 1) {
      if (text[index] === "\n") {
        line += 1;
        column = 1;
      } else {
        column += 1;
      }
      index += 1;
    }
  };
  const add = (
    kind: RustTokenKind,
    value: string,
    tokenLine: number,
    tokenColumn: number,
  ): boolean => {
    if (tokens.length >= MAX_RUST_TOKENS) return false;
    tokens.push({ kind, value, line: tokenLine, column: tokenColumn });
    return true;
  };

  while (index < text.length) {
    const character = text[index] ?? "";
    if (/\s/u.test(character)) {
      advance();
      continue;
    }
    if (character === "/" && text[index + 1] === "/") {
      while (index < text.length && text[index] !== "\n") advance();
      continue;
    }
    if (character === "/" && text[index + 1] === "*") {
      let depth = 1;
      advance(2);
      while (index < text.length && depth > 0) {
        if (text[index] === "/" && text[index + 1] === "*") {
          depth += 1;
          if (depth > MAX_RUST_NESTING) return undefined;
          advance(2);
        } else if (text[index] === "*" && text[index + 1] === "/") {
          depth -= 1;
          advance(2);
        } else {
          advance();
        }
      }
      if (depth !== 0) return undefined;
      continue;
    }

    const rawPrefix = /^(?:br|rb|r)(#{0,64})"/u.exec(text.slice(index));
    if (rawPrefix !== null) {
      const tokenLine = line;
      const tokenColumn = column;
      const prefixLength = rawPrefix[0].length;
      const hashes = rawPrefix[1] ?? "";
      advance(prefixLength);
      const start = index;
      const closing = `"${hashes}`;
      const end = text.indexOf(closing, index);
      if (end < 0) return undefined;
      const value = text.slice(start, end);
      advance(end - index + closing.length);
      if (!add("string", value, tokenLine, tokenColumn)) return undefined;
      continue;
    }

    const quotePrefix = /^(?:b|c)?"/u.exec(text.slice(index));
    if (quotePrefix !== null) {
      const tokenLine = line;
      const tokenColumn = column;
      advance(quotePrefix[0].length);
      let value = "";
      let closed = false;
      while (index < text.length) {
        if (text[index] === "\\") {
          const escaped = text[index + 1];
          if (escaped === undefined) return undefined;
          const decoded = new Map([
            ["n", "\n"],
            ["r", "\r"],
            ["t", "\t"],
            ["0", "\0"],
            ['"', '"'],
            ["\\", "\\"],
          ]).get(escaped);
          value += decoded ?? escaped;
          advance(2);
        } else if (text[index] === '"') {
          advance();
          closed = true;
          break;
        } else {
          value += text[index];
          advance();
        }
      }
      if (!closed || !add("string", value, tokenLine, tokenColumn)) {
        return undefined;
      }
      continue;
    }

    if (character === "'") {
      const codePoint = text.codePointAt(index + 1);
      const scalarLength =
        codePoint !== undefined && codePoint > 0xffff ? 2 : 1;
      let closing = codePoint === undefined ? -1 : index + 1 + scalarLength;
      if (text[index + 1] === "\\") {
        closing = text.indexOf("'", index + 2);
        if (
          closing < 0 ||
          closing - index > 16 ||
          /\s/u.test(text.slice(index + 1, closing))
        ) {
          closing = -1;
        }
      } else if (text[closing] !== "'") {
        closing = -1;
      }
      if (closing > index + 1) {
        const tokenLine = line;
        const tokenColumn = column;
        const value = text.slice(index + 1, closing);
        advance(closing - index + 1);
        if (!add("string", value, tokenLine, tokenColumn)) return undefined;
        continue;
      }
    }

    if (identifierStart(character)) {
      const tokenLine = line;
      const tokenColumn = column;
      const start = index;
      advance();
      while (index < text.length && identifierPart(text[index] ?? "")) {
        advance();
      }
      if (
        !add("identifier", text.slice(start, index), tokenLine, tokenColumn)
      ) {
        return undefined;
      }
      continue;
    }
    if (/[0-9]/u.test(character)) {
      const tokenLine = line;
      const tokenColumn = column;
      const start = index;
      advance();
      while (index < text.length && /[A-Za-z0-9_.]/u.test(text[index] ?? "")) {
        advance();
      }
      if (!add("number", text.slice(start, index), tokenLine, tokenColumn)) {
        return undefined;
      }
      continue;
    }

    const tokenLine = line;
    const tokenColumn = column;
    const pair = text.slice(index, index + 2);
    const value = new Set([
      "::",
      "->",
      "=>",
      "&&",
      "||",
      "+=",
      "-=",
      "*=",
      "/=",
      "==",
      "!=",
      "<=",
      ">=",
      "..",
    ]).has(pair)
      ? pair
      : character;
    if ("([{ ".trim().includes(value)) {
      delimiters.push(value);
      if (delimiters.length > MAX_RUST_NESTING) return undefined;
    } else if (")] }".replaceAll(" ", "").includes(value)) {
      const expected = new Map([
        [")", "("],
        ["]", "["],
        ["}", "{"],
      ]).get(value);
      if (delimiters.pop() !== expected) return undefined;
    }
    advance(value.length);
    if (!add("symbol", value, tokenLine, tokenColumn)) return undefined;
  }
  return delimiters.length === 0 ? tokens : undefined;
}

function compact(tokens: readonly RustToken[]): string {
  return tokens.map(({ value }) => value).join("");
}

function matchingDelimiter(
  tokens: readonly RustToken[],
  open: number,
): number | undefined {
  const opening = tokens[open]?.value;
  const closing = new Map([
    ["(", ")"],
    ["[", "]"],
    ["{", "}"],
  ]).get(opening ?? "");
  if (closing === undefined) return undefined;
  let depth = 0;
  for (let index = open; index < tokens.length; index += 1) {
    if (tokens[index]?.value === opening) depth += 1;
    else if (tokens[index]?.value === closing) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return undefined;
}

function splitTopLevel(
  tokens: readonly RustToken[],
  separator: string,
): RustToken[][] {
  const result: RustToken[][] = [];
  let start = 0;
  let depth = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    const value = tokens[index]?.value;
    if (value === "(" || value === "[" || value === "{" || value === "<") {
      depth += 1;
    } else if (
      value === ")" ||
      value === "]" ||
      value === "}" ||
      value === ">"
    ) {
      depth = Math.max(0, depth - 1);
    } else if (value === separator && depth === 0) {
      result.push(tokens.slice(start, index));
      start = index + 1;
    }
  }
  result.push(tokens.slice(start));
  return result.filter((part) => part.length > 0);
}

function importStatements(tokens: readonly RustToken[]): RustToken[][] {
  const result: RustToken[][] = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index]?.value !== "use") continue;
    const end = tokens.findIndex(
      (token, candidate) => candidate > index && token.value === ";",
    );
    if (end < 0) break;
    result.push(tokens.slice(index, end + 1));
    index = end;
  }
  return result;
}

function aliasAfter(text: string, name: string): string {
  const match = new RegExp(`${name}(?:as([A-Za-z_]\\w*))?`, "u").exec(text);
  return match?.[1] ?? name;
}

function parseImports(tokens: readonly RustToken[]): RustImports {
  const result: RustImports = {
    commandAliases: new Map<string, RustCommandState["runtime"]>(),
    processAliases: new Map<string, RustCommandState["runtime"]>(),
    unixCommandExt: false,
    windowsCommandExt: false,
    extractorAliases: new Map(),
    actixWebAliases: new Set(),
  };
  for (const statement of importStatements(tokens)) {
    const text = compact(statement);
    for (const runtime of ["std", "tokio"] as const) {
      if (
        new RegExp(
          `^use${runtime}::process::Command(?:as[A-Za-z_]\\w*)?;$`,
          "u",
        ).test(text)
      ) {
        result.commandAliases.set(aliasAfter(text, "Command"), runtime);
      }
      if (
        new RegExp(
          `^use${runtime}::process::\\{[^}]*Command(?:as[A-Za-z_]\\w*)?[^}]*\\};$`,
          "u",
        ).test(text)
      ) {
        result.commandAliases.set(aliasAfter(text, "Command"), runtime);
      }
      const groupedCommand = new RegExp(
        `(?:^|[,{])process::(?:\\{[^}]*?Command(?:as([A-Za-z_]\\w*))?(?=[,}])|Command(?:as([A-Za-z_]\\w*))?(?=[,}]))`,
        "u",
      ).exec(text.startsWith(`use${runtime}`) ? text : "");
      if (groupedCommand !== null) {
        result.commandAliases.set(
          groupedCommand[1] ?? groupedCommand[2] ?? "Command",
          runtime,
        );
      }
      const processMatch = new RegExp(
        `^use${runtime}::process(?:as([A-Za-z_]\\w*))?;$`,
        "u",
      ).exec(text);
      if (processMatch !== null) {
        result.processAliases.set(processMatch[1] ?? "process", runtime);
      }
      const groupedProcess = new RegExp(
        `(?:^|[,{])process::\\{[^}]*self(?:as([A-Za-z_]\\w*))?[^}]*\\}`,
        "u",
      ).exec(text.startsWith(`use${runtime}`) ? text : "");
      if (groupedProcess !== null) {
        result.processAliases.set(groupedProcess[1] ?? "process", runtime);
      }
    }
    if (
      /^usestd::os::unix::process::CommandExt(?:as[A-Za-z_]\w*)?;$/u.test(text)
    ) {
      result.unixCommandExt = true;
    }
    if (
      /^usestd::os::windows::process::CommandExt(?:as[A-Za-z_]\w*)?;$/u.test(
        text,
      )
    ) {
      result.windowsCommandExt = true;
    }

    for (const extractor of EXTRACTORS) {
      const directAxum = new RegExp(
        `^useaxum::extract::${extractor}(?:as([A-Za-z_]\\w*))?;$`,
        "u",
      ).exec(text);
      if (directAxum !== null) {
        result.extractorAliases.set(directAxum[1] ?? extractor, {
          framework: "axum",
          extractor,
        });
      }
      if (text.startsWith("useaxum") && text.includes("extract")) {
        const grouped = new RegExp(
          `(?:\\{|,)${extractor}(?:as([A-Za-z_]\\w*))?(?:,|\\})`,
          "u",
        ).exec(text);
        if (grouped !== null) {
          result.extractorAliases.set(grouped[1] ?? extractor, {
            framework: "axum",
            extractor,
          });
        }
      }

      const directActix = new RegExp(
        `^useactix_web::web::${extractor}(?:as([A-Za-z_]\\w*))?;$`,
        "u",
      ).exec(text);
      if (directActix !== null) {
        result.extractorAliases.set(directActix[1] ?? extractor, {
          framework: "actix-web",
          extractor,
        });
      }
      if (text.startsWith("useactix_web::web::{")) {
        const grouped = new RegExp(
          `(?:\\{|,)${extractor}(?:as([A-Za-z_]\\w*))?(?:,|\\})`,
          "u",
        ).exec(text);
        if (grouped !== null) {
          result.extractorAliases.set(grouped[1] ?? extractor, {
            framework: "actix-web",
            extractor,
          });
        }
      }
    }
    const directWeb = /^useactix_web::web(?:as([A-Za-z_]\w*))?;$/u.exec(text);
    if (directWeb !== null) result.actixWebAliases.add(directWeb[1] ?? "web");
    if (/^useactix_web::\{[^}]*web(?:,|\})/u.test(text)) {
      result.actixWebAliases.add(aliasAfter(text, "web"));
    }
  }
  return result;
}

function hasLocalTokioShadow(tokens: readonly RustToken[]): boolean {
  const text = compact(tokens);
  return (
    /(?:^|[;{}])modtokio(?:;|\{)/u.test(text) ||
    /(?:^|[;{}])externcrate(?!tokio(?:as[A-Za-z_]\w*)?;)[A-Za-z_]\w*astokio;/u.test(
      text,
    )
  );
}

function rustFunctions(tokens: readonly RustToken[]): RustFunction[] {
  const functions: RustFunction[] = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index]?.value !== "fn") continue;
    const name = tokens[index + 1];
    if (name?.kind !== "identifier") continue;
    let open = index + 2;
    while (open < tokens.length && tokens[open]?.value !== "(") open += 1;
    if (open >= tokens.length) continue;
    const close = matchingDelimiter(tokens, open);
    if (close === undefined) continue;
    let bodyOpen = close + 1;
    while (
      bodyOpen < tokens.length &&
      tokens[bodyOpen]?.value !== "{" &&
      tokens[bodyOpen]?.value !== ";"
    ) {
      bodyOpen += 1;
    }
    if (tokens[bodyOpen]?.value !== "{") continue;
    const bodyClose = matchingDelimiter(tokens, bodyOpen);
    if (bodyClose === undefined) continue;
    functions.push({
      name: name.value,
      parameters: splitTopLevel(tokens.slice(open + 1, close), ","),
      body: tokens.slice(bodyOpen + 1, bodyClose),
    });
    index = bodyClose;
  }
  return functions;
}

function extractorType(
  typeTokens: readonly RustToken[],
  imports: RustImports,
):
  | { framework: RustSource["framework"]; extractor: RustSource["extractor"] }
  | undefined {
  const text = compact(typeTokens).replace(/^&(?:'[A-Za-z_]\w*)?(?:mut)?/u, "");
  for (const extractor of EXTRACTORS) {
    if (text.startsWith(`axum::extract::${extractor}<`)) {
      return { framework: "axum", extractor };
    }
    if (text.startsWith(`actix_web::web::${extractor}<`)) {
      return { framework: "actix-web", extractor };
    }
    for (const alias of imports.actixWebAliases) {
      if (text.startsWith(`${alias}::${extractor}<`)) {
        return { framework: "actix-web", extractor };
      }
    }
  }
  const first = typeTokens.find(({ kind }) => kind === "identifier")?.value;
  return first === undefined ? undefined : imports.extractorAliases.get(first);
}

function sourceParameters(
  parameter: readonly RustToken[],
  imports: RustImports,
): Array<{ name: string; source: RustSource }> {
  let depth = 0;
  let colon = -1;
  for (let index = 0; index < parameter.length; index += 1) {
    const value = parameter[index]?.value;
    if (value === "(" || value === "[" || value === "{") depth += 1;
    else if (value === ")" || value === "]" || value === "}") depth -= 1;
    else if (value === ":" && depth === 0) {
      colon = index;
      break;
    }
  }
  if (colon < 1) return [];
  const sourceType = extractorType(parameter.slice(colon + 1), imports);
  if (sourceType === undefined) return [];
  const pattern = parameter.slice(0, colon);
  const identifiers = pattern.filter(
    ({ kind, value }, index) =>
      kind === "identifier" &&
      value !== "mut" &&
      value !== "ref" &&
      /^[a-z_]/u.test(value) &&
      pattern[index - 1]?.value !== "::" &&
      pattern[index + 1]?.value !== "::" &&
      pattern[index + 1]?.value !== ":",
  );
  return identifiers
    .filter(
      (identifier, index, all) =>
        all.findIndex(({ value }) => value === identifier.value) === index,
    )
    .map((name) => ({
      name: name.value,
      source: {
        kind: "rust-http-extractor",
        ...sourceType,
        line: name.line,
        symbol: `${sourceType.framework}::${sourceType.extractor}(${name.value})`,
      },
    }));
}

function statements(tokens: readonly RustToken[]): RustToken[][] {
  const result: RustToken[][] = [];
  let start = 0;
  let parentheses = 0;
  let brackets = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    const value = tokens[index]?.value;
    if (value === "(") parentheses += 1;
    else if (value === ")") parentheses -= 1;
    else if (value === "[") brackets += 1;
    else if (value === "]") brackets -= 1;
    else if (value === ";" && parentheses === 0 && brackets === 0) {
      const statement = tokens.slice(start, index);
      if (statement.length > 0) result.push(statement);
      start = index + 1;
    }
  }
  const remainder = tokens.slice(start);
  if (remainder.length > 0) result.push(remainder);
  return result;
}

function assignment(
  tokens: readonly RustToken[],
): { name: string; expression: RustToken[]; line: number } | undefined {
  let letIndex = tokens.findIndex(({ value }) => value === "let");
  if (letIndex >= 0) {
    let nameIndex = letIndex + 1;
    if (tokens[nameIndex]?.value === "mut") nameIndex += 1;
    const name = tokens[nameIndex];
    if (name?.kind !== "identifier") return undefined;
    const equals = tokens.findIndex(
      ({ value }, index) => index > nameIndex && value === "=",
    );
    if (equals < 0) return undefined;
    return {
      name: name.value,
      expression: tokens.slice(equals + 1),
      line: name.line,
    };
  }
  letIndex = tokens.findIndex(({ kind }) => kind === "identifier");
  if (letIndex < 0 || tokens[letIndex + 1]?.value !== "=") return undefined;
  const name = tokens[letIndex];
  return {
    name: name?.value ?? "",
    expression: tokens.slice(letIndex + 2),
    line: name?.line ?? 1,
  };
}

function numericNormalization(tokens: readonly RustToken[]): boolean {
  const text = compact(tokens);
  return (
    new RegExp(`\\.parse::?<${NUMERIC_TYPES}>\\(`, "u").test(text) ||
    new RegExp(`${NUMERIC_TYPES}::from_str\\(`, "u").test(text)
  );
}

function expressionTaint(
  tokens: readonly RustToken[],
  taints: ReadonlyMap<string, RustTaint>,
  assignmentName?: string,
  assignmentLine?: number,
): RustTaint | undefined {
  if (numericNormalization(tokens)) return undefined;
  let matched: { token: RustToken; taint: RustTaint } | undefined;
  for (const token of tokens) {
    if (token.kind !== "identifier") continue;
    const taint = taints.get(token.value);
    if (taint !== undefined) {
      matched = { token, taint };
      break;
    }
  }
  if (matched === undefined) return undefined;
  const propagators = [...matched.taint.propagators];
  const line = assignmentLine ?? matched.token.line;
  if (assignmentName !== undefined) {
    propagators.push({
      kind: "rust-local-assignment",
      line,
      symbol: assignmentName,
    });
  }
  const text = compact(tokens);
  if (/\bformat!/u.test(text)) {
    propagators.push({ kind: "rust-format-macro", line });
  }
  if (tokens.some(({ value }) => value === "+" || value === "+=")) {
    propagators.push({ kind: "rust-string-concatenation", line });
  }
  if (/shell_escape|shell_words|\.escape\(/u.test(text)) {
    propagators.push({ kind: "rust-shell-escape-candidate", line });
  }
  return {
    source: matched.taint.source,
    propagators: propagators.slice(-16),
    controls: [...matched.taint.controls],
  };
}

function functionControls(tokens: readonly RustToken[]): Array<{
  kind: string;
  line: number;
}> {
  const controls: Array<{ kind: string; line: number }> = [];
  const add = (kind: string, line: number): void => {
    if (
      !controls.some(
        (control) => control.kind === kind && control.line === line,
      )
    ) {
      controls.push({ kind, line });
    }
  };
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token === undefined) continue;
    const window = compact(tokens.slice(index, index + 12));
    if (/^(?:Regex::new|regex::Regex::new)/u.test(window)) {
      add("process-input-regex", token.line);
    }
    if (/^(?:matches!|match)/u.test(window)) {
      add("process-input-literal-selection", token.line);
    }
    if (/^(?:shell_escape|shell_words)|\.escape\(/u.test(window)) {
      add("shell-argument-escape-candidate", token.line);
    }
    if (/^(?:tokio::time::timeout|timeout)\(/u.test(window)) {
      add("process-deadline", token.line);
    }
  }
  return controls.slice(0, 8);
}

function isCommandConstructor(
  tokens: readonly RustToken[],
  newIndex: number,
  imports: RustImports,
): RustCommandState["runtime"] | undefined {
  if (
    tokens[newIndex]?.value !== "new" ||
    tokens[newIndex - 1]?.value !== "::"
  ) {
    return undefined;
  }
  const segments: string[] = [];
  let index = newIndex - 2;
  while (index >= 0 && tokens[index]?.kind === "identifier") {
    segments.unshift(tokens[index]?.value ?? "");
    if (tokens[index - 1]?.value !== "::") break;
    index -= 2;
  }
  const path = segments.join("::");
  if (path === "std::process::Command") return "std";
  if (path === "tokio::process::Command") return "tokio";
  if (segments.length === 1) return imports.commandAliases.get(path);
  if (
    segments.length === 2 &&
    segments[1] === "Command" &&
    imports.processAliases.has(segments[0] ?? "")
  ) {
    return imports.processAliases.get(segments[0] ?? "");
  }
  return undefined;
}

function expandArguments(tokens: readonly RustToken[]): RustToken[][] {
  let start = tokens.findIndex(({ value }) => value === "[");
  if (start < 0) return [tokens.slice()];
  const end = matchingDelimiter(tokens, start);
  if (end === undefined) return [tokens.slice()];
  return splitTopLevel(tokens.slice(start + 1, end), ",");
}

function methodChain(
  tokens: readonly RustToken[],
  start: number,
  state: RustCommandState,
  unixCommandExt: boolean,
  windowsCommandExt: boolean,
): { state: RustCommandState; execution?: RustExecution } {
  let index = start;
  let execution: RustExecution | undefined;
  while (index < tokens.length) {
    if (tokens[index]?.value === "?" || tokens[index]?.value === "await") {
      index += 1;
      continue;
    }
    if (tokens[index]?.value !== ".") {
      index += 1;
      continue;
    }
    const method = tokens[index + 1];
    const open = tokens[index + 2];
    if (method?.kind !== "identifier" || open?.value !== "(") {
      index += 1;
      continue;
    }
    const close = matchingDelimiter(tokens, index + 2);
    if (close === undefined) break;
    const callArguments = tokens.slice(index + 3, close);
    if (
      method.value === "arg" ||
      (method.value === "raw_arg" &&
        (state.runtime === "tokio" || windowsCommandExt))
    ) {
      state.arguments.push({
        tokens: callArguments,
        line: method.line,
        raw: method.value === "raw_arg",
      });
    } else if (method.value === "args") {
      for (const argument of expandArguments(callArguments)) {
        state.arguments.push({
          tokens: argument,
          line: method.line,
          raw: false,
        });
      }
    } else if (
      EXECUTION_METHODS.has(method.value) &&
      (method.value !== "exec" || (state.runtime === "std" && unixCommandExt))
    ) {
      // Tokio status() and output() call spawn() before returning their future;
      // dropping that future does not make process creation inert.
      execution = {
        ...state,
        arguments: [...state.arguments],
        method: method.value as RustExecution["method"],
        line: method.line,
      };
    }
    index = close + 1;
  }
  return { state, execution };
}

function commandConstructor(
  tokens: readonly RustToken[],
  imports: RustImports,
): { state: RustCommandState; execution?: RustExecution } | undefined {
  for (let index = 0; index < tokens.length; index += 1) {
    const runtime = isCommandConstructor(tokens, index, imports);
    if (runtime === undefined) continue;
    if (tokens[index + 1]?.value !== "(") continue;
    const close = matchingDelimiter(tokens, index + 1);
    if (close === undefined) return undefined;
    const program = splitTopLevel(tokens.slice(index + 2, close), ",")[0];
    if (program === undefined || program.length === 0) return undefined;
    return methodChain(
      tokens,
      close + 1,
      {
        runtime,
        program,
        constructorLine: tokens[index]?.line ?? 1,
        arguments: [],
      },
      imports.unixCommandExt,
      imports.windowsCommandExt,
    );
  }
  return undefined;
}

function builderChain(
  tokens: readonly RustToken[],
  name: string,
  existing: RustCommandState,
  unixCommandExt: boolean,
  windowsCommandExt: boolean,
): { state: RustCommandState; execution?: RustExecution } | undefined {
  const index = tokens.findIndex(
    (token, candidate) =>
      token.value === name && tokens[candidate + 1]?.value === ".",
  );
  if (index < 0) return undefined;
  return methodChain(
    tokens,
    index + 1,
    { ...existing, arguments: [...existing.arguments] },
    unixCommandExt,
    windowsCommandExt,
  );
}

function literalArgument(
  tokens: readonly RustToken[],
  literals: ReadonlyMap<string, string>,
): string | undefined {
  const meaningful = tokens.filter(({ value }) => value !== "&");
  if (meaningful.length === 1 && meaningful[0]?.kind === "string") {
    return meaningful[0].value;
  }
  if (meaningful.length === 1 && meaningful[0]?.kind === "identifier") {
    return literals.get(meaningful[0].value);
  }
  const strings = meaningful.filter(({ kind }) => kind === "string");
  const text = compact(meaningful);
  if (
    strings.length === 1 &&
    /^(?:(?:OsStr|OsString|Path|PathBuf|String)::(?:from|new)|Cow::Borrowed)\(/u.test(
      text,
    )
  ) {
    return strings[0]?.value;
  }
  const base = meaningful.find(({ kind }) => kind === "identifier");
  if (
    base !== undefined &&
    literals.has(base.value) &&
    /\.(?:as_ref|as_str|clone|into|to_owned|to_string)\(\)$/u.test(text)
  ) {
    return literals.get(base.value);
  }
  return undefined;
}

function executableBase(value: string): string {
  return value.split(/[\\/]/u).at(-1)?.toLowerCase() ?? value.toLowerCase();
}

function executionRisk(
  execution: RustExecution,
  taints: ReadonlyMap<string, RustTaint>,
  literals: ReadonlyMap<string, string>,
): RustRisk | undefined {
  const programTaint = expressionTaint(execution.program, taints);
  if (programTaint !== undefined) {
    return {
      kind: "rust-process-executable-selection",
      taint: programTaint,
      argumentIndex: 0,
    };
  }
  for (const [index, argument] of execution.arguments.entries()) {
    if (!argument.raw) continue;
    const taint = expressionTaint(argument.tokens, taints);
    if (taint !== undefined) {
      return {
        kind: "rust-process-raw-command-line",
        taint,
        argumentIndex: index + 1,
      };
    }
  }
  const program = literalArgument(execution.program, literals);
  if (program === undefined) return undefined;
  const base = executableBase(program);
  const argumentLiterals = execution.arguments.map(({ tokens }) =>
    literalArgument(tokens, literals),
  );
  const tainted = execution.arguments.map(({ tokens }) =>
    expressionTaint(tokens, taints),
  );
  const commandAfter = (flags: ReadonlySet<string>): RustRisk | undefined => {
    for (let index = 0; index < argumentLiterals.length - 1; index += 1) {
      if (!flags.has((argumentLiterals[index] ?? "").toLowerCase())) continue;
      const taint = tainted[index + 1];
      if (taint !== undefined) {
        return {
          kind: "rust-process-shell-command",
          taint,
          argumentIndex: index + 2,
        };
      }
    }
    return undefined;
  };
  if (POSIX_SHELLS.has(base)) {
    const risk = commandAfter(new Set(["-c"]));
    if (risk !== undefined) return risk;
  }
  if (base === "cmd" || base === "cmd.exe") {
    const risk = commandAfter(new Set(["/c", "/k"]));
    if (risk !== undefined) return risk;
  }
  if (POWERSHELLS.has(base)) {
    const risk = commandAfter(new Set(["-c", "-command"]));
    if (risk !== undefined) return risk;
  }
  const flags = INTERPRETER_FLAGS.get(base);
  if (flags !== undefined) {
    const risk = commandAfter(flags);
    if (risk !== undefined) {
      return { ...risk, kind: "rust-process-interpreter-command" };
    }
  }
  if (base.endsWith(".bat") || base.endsWith(".cmd")) {
    const index = tainted.findIndex((taint) => taint !== undefined);
    const taint = tainted[index];
    if (index >= 0 && taint !== undefined) {
      return {
        kind: "rust-process-shell-command",
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

function productionRustPath(path: string): boolean {
  const normalized = path.replaceAll("\\", "/").toLowerCase();
  if (!normalized.endsWith(".rs")) return false;
  if (
    /(?:^|\/)(?:benches|examples|fixtures|target|tests?)(?:\/|$)/u.test(
      normalized,
    )
  ) {
    return false;
  }
  return !/(?:_test|_spec)\.rs$/u.test(normalized);
}

function recordForRisk(
  path: string,
  lines: readonly string[],
  execution: RustExecution,
  risk: RustRisk,
  controls: readonly { kind: string; line: number }[],
): RustCommandInjectionRecord {
  const startLine = Math.max(1, execution.line - CONTEXT_LINES_BEFORE);
  const endLine = Math.min(lines.length, execution.line + CONTEXT_LINES_AFTER);
  const sourceStart = Math.max(1, risk.taint.source.line - 1);
  const sourceEnd = Math.min(lines.length, risk.taint.source.line + 1);
  const candidateControls = [...risk.taint.controls, ...controls]
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
    line: execution.line,
    categories: ["rust-web-command-injection"],
    priority: 10,
    startLine,
    endLine,
    excerpt: excerpt(lines, startLine, endLine),
    sourceExcerpt: excerpt(lines, sourceStart, sourceEnd),
    frameworkModel: {
      schemaVersion: "1.2",
      id: "rust-web-command-injection",
      language: "rust",
      scope: "same-file",
      source: {
        kind: "rust-http-extractor",
        path,
        line: risk.taint.source.line,
        symbol: risk.taint.source.symbol,
      },
      sink: {
        kind: risk.kind,
        path,
        line: execution.line,
        symbol: `${execution.runtime}::process::Command;method=${execution.method};argument=${risk.argumentIndex}`,
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

export function rustCommandInjectionRecords(
  path: string,
  lines: readonly string[],
  text: string,
): RustCommandInjectionRecord[] {
  if (!productionRustPath(path)) return [];
  const tokens = rustTokens(text);
  if (tokens === undefined) return [];
  const imports = parseImports(tokens);
  const usesTokio =
    [...imports.commandAliases.values()].includes("tokio") ||
    [...imports.processAliases.values()].includes("tokio") ||
    compact(tokens).includes("tokio::process::Command::new");
  if (usesTokio && hasLocalTokioShadow(tokens)) return [];
  if (
    imports.commandAliases.size === 0 &&
    imports.processAliases.size === 0 &&
    !compact(tokens).includes("std::process::Command::new") &&
    !compact(tokens).includes("tokio::process::Command::new")
  ) {
    return [];
  }
  const records: RustCommandInjectionRecord[] = [];
  for (const function_ of rustFunctions(tokens)) {
    const taints = new Map<string, RustTaint>();
    const literals = new Map<string, string>();
    for (const parameter of function_.parameters) {
      for (const source of sourceParameters(parameter, imports)) {
        taints.set(source.name, {
          source: source.source,
          propagators: [],
          controls: [],
        });
      }
    }
    if (taints.size === 0) continue;
    const controls = functionControls(function_.body);
    const builders = new Map<string, RustCommandState>();
    for (const statement of statements(function_.body)) {
      const assigned = assignment(statement);
      const constructor = commandConstructor(statement, imports);
      if (assigned !== undefined && constructor === undefined) {
        builders.delete(assigned.name);
        const taint = expressionTaint(
          assigned.expression,
          taints,
          assigned.name,
          assigned.line,
        );
        if (taint === undefined) {
          taints.delete(assigned.name);
          const literal = literalArgument(assigned.expression, literals);
          if (literal === undefined) literals.delete(assigned.name);
          else literals.set(assigned.name, literal);
        } else {
          taints.set(assigned.name, taint);
          literals.delete(assigned.name);
        }
      }
      if (constructor !== undefined) {
        if (assigned !== undefined && constructor.execution === undefined) {
          builders.set(assigned.name, constructor.state);
          taints.delete(assigned.name);
          literals.delete(assigned.name);
        }
        if (constructor.execution !== undefined) {
          const risk = executionRisk(constructor.execution, taints, literals);
          if (risk !== undefined) {
            records.push(
              recordForRisk(path, lines, constructor.execution, risk, controls),
            );
          }
        }
      }
      for (const [name, builder] of [...builders]) {
        if (assigned?.name === name && constructor === undefined) continue;
        const chain = builderChain(
          statement,
          name,
          builder,
          imports.unixCommandExt,
          imports.windowsCommandExt,
        );
        if (chain === undefined) continue;
        builders.set(name, chain.state);
        if (chain.execution !== undefined) {
          const risk = executionRisk(chain.execution, taints, literals);
          if (risk !== undefined) {
            records.push(
              recordForRisk(path, lines, chain.execution, risk, controls),
            );
          }
        }
      }
      if (records.length >= MAX_RECORDS) break;
    }
    if (records.length >= MAX_RECORDS) break;
  }
  return records
    .filter(
      (record, index, all) =>
        all.findIndex(
          (candidate) =>
            candidate.path === record.path &&
            candidate.line === record.line &&
            candidate.frameworkModel.sink.kind ===
              record.frameworkModel.sink.kind &&
            candidate.frameworkModel.source.line ===
              record.frameworkModel.source.line,
        ) === index,
    )
    .slice(0, MAX_RECORDS);
}
