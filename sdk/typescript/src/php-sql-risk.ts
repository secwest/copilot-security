const CONTEXT_LINES_BEFORE = 3;
const CONTEXT_LINES_AFTER = 5;
const MAX_PHP_TOKENS = 131_072;
const MAX_PHP_NESTING = 128;
const MAX_RECORDS = 64;
const MAX_EXCERPT_LINE_CHARACTERS = 2_048;

type TokenKind = "identifier" | "number" | "string" | "symbol" | "variable";
type DatabaseKind = "mysqli" | "pdo";

interface PhpToken {
  kind: TokenKind;
  value: string;
  line: number;
  column: number;
  references: string[];
}

interface PhpPropagator {
  kind:
    | "php-database-prepare"
    | "php-fixed-query-fragment-selection"
    | "php-string-concatenation"
    | "php-string-formatting"
    | "php-string-interpolation"
    | "php-variable-assignment";
  line: number;
  symbol?: string;
}

interface PhpTaint {
  sourceLine: number;
  sourceSymbol: string;
  propagators: PhpPropagator[];
  controls: Array<{ kind: string; line: number }>;
}

interface PhpCall {
  name: string;
  receiver?: string;
  line: number;
  openIndex: number;
  closeIndex: number;
  arguments: PhpToken[][];
}

interface PreparedStatement {
  database: DatabaseKind;
  receiver: string;
  taint: PhpTaint;
  line: number;
}

interface PhpSqlSink {
  kind:
    | "mysqli-direct-sql-execution"
    | "mysqli-tainted-prepared-execution"
    | "pdo-direct-sql-execution"
    | "pdo-tainted-prepared-execution";
  method: string;
  database: DatabaseKind;
  receiver: string;
  statement?: string;
  prepareLine?: number;
  line: number;
  taint: PhpTaint;
}

interface PhpClassScope {
  start: number;
  end: number;
  receivers: Map<string, DatabaseKind>;
}

export interface PhpSqlInjectionRecord {
  path: string;
  line: number;
  categories: ["php-pdo-mysqli-sql-injection"];
  priority: number;
  startLine: number;
  endLine: number;
  excerpt: string;
  sourceExcerpt: string;
  frameworkModel: {
    schemaVersion: "1.2";
    id: "php-pdo-mysqli-sql-injection";
    language: "php";
    scope: "same-file";
    source: {
      kind: "php-http-input";
      path: string;
      line: number;
      symbol: string;
    };
    sink: {
      kind: PhpSqlSink["kind"];
      path: string;
      line: number;
      symbol: string;
      cweIds: readonly ["CWE-89"];
    };
    propagators: Array<{
      kind: PhpPropagator["kind"];
      path: string;
      line: number;
      symbol?: string;
    }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

const HTTP_SUPERGLOBALS = new Set([
  "$_COOKIE",
  "$_GET",
  "$_POST",
  "$_REQUEST",
  "$_SERVER",
]);

function isIdentifierStart(character: string): boolean {
  return /[A-Za-z_\u0080-\uffff]/u.test(character);
}

function isIdentifierPart(character: string): boolean {
  return /[A-Za-z0-9_\u0080-\uffff]/u.test(character);
}

function stringReferences(value: string): string[] {
  const references = new Set<string>();
  for (const match of value.matchAll(
    /\$[A-Za-z_\u0080-\uffff][A-Za-z0-9_\u0080-\uffff]*(?:\s*->\s*[A-Za-z_\u0080-\uffff][A-Za-z0-9_\u0080-\uffff]*)*/gu,
  )) {
    references.add(match[0].replace(/\s+/gu, ""));
  }
  return [...references];
}

function phpTokens(source: string): PhpToken[] | undefined {
  const tokens: PhpToken[] = [];
  const delimiters: string[] = [];
  let index = 0;
  let line = 1;
  let column = 1;
  let inPhp = false;
  let sawOpeningTag = false;
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
    const text = source.slice(index, index + length);
    advance(text);
    index += length;
    return text;
  };
  const add = (token: PhpToken): boolean => {
    tokens.push(token);
    return tokens.length <= MAX_PHP_TOKENS;
  };

  while (index < source.length) {
    if (!inPhp) {
      const rest = source.slice(index);
      const opening = /^<\?(?:php(?=\s)|=|(?=\s))/iu.exec(rest);
      if (opening !== null) {
        sawOpeningTag = true;
        inPhp = true;
        consume(opening[0].length);
        continue;
      }
      const next = rest.search(/<\?/u);
      if (next < 0) {
        consume(rest.length);
      } else {
        consume(Math.max(1, next));
      }
      continue;
    }

    if (source.startsWith("?>", index)) {
      consume(2);
      inPhp = false;
      continue;
    }
    const character = source[index] ?? "";
    if (/\s/u.test(character)) {
      consume(1);
      continue;
    }
    if (
      source.startsWith("//", index) ||
      (character === "#" && source[index + 1] !== "[")
    ) {
      const end = source.slice(index).search(/\r\n|\r|\n/u);
      consume(end < 0 ? source.length - index : end);
      continue;
    }
    if (source.startsWith("/*", index)) {
      const end = source.indexOf("*/", index + 2);
      if (end < 0) return undefined;
      consume(end + 2 - index);
      continue;
    }

    if (source.startsWith("<<<", index)) {
      const startLine = line;
      const startColumn = column;
      const header =
        /^<<<[ \t]*(?:'([A-Za-z_][A-Za-z0-9_]*)'|"([A-Za-z_][A-Za-z0-9_]*)"|([A-Za-z_][A-Za-z0-9_]*))[^\r\n]*(?:\r\n|\r|\n)/u.exec(
          source.slice(index),
        );
      if (header === null) return undefined;
      const marker = header[1] ?? header[2] ?? header[3] ?? "";
      const nowdoc = header[1] !== undefined;
      const bodyStart = index + header[0].length;
      const terminator = new RegExp(
        `^[ \\t]*${marker}(;?)[ \\t]*(?:\\r\\n|\\r|\\n|$)`,
        "gmu",
      );
      terminator.lastIndex = bodyStart;
      const closing = terminator.exec(source);
      if (closing === null) return undefined;
      const body = source.slice(bodyStart, closing.index);
      if (
        !add({
          kind: "string",
          value: body,
          line: startLine,
          column: startColumn,
          references: nowdoc ? [] : stringReferences(body),
        })
      ) {
        return undefined;
      }
      const closingLine =
        line +
        (source.slice(index, closing.index).match(/\r\n|\r|\n/gu)?.length ?? 0);
      consume(closing.index + closing[0].length - index);
      if (closing[1] === ";") {
        if (
          !add({
            kind: "symbol",
            value: ";",
            line: closingLine,
            column: 1,
            references: [],
          })
        ) {
          return undefined;
        }
      }
      continue;
    }

    if (character === "'" || character === '"' || character === "`") {
      const quote = character;
      const startLine = line;
      const startColumn = column;
      let cursor = index + 1;
      let escaped = false;
      while (cursor < source.length) {
        const current = source[cursor] ?? "";
        if (!escaped && current === quote) break;
        if (!escaped && current === "\\") {
          escaped = true;
        } else {
          escaped = false;
        }
        cursor += 1;
      }
      if (cursor >= source.length) return undefined;
      const value = source.slice(index + 1, cursor);
      if (
        !add({
          kind: "string",
          value,
          line: startLine,
          column: startColumn,
          references: quote === "'" ? [] : stringReferences(value),
        })
      ) {
        return undefined;
      }
      consume(cursor + 1 - index);
      continue;
    }

    if (character === "$" && isIdentifierStart(source[index + 1] ?? "")) {
      const startLine = line;
      const startColumn = column;
      let cursor = index + 2;
      while (isIdentifierPart(source[cursor] ?? "")) cursor += 1;
      const value = source.slice(index, cursor);
      if (
        !add({
          kind: "variable",
          value,
          line: startLine,
          column: startColumn,
          references: [],
        })
      ) {
        return undefined;
      }
      consume(cursor - index);
      continue;
    }

    if (isIdentifierStart(character)) {
      const startLine = line;
      const startColumn = column;
      let cursor = index + 1;
      while (isIdentifierPart(source[cursor] ?? "")) cursor += 1;
      const value = source.slice(index, cursor);
      if (
        !add({
          kind: "identifier",
          value,
          line: startLine,
          column: startColumn,
          references: [],
        })
      ) {
        return undefined;
      }
      consume(cursor - index);
      continue;
    }

    if (/\d/u.test(character)) {
      const startLine = line;
      const startColumn = column;
      const number = /^(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|\d+(?:\.\d+)?)/u.exec(
        source.slice(index),
      );
      if (number === null) return undefined;
      if (
        !add({
          kind: "number",
          value: number[0],
          line: startLine,
          column: startColumn,
          references: [],
        })
      ) {
        return undefined;
      }
      consume(number[0].length);
      continue;
    }

    const operator = [
      "?->",
      "??=",
      "===",
      "!==",
      "<=>",
      "**=",
      "...",
      "->",
      "::",
      "=>",
      "==",
      "!=",
      "<=",
      ">=",
      "&&",
      "||",
      "??",
      ".=",
      "+=",
      "-=",
      "*=",
      "/=",
      "%=",
      "**",
      "++",
      "--",
      "<<",
      ">>",
      "&=",
      "|=",
      "^=",
    ].find((candidate) => source.startsWith(candidate, index));
    const symbol = operator ?? character;
    if (!/[!#$%&()*+,\-.\/:;<=>?@[\]^{|}~\\]/u.test(symbol[0] ?? "")) {
      return undefined;
    }
    if (symbol.length === 1) {
      const pairs: Record<string, string> = { "(": ")", "[": "]", "{": "}" };
      if (pairs[symbol] !== undefined) {
        delimiters.push(pairs[symbol]!);
        if (delimiters.length > MAX_PHP_NESTING) return undefined;
      } else if (/^[)\]}]$/u.test(symbol)) {
        if (delimiters.pop() !== symbol) return undefined;
      }
    }
    if (
      !add({
        kind: "symbol",
        value: symbol,
        line,
        column,
        references: [],
      })
    ) {
      return undefined;
    }
    consume(symbol.length);
  }
  if (!sawOpeningTag || delimiters.length !== 0) return undefined;
  return tokens;
}

function matchingDelimiter(
  tokens: PhpToken[],
  openIndex: number,
): number | undefined {
  const open = tokens[openIndex]?.value;
  const close =
    open === "(" ? ")" : open === "[" ? "]" : open === "{" ? "}" : undefined;
  if (close === undefined) return undefined;
  let depth = 0;
  for (let index = openIndex; index < tokens.length; index += 1) {
    if (tokens[index]?.value === open) depth += 1;
    if (tokens[index]?.value === close) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return undefined;
}

function findTokenValue(
  tokens: PhpToken[],
  value: string,
  start: number,
): number {
  for (let index = start; index < tokens.length; index += 1) {
    if (tokens[index]?.value === value) return index;
  }
  return -1;
}

function splitArguments(tokens: PhpToken[]): PhpToken[][] {
  const result: PhpToken[][] = [];
  let start = 0;
  let depth = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    const value = tokens[index]?.value;
    if (value === "(" || value === "[" || value === "{") depth += 1;
    if (value === ")" || value === "]" || value === "}") depth -= 1;
    if (value === "," && depth === 0) {
      result.push(tokens.slice(start, index));
      start = index + 1;
    }
  }
  if (start < tokens.length || result.length > 0)
    result.push(tokens.slice(start));
  return result;
}

function canonicalMember(tokens: PhpToken[]): string | undefined {
  let index = tokens.length - 1;
  const parts: string[] = [];
  const last = tokens[index];
  if (last?.kind === "variable") return last.value;
  if (last?.kind !== "identifier") return undefined;
  parts.unshift(last.value);
  index -= 1;
  while (index >= 1 && /^(?:\?->|->)$/u.test(tokens[index]?.value ?? "")) {
    const previous = tokens[index - 1];
    if (previous?.kind === "variable") {
      parts.unshift(previous.value);
      return parts.join("->");
    }
    if (previous?.kind !== "identifier") return undefined;
    parts.unshift(previous.value);
    index -= 2;
  }
  return undefined;
}

function phpCalls(tokens: PhpToken[]): PhpCall[] {
  const calls: PhpCall[] = [];
  for (let index = 0; index + 1 < tokens.length; index += 1) {
    const name = tokens[index];
    if (name?.kind !== "identifier" || tokens[index + 1]?.value !== "(")
      continue;
    const previous = tokens[index - 1]?.value;
    if (
      previous === "::" ||
      (tokens[index - 1]?.kind === "identifier" &&
        /^(?:function|new)$/iu.test(tokens[index - 1]!.value))
    ) {
      continue;
    }
    const closeIndex = matchingDelimiter(tokens, index + 1);
    if (closeIndex === undefined) continue;
    const receiver = /^(?:\?->|->)$/u.test(previous ?? "")
      ? canonicalMember(tokens.slice(0, index - 1))
      : undefined;
    calls.push({
      name: name.value.toLowerCase(),
      receiver,
      line: name.line,
      openIndex: index + 1,
      closeIndex,
      arguments: splitArguments(tokens.slice(index + 2, closeIndex)),
    });
  }
  return calls;
}

function statementSlices(tokens: PhpToken[]): PhpToken[][] {
  const statements: PhpToken[][] = [];
  let start = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index]?.value !== ";") continue;
    if (index > start) statements.push(tokens.slice(start, index));
    start = index + 1;
  }
  if (start < tokens.length) statements.push(tokens.slice(start));
  return statements;
}

function assignment(
  statement: PhpToken[],
): { append: boolean; target: string; value: PhpToken[] } | undefined {
  const equal = statement.findIndex((token) =>
    /^(?:\.=|=)$/u.test(token.value),
  );
  if (equal < 0) return undefined;
  const target = canonicalMember(statement.slice(0, equal));
  if (target === undefined) return undefined;
  return {
    append: statement[equal]?.value === ".=",
    target,
    value: statement.slice(equal + 1),
  };
}

function attackerControlledServerKey(key: string | undefined): boolean {
  return (
    key !== undefined &&
    (/^HTTP_/u.test(key) ||
      /^(?:ORIG_PATH_INFO|PATH_INFO|PHP_AUTH_DIGEST|PHP_AUTH_PW|PHP_AUTH_USER|QUERY_STRING|REQUEST_URI)$/u.test(
        key,
      ))
  );
}

function sourceFromExpression(tokens: PhpToken[]): PhpTaint | undefined {
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token?.kind === "variable" && HTTP_SUPERGLOBALS.has(token.value)) {
      const key =
        tokens[index + 1]?.value === "[" && tokens[index + 2]?.kind === "string"
          ? tokens[index + 2]!.value
          : undefined;
      if (
        key === undefined ||
        (token.value === "$_SERVER" && !attackerControlledServerKey(key))
      ) {
        continue;
      }
      return {
        sourceLine: token.line,
        sourceSymbol: `${token.value}${key === undefined ? "" : `[${key}]`}`,
        propagators: [],
        controls: [],
      };
    }
    if (token?.kind === "string") {
      const source =
        /\$(?:_COOKIE|_GET|_POST|_REQUEST|_SERVER)\s*\[\s*['"]([^'"]+)['"]\s*\]/gu.exec(
          token.value,
        );
      if (source !== null) {
        const root = /^\$[A-Z_]+/u.exec(source[0])?.[0];
        const key = source[1];
        if (
          root === undefined ||
          !HTTP_SUPERGLOBALS.has(root) ||
          (root === "$_SERVER" && !attackerControlledServerKey(key))
        ) {
          continue;
        }
        return {
          sourceLine: token.line,
          sourceSymbol: `${root}[${key}]`,
          propagators: [{ kind: "php-string-interpolation", line: token.line }],
          controls: [],
        };
      }
    }
  }
  for (const call of phpCalls(tokens)) {
    if (call.receiver !== undefined || call.name !== "filter_input") continue;
    const input = call.arguments[0]?.find(
      (token) => token.kind === "identifier",
    )?.value;
    const key = call.arguments[1]?.find(
      (token) => token.kind === "string",
    )?.value;
    if (
      /^INPUT_(?:COOKIE|GET|POST)$/u.test(input ?? "") ||
      (input === "INPUT_SERVER" && attackerControlledServerKey(key))
    ) {
      return {
        sourceLine: call.line,
        sourceSymbol: `filter_input(${input}${key === undefined ? "" : `,${key}`})`,
        propagators: [],
        controls: [],
      };
    }
  }
  return undefined;
}

function referencedTaint(
  tokens: PhpToken[],
  taints: ReadonlyMap<string, PhpTaint>,
): PhpTaint | undefined {
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token?.kind === "variable") {
      const member = canonicalMember(
        tokens.slice(index, Math.min(tokens.length, index + 5)),
      );
      if (member !== undefined && taints.has(member)) return taints.get(member);
      if (taints.has(token.value)) return taints.get(token.value);
    }
    if (token?.kind === "string") {
      for (const reference of token.references) {
        if (taints.has(reference)) return taints.get(reference);
      }
    }
  }
  return undefined;
}

function fixedLiteral(tokens: PhpToken[]): boolean {
  const meaningful = tokens.filter((token) => !/^[()]$/u.test(token.value));
  return (
    meaningful.length === 1 &&
    /^(?:identifier|number|string)$/u.test(meaningful[0]?.kind ?? "")
  );
}

function fixedTernarySelection(tokens: PhpToken[]): boolean {
  let depth = 0;
  let question = -1;
  let colon = -1;
  for (let index = 0; index < tokens.length; index += 1) {
    const value = tokens[index]?.value;
    if (value === "(" || value === "[" || value === "{") depth += 1;
    if (value === ")" || value === "]" || value === "}") depth -= 1;
    if (depth === 0 && value === "?" && question < 0) question = index;
    if (depth === 0 && value === ":" && question >= 0) {
      colon = index;
      break;
    }
  }
  return (
    question > 0 &&
    colon > question &&
    fixedLiteral(tokens.slice(question + 1, colon)) &&
    fixedLiteral(tokens.slice(colon + 1))
  );
}

function scalarSanitizer(tokens: PhpToken[]): boolean {
  const structural = tokens.map((token) => token.value.toLowerCase()).join(" ");
  if (/^\( (?:bool|boolean|double|float|int|integer) \)/u.test(structural))
    return true;
  const calls = phpCalls(tokens);
  if (
    calls.some(
      (call) =>
        call.receiver === undefined &&
        /^(?:boolval|floatval|intval)$/u.test(call.name),
    )
  ) {
    return true;
  }
  return calls.some(
    (call) =>
      call.receiver === undefined &&
      ((call.name === "filter_var" &&
        call.arguments[1]?.some(
          (token) =>
            token.kind === "identifier" &&
            /^FILTER_VALIDATE_(?:BOOLEAN|FLOAT|INT)$/u.test(token.value),
        )) ||
        (call.name === "filter_input" &&
          call.arguments[2]?.some(
            (token) =>
              token.kind === "identifier" &&
              /^FILTER_VALIDATE_(?:BOOLEAN|FLOAT|INT)$/u.test(token.value),
          ))),
  );
}

function expressionTaint(
  tokens: PhpToken[],
  taints: ReadonlyMap<string, PhpTaint>,
): PhpTaint | undefined {
  if (scalarSanitizer(tokens) || fixedTernarySelection(tokens))
    return undefined;
  const source =
    sourceFromExpression(tokens) ?? referencedTaint(tokens, taints);
  if (source === undefined) return undefined;
  const propagators = [...source.propagators];
  const controls = [...source.controls];
  const addPropagator = (propagator: PhpPropagator): void => {
    if (
      !propagators.some(
        (item) =>
          item.kind === propagator.kind && item.line === propagator.line,
      )
    ) {
      propagators.push(propagator);
    }
  };
  if (tokens.some((token) => token.value === ".")) {
    addPropagator({
      kind: "php-string-concatenation",
      line:
        tokens.find((token) => token.value === ".")?.line ?? source.sourceLine,
    });
  }
  const interpolation = tokens.find(
    (token) => token.kind === "string" && token.references.length > 0,
  );
  if (interpolation !== undefined) {
    addPropagator({
      kind: "php-string-interpolation",
      line: interpolation.line,
    });
  }
  if (
    phpCalls(tokens).some(
      (call) =>
        call.receiver === undefined &&
        /^(?:sprintf|vsprintf)$/u.test(call.name),
    )
  ) {
    addPropagator({
      kind: "php-string-formatting",
      line: tokens[0]?.line ?? source.sourceLine,
    });
  }
  for (const call of phpCalls(tokens)) {
    const kind =
      call.name === "mysqli_real_escape_string" ||
      (call.name === "real_escape_string" && call.receiver !== undefined) ||
      (call.name === "quote" && call.receiver !== undefined)
        ? "database-string-escaping-requires-same-connection-and-context"
        : /^(?:addcslashes|addslashes)$/u.test(call.name)
          ? "generic-string-escaping-is-not-sql-parameterization"
          : undefined;
    if (
      kind !== undefined &&
      !controls.some(
        (control) => control.kind === kind && control.line === call.line,
      )
    ) {
      controls.push({ kind, line: call.line });
    }
  }
  return {
    ...source,
    propagators: propagators.slice(0, 16),
    controls: controls.slice(0, 8),
  };
}

function databaseFromNew(tokens: PhpToken[]): DatabaseKind | undefined {
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index]?.kind !== "identifier" ||
      tokens[index]?.value.toLowerCase() !== "new"
    ) {
      continue;
    }
    let typeIndex = index + 1;
    if (tokens[typeIndex]?.value === "\\") typeIndex += 1;
    const name = tokens[typeIndex]?.value.toLowerCase();
    if (name === "pdo" || name === "mysqli") return name;
  }
  if (
    phpCalls(tokens).some(
      (call) => call.receiver === undefined && call.name === "mysqli_connect",
    )
  ) {
    return "mysqli";
  }
  return undefined;
}

function typedReceivers(tokens: PhpToken[]): Map<string, DatabaseKind> {
  const receivers = new Map<string, DatabaseKind>();
  for (let index = 0; index + 1 < tokens.length; index += 1) {
    const type = tokens[index];
    const variable = tokens[index + 1];
    if (type?.kind !== "identifier" || variable?.kind !== "variable") continue;
    const name = type.value.toLowerCase();
    if (name === "pdo" || name === "mysqli")
      receivers.set(variable.value, name);
  }
  return receivers;
}

function phpClassScopes(tokens: PhpToken[]): PhpClassScope[] {
  const classes: PhpClassScope[] = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index]?.kind !== "identifier" ||
      tokens[index]?.value.toLowerCase() !== "class" ||
      tokens[index - 1]?.value === "::"
    ) {
      continue;
    }
    const bodyOpen = findTokenValue(tokens, "{", index + 1);
    const declarationEnd = findTokenValue(tokens, ";", index + 1);
    if (bodyOpen < 0 || (declarationEnd >= 0 && declarationEnd < bodyOpen)) {
      continue;
    }
    const bodyClose = matchingDelimiter(tokens, bodyOpen);
    if (bodyClose === undefined) return [];
    const receivers = new Map<string, DatabaseKind>();
    for (let typeIndex = bodyOpen + 1; typeIndex < bodyClose; typeIndex += 1) {
      const type = tokens[typeIndex];
      const variable = tokens[typeIndex + 1];
      if (type?.kind !== "identifier" || variable?.kind !== "variable")
        continue;
      const database = type.value.toLowerCase();
      if (database !== "pdo" && database !== "mysqli") continue;
      const prefix: PhpToken[] = [];
      for (
        let prefixIndex = typeIndex - 1;
        prefixIndex >= Math.max(bodyOpen + 1, typeIndex - 6);
        prefixIndex -= 1
      ) {
        const candidate = tokens[prefixIndex];
        if (candidate === undefined || /^[(),;{}]$/u.test(candidate.value))
          break;
        prefix.push(candidate);
      }
      if (
        !prefix.some(
          (token) =>
            token.kind === "identifier" &&
            /^(?:private|protected|public|readonly|var)$/iu.test(token.value),
        ) ||
        prefix.some(
          (token) =>
            token.kind === "identifier" &&
            token.value.toLowerCase() === "static",
        )
      ) {
        continue;
      }
      receivers.set(`$this->${variable.value.slice(1)}`, database);
    }
    classes.push({ start: index, end: bodyClose, receivers });
  }
  return classes;
}

function prepareCall(
  call: PhpCall,
  receivers: ReadonlyMap<string, DatabaseKind>,
  taints: ReadonlyMap<string, PhpTaint>,
): PreparedStatement | undefined {
  let database: DatabaseKind | undefined;
  let receiver: string | undefined;
  let query: PhpToken[] | undefined;
  if (call.receiver !== undefined && call.name === "prepare") {
    database = receivers.get(call.receiver);
    receiver = call.receiver;
    query = call.arguments[0];
  } else if (call.receiver === undefined && call.name === "mysqli_prepare") {
    const connection = canonicalMember(call.arguments[0] ?? []);
    if (connection !== undefined && receivers.get(connection) === "mysqli") {
      database = "mysqli";
      receiver = connection;
      query = call.arguments[1];
    }
  }
  if (database === undefined || query === undefined || receiver === undefined)
    return undefined;
  const taint = expressionTaint(query, taints);
  return taint === undefined
    ? undefined
    : { database, receiver, taint, line: call.line };
}

function directSink(
  call: PhpCall,
  receivers: ReadonlyMap<string, DatabaseKind>,
  taints: ReadonlyMap<string, PhpTaint>,
): PhpSqlSink | undefined {
  let database: DatabaseKind | undefined;
  let receiver: string | undefined;
  let query: PhpToken[] | undefined;
  if (call.receiver !== undefined) {
    database = receivers.get(call.receiver);
    receiver = call.receiver;
    if (database === "pdo" && /^(?:exec|query)$/u.test(call.name)) {
      query = call.arguments[0];
    } else if (
      database === "mysqli" &&
      /^(?:execute_query|multi_query|query|real_query)$/u.test(call.name)
    ) {
      query = call.arguments[0];
    }
  } else if (
    /^mysqli_(?:execute_query|multi_query|query|real_query)$/u.test(call.name)
  ) {
    const connection = canonicalMember(call.arguments[0] ?? []);
    if (connection !== undefined && receivers.get(connection) === "mysqli") {
      database = "mysqli";
      receiver = connection;
      query = call.arguments[1];
    }
  }
  if (database === undefined || query === undefined || receiver === undefined)
    return undefined;
  const taint = expressionTaint(query, taints);
  if (taint === undefined) return undefined;
  return {
    kind:
      database === "pdo"
        ? "pdo-direct-sql-execution"
        : "mysqli-direct-sql-execution",
    method: call.name,
    database,
    receiver,
    line: call.line,
    taint,
  };
}

function scopeSinks(
  tokens: PhpToken[],
  inheritedReceivers: ReadonlyMap<string, DatabaseKind>,
): PhpSqlSink[] {
  const receivers = new Map(inheritedReceivers);
  for (const [name, database] of typedReceivers(tokens))
    receivers.set(name, database);
  const taints = new Map<string, PhpTaint>();
  const prepared = new Map<string, PreparedStatement>();
  const sinks: PhpSqlSink[] = [];

  for (const statement of statementSlices(tokens)) {
    const assigned = assignment(statement);
    const calls = phpCalls(statement);
    let pendingPrepared: PreparedStatement | undefined;
    for (const call of calls) {
      const sink = directSink(call, receivers, taints);
      if (sink !== undefined) sinks.push(sink);

      const preparedCall = prepareCall(call, receivers, taints);
      if (preparedCall !== undefined) pendingPrepared = preparedCall;

      let executed: PreparedStatement | undefined;
      if (call.receiver !== undefined && call.name === "execute") {
        executed = prepared.get(call.receiver);
      } else if (
        call.receiver === undefined &&
        /^(?:mysqli_execute|mysqli_stmt_execute)$/u.test(call.name)
      ) {
        const statementName = canonicalMember(call.arguments[0] ?? []);
        if (statementName !== undefined) executed = prepared.get(statementName);
      }
      if (executed !== undefined) {
        sinks.push({
          kind:
            executed.database === "pdo"
              ? "pdo-tainted-prepared-execution"
              : "mysqli-tainted-prepared-execution",
          method: call.name,
          database: executed.database,
          receiver: executed.receiver,
          statement: call.receiver ?? "<unknown-statement>",
          prepareLine: executed.line,
          line: call.line,
          taint: {
            ...executed.taint,
            propagators: [
              ...executed.taint.propagators,
              {
                kind: "php-database-prepare" as const,
                line: executed.line,
                symbol: `${executed.database}:${executed.receiver}`,
              },
            ].slice(0, 16),
          },
        });
      }
      const chainedExecution = calls.find(
        (candidate) =>
          candidate.openIndex > call.closeIndex && candidate.name === "execute",
      );
      if (preparedCall !== undefined && chainedExecution !== undefined) {
        sinks.push({
          kind:
            preparedCall.database === "pdo"
              ? "pdo-tainted-prepared-execution"
              : "mysqli-tainted-prepared-execution",
          method: "execute",
          database: preparedCall.database,
          receiver: preparedCall.receiver,
          statement: "<chained-statement>",
          prepareLine: preparedCall.line,
          line: chainedExecution.line,
          taint: {
            ...preparedCall.taint,
            propagators: [
              ...preparedCall.taint.propagators,
              {
                kind: "php-database-prepare" as const,
                line: preparedCall.line,
                symbol: `${preparedCall.database}:${preparedCall.receiver}`,
              },
            ].slice(0, 16),
          },
        });
      }
    }

    if (assigned === undefined) continue;
    const previousTaint = taints.get(assigned.target);
    if (assigned.append) {
      const appended = expressionTaint(assigned.value, taints) ?? previousTaint;
      if (appended !== undefined) {
        taints.set(assigned.target, {
          ...appended,
          propagators: [
            ...appended.propagators,
            {
              kind: "php-string-concatenation" as const,
              line:
                statement.find((token) => token.value === ".=")?.line ??
                appended.sourceLine,
              symbol: assigned.target,
            },
          ].slice(0, 16),
        });
      }
      continue;
    }
    taints.delete(assigned.target);
    prepared.delete(assigned.target);
    receivers.delete(assigned.target);

    const database = databaseFromNew(assigned.value);
    if (database !== undefined) receivers.set(assigned.target, database);

    if (pendingPrepared !== undefined)
      prepared.set(assigned.target, pendingPrepared);

    const taint = expressionTaint(assigned.value, taints);
    if (taint !== undefined) {
      taints.set(assigned.target, {
        ...taint,
        propagators: [
          ...taint.propagators,
          {
            kind: "php-variable-assignment" as const,
            line:
              statement.find((token) => token.value === "=")?.line ??
              taint.sourceLine,
            symbol: assigned.target,
          },
        ].slice(0, 16),
      });
    }
  }
  return sinks;
}

function functionScopes(tokens: PhpToken[]): Array<{
  body: PhpToken[];
  receivers: Map<string, DatabaseKind>;
  start: number;
  end: number;
}> {
  const scopes: Array<{
    body: PhpToken[];
    receivers: Map<string, DatabaseKind>;
    start: number;
    end: number;
  }> = [];
  const classes = phpClassScopes(tokens);
  for (let index = 0; index < tokens.length; index += 1) {
    if (
      tokens[index]?.kind !== "identifier" ||
      tokens[index]?.value.toLowerCase() !== "function"
    ) {
      continue;
    }
    const parametersOpen = findTokenValue(tokens, "(", index + 1);
    if (parametersOpen < 0) return [];
    const parametersClose = matchingDelimiter(tokens, parametersOpen);
    if (parametersClose === undefined) return [];
    const bodyOpen = findTokenValue(tokens, "{", parametersClose + 1);
    const declarationEnd = findTokenValue(tokens, ";", parametersClose + 1);
    if (declarationEnd >= 0 && (bodyOpen < 0 || declarationEnd < bodyOpen)) {
      index = declarationEnd;
      continue;
    }
    if (bodyOpen < 0) continue;
    const bodyClose = matchingDelimiter(tokens, bodyOpen);
    if (bodyClose === undefined) return [];
    const receivers = typedReceivers(
      tokens.slice(parametersOpen + 1, parametersClose),
    );
    const owner = classes
      .filter(
        (candidate) => candidate.start < index && candidate.end > bodyClose,
      )
      .sort(
        (left, right) => left.end - left.start - (right.end - right.start),
      )[0];
    for (const [name, database] of owner?.receivers ?? []) {
      receivers.set(name, database);
    }
    scopes.push({
      body: tokens.slice(bodyOpen + 1, bodyClose),
      receivers,
      start: index,
      end: bodyClose,
    });
    index = bodyClose;
  }
  return scopes;
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

export function phpSqlInjectionRecords(
  path: string,
  lines: readonly string[],
  source: string,
): PhpSqlInjectionRecord[] {
  if (!/\.(?:php|phtml)$/iu.test(path)) return [];
  const tokens = phpTokens(source);
  if (tokens === undefined || tokens.length === 0) return [];
  const scopes = functionScopes(tokens);
  const excluded = new Set<number>();
  for (const scope of scopes) {
    for (let index = scope.start; index <= scope.end; index += 1)
      excluded.add(index);
  }
  const globalTokens = tokens.filter((_, index) => !excluded.has(index));
  const sinks = [
    ...scopeSinks(globalTokens, new Map()),
    ...scopes.flatMap((scope) => scopeSinks(scope.body, scope.receivers)),
  ];
  const seen = new Set<string>();
  const records: PhpSqlInjectionRecord[] = [];
  for (const sink of sinks) {
    const key = `${sink.kind}:${sink.line}:${sink.taint.sourceLine}:${sink.taint.sourceSymbol}`;
    if (seen.has(key)) continue;
    seen.add(key);
    records.push({
      path,
      line: sink.line,
      categories: ["php-pdo-mysqli-sql-injection"],
      priority: 126,
      startLine: Math.max(1, sink.line - CONTEXT_LINES_BEFORE),
      endLine: Math.min(lines.length, sink.line + CONTEXT_LINES_AFTER),
      excerpt: excerpt(lines, sink.line),
      sourceExcerpt: excerpt(lines, sink.taint.sourceLine),
      frameworkModel: {
        schemaVersion: "1.2",
        id: "php-pdo-mysqli-sql-injection",
        language: "php",
        scope: "same-file",
        source: {
          kind: "php-http-input",
          path,
          line: sink.taint.sourceLine,
          symbol: sink.taint.sourceSymbol,
        },
        sink: {
          kind: sink.kind,
          path,
          line: sink.line,
          symbol: [
            `database=${sink.database}`,
            `receiver=${sink.receiver}`,
            sink.statement === undefined
              ? undefined
              : `statement=${sink.statement}`,
            sink.prepareLine === undefined
              ? undefined
              : `prepareLine=${sink.prepareLine}`,
            `method=${sink.method}`,
          ]
            .filter((value) => value !== undefined)
            .join(";"),
          cweIds: ["CWE-89"],
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
