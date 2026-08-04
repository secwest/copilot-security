import { posix } from "node:path";

const CONTEXT_LINES_BEFORE = 3;
const CONTEXT_LINES_AFTER = 5;
const MAX_FUNCTION_SIGNATURE_BYTES = 2_048;
const MAX_FUNCTIONS = 512;
const MAX_CALLS_PER_FUNCTION = 512;
const MAX_RECORDS = 64;

export interface GoHttpSourceFile {
  path: string;
  extension: string;
  lines: readonly string[];
  text: string;
}

export interface GoHttpSsrfRecord {
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
    id: "go-net-http-ssrf";
    language: "go";
    scope: "same-file" | "cross-file-wrapper";
    source: { kind: string; path: string; line: number };
    sink: {
      kind: string;
      path: string;
      line: number;
      cweIds: readonly ["CWE-918"];
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

export interface GoParameter {
  name: string;
  type: string;
}

export interface GoFunction {
  file: GoHttpSourceFile;
  packageName: string;
  httpAlias?: string;
  name: string;
  receiver?: string;
  parameters: GoParameter[];
  startLine: number;
  bodyStartLine: number;
  endLine: number;
  structuralLines: readonly string[];
}

export interface GoCall {
  name: string;
  arguments: string[];
  rawArguments: string[];
  line: number;
  offset: number;
  linePrefix: string;
}

export interface GoReceiverTypeSpecification {
  alias: string;
  typeNames: readonly string[];
}

export interface GoPropagator {
  kind: string;
  line: number;
  symbol?: string;
}

export interface GoTaint {
  kind: string;
  line: number;
  propagators: GoPropagator[];
}

interface FunctionSink {
  kind: "go-http-client-url" | "go-http-client-do";
  line: number;
  source: GoTaint;
  controls: Array<{ kind: string; line: number }>;
}

interface WrapperSummary {
  file: GoHttpSourceFile;
  packageName: string;
  functionName: string;
  parameterName: string;
  parameterIndex: number;
  parameterLine: number;
  sink: FunctionSink;
}

interface MaskState {
  blockComment: boolean;
  quote: '"' | "'" | "`" | "";
  escaped: boolean;
}

export function maskGoLines(
  lines: readonly string[],
  maskStrings: boolean,
): string[] {
  const state: MaskState = {
    blockComment: false,
    quote: "",
    escaped: false,
  };
  const result: string[] = [];
  for (const line of lines) {
    const output = [...line];
    for (let index = 0; index < output.length; index += 1) {
      const character = line[index]!;
      const next = line[index + 1] ?? "";
      if (state.blockComment) {
        output[index] = " ";
        if (character === "*" && next === "/") {
          if (index + 1 < output.length) output[index + 1] = " ";
          index += 1;
          state.blockComment = false;
        }
        continue;
      }
      if (state.quote !== "") {
        if (maskStrings) output[index] = " ";
        if (state.quote === "`") {
          if (character === "`") state.quote = "";
          continue;
        }
        if (state.escaped) state.escaped = false;
        else if (character === "\\") state.escaped = true;
        else if (character === state.quote) state.quote = "";
        continue;
      }
      if (character === "/" && next === "*") {
        output[index] = " ";
        if (index + 1 < output.length) output[index + 1] = " ";
        index += 1;
        state.blockComment = true;
      } else if (character === "/" && next === "/") {
        output.fill(" ", index);
        break;
      } else if (character === '"' || character === "'" || character === "`") {
        state.quote = character;
        state.escaped = false;
        if (maskStrings) output[index] = " ";
      }
    }
    result.push(output.join(""));
  }
  return result;
}

function lineStarts(value: string): number[] {
  const starts = [0];
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === "\n") starts.push(index + 1);
  }
  return starts;
}

function lineAt(starts: readonly number[], offset: number): number {
  let low = 0;
  let high = starts.length - 1;
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    if ((starts[middle] ?? 0) <= offset) low = middle + 1;
    else high = middle - 1;
  }
  return Math.max(1, high + 1);
}

function matchingDelimiter(
  value: string,
  open: number,
  opening: string,
  closing: string,
): number {
  let depth = 0;
  for (let index = open; index < value.length; index += 1) {
    if (value[index] === opening) depth += 1;
    else if (value[index] === closing) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function splitGoArguments(value: string): string[] {
  const result: string[] = [];
  let start = 0;
  let depth = 0;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]!;
    if (character === "(" || character === "[" || character === "{") {
      depth += 1;
    } else if (character === ")" || character === "]" || character === "}") {
      depth -= 1;
    } else if (character === "," && depth === 0) {
      result.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  result.push(value.slice(start).trim());
  return result;
}

function goParameters(value: string): GoParameter[] {
  const result: GoParameter[] = [];
  const pending: string[] = [];
  for (const part of splitGoArguments(value)) {
    const trimmed = part.trim();
    if (trimmed === "") continue;
    const declaration = /^([A-Za-z_]\w*)\s+([\s\S]+)$/u.exec(trimmed);
    if (declaration === null) {
      if (/^[A-Za-z_]\w*$/u.test(trimmed)) pending.push(trimmed);
      continue;
    }
    const name = declaration[1]!;
    const type = declaration[2]!.trim();
    for (const pendingName of pending.splice(0)) {
      result.push({ name: pendingName, type });
    }
    result.push({ name, type });
  }
  return result;
}

function packageName(lines: readonly string[]): string | undefined {
  const structural = maskGoLines(lines, true);
  for (const line of structural) {
    const match = /^\s*package\s+([A-Za-z_]\w*)\b/u.exec(line);
    if (match !== null) return match[1];
  }
  return undefined;
}

export function goImportAlias(
  lines: readonly string[],
  importPath: string,
  defaultAlias: string,
): string | undefined {
  const source = maskGoLines(lines, false).join("\n");
  const aliases: string[] = [];
  const path = escapeRegularExpression(importPath);
  for (const declaration of source.matchAll(
    new RegExp(
      `\\bimport\\s*(?:\\(([\\s\\S]*?)\\)|(?:([A-Za-z_]\\w*|[._])\\s+)?("${path}"))`,
      "gu",
    ),
  )) {
    if (declaration[1] !== undefined) {
      for (const entry of declaration[1].matchAll(
        new RegExp(`^\\s*(?:([A-Za-z_]\\w*|[._])\\s+)?"${path}"\\s*$`, "gmu"),
      )) {
        aliases.push(entry[1] ?? defaultAlias);
      }
    } else if (declaration[3] !== undefined) {
      aliases.push(declaration[2] ?? defaultAlias);
    }
  }
  if (aliases.length !== 1 || aliases[0] === "." || aliases[0] === "_") {
    return undefined;
  }
  return aliases[0];
}

function netHttpAlias(lines: readonly string[]): string | undefined {
  return goImportAlias(lines, "net/http", "http");
}

export function goFunctions(file: GoHttpSourceFile): GoFunction[] {
  const package_ = packageName(file.lines);
  if (package_ === undefined) return [];
  const httpAlias = netHttpAlias(file.lines);
  const structuralLines = maskGoLines(file.lines, true);
  const structural = structuralLines.join("\n");
  const starts = lineStarts(structural);
  const functions: GoFunction[] = [];
  const declaration = /\bfunc\s+(?:(\([^)]*\))\s*)?([A-Za-z_]\w*)\s*\(/gu;
  for (const match of structural.matchAll(declaration)) {
    if (functions.length >= MAX_FUNCTIONS) break;
    const matchOffset = match.index ?? 0;
    const open = structural.indexOf("(", matchOffset + match[0].length - 1);
    if (open < 0) continue;
    const close = matchingDelimiter(structural, open, "(", ")");
    if (close < 0) continue;
    const bodyOpen = structural.indexOf("{", close + 1);
    if (
      bodyOpen < 0 ||
      bodyOpen - matchOffset > MAX_FUNCTION_SIGNATURE_BYTES ||
      /\bfunc\b/u.test(structural.slice(close + 1, bodyOpen))
    ) {
      continue;
    }
    const bodyClose = matchingDelimiter(structural, bodyOpen, "{", "}");
    if (bodyClose < 0) continue;
    functions.push({
      file,
      packageName: package_,
      httpAlias,
      name: match[2]!,
      ...(match[1] === undefined ? {} : { receiver: match[1] }),
      parameters: goParameters(structural.slice(open + 1, close)),
      startLine: lineAt(starts, matchOffset),
      bodyStartLine: lineAt(starts, bodyOpen),
      endLine: lineAt(starts, bodyClose),
      structuralLines,
    });
  }
  return functions;
}

export function goCalls(function_: GoFunction): GoCall[] {
  const slice = function_.structuralLines
    .slice(function_.bodyStartLine - 1, function_.endLine)
    .join("\n");
  const rawSlice = maskGoLines(function_.file.lines, false)
    .slice(function_.bodyStartLine - 1, function_.endLine)
    .join("\n");
  const starts = lineStarts(slice);
  const calls: GoCall[] = [];
  for (const match of slice.matchAll(
    /\b([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)\s*\(/gu,
  )) {
    if (calls.length >= MAX_CALLS_PER_FUNCTION) break;
    const offset = match.index ?? 0;
    const open = slice.indexOf("(", offset + match[0].length - 1);
    if (open < 0) continue;
    const close = matchingDelimiter(slice, open, "(", ")");
    if (close < 0) continue;
    const previousNewline = slice.lastIndexOf("\n", offset - 1);
    calls.push({
      name: match[1]!.replace(/\s+/gu, ""),
      arguments: splitGoArguments(slice.slice(open + 1, close)),
      rawArguments: splitGoArguments(rawSlice.slice(open + 1, close)),
      line: function_.bodyStartLine + lineAt(starts, offset) - 1,
      offset,
      linePrefix: slice.slice(previousNewline + 1, offset),
    });
  }
  return calls;
}

export function escapeRegularExpression(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

export function goHttpRequestParameters(function_: GoFunction): string[] {
  const alias = function_.httpAlias;
  if (alias === undefined) return [];
  return function_.parameters
    .filter(
      (parameter) =>
        parameter.type.replace(/\s+/gu, "") === `*${alias}.Request`,
    )
    .map((parameter) => parameter.name);
}

export function goTypedReceiverNames(
  function_: GoFunction,
  specifications: readonly GoReceiverTypeSpecification[],
): Set<string> {
  if (specifications.length === 0) return new Set();
  const qualifiedType = `(?:${specifications
    .map(
      ({ alias, typeNames }) =>
        `${escapeRegularExpression(alias)}\\.(?:${typeNames
          .map(escapeRegularExpression)
          .join("|")})`,
    )
    .join("|")})`;
  const result = new Set<string>();
  for (const parameter of function_.parameters) {
    if (
      new RegExp(`^\\*?${qualifiedType}$`, "u").test(
        parameter.type.replace(/\s+/gu, ""),
      )
    ) {
      result.add(parameter.name);
    }
  }

  const structuralLines = maskGoLines(function_.file.lines, true);
  let braceDepth = 0;
  for (let index = 0; index < structuralLines.length; index += 1) {
    const line = structuralLines[index]!;
    const lineNumber = index + 1;
    const insideCurrentFunction =
      lineNumber >= function_.startLine && lineNumber <= function_.endLine;
    const declaration = new RegExp(
      `^\\s*var\\s+([A-Za-z_]\\w*)\\s+\\*?${qualifiedType}\\b`,
      "u",
    ).exec(line);
    if (declaration !== null && (braceDepth === 0 || insideCurrentFunction)) {
      result.add(declaration[1]!);
    }
    for (const character of line) {
      if (character === "{") braceDepth += 1;
      else if (character === "}") braceDepth = Math.max(0, braceDepth - 1);
    }
  }

  const receiver = /^\(\s*([A-Za-z_]\w*)\s+\*?([A-Za-z_]\w*)\s*\)$/u.exec(
    function_.receiver ?? "",
  );
  if (receiver === null) return result;
  const receiverName = receiver[1]!;
  const receiverType = escapeRegularExpression(receiver[2]!);
  const structural = structuralLines.join("\n");
  const structs = [
    ...structural.matchAll(
      new RegExp(
        `\\btype\\s+${receiverType}\\s+struct\\s*\\{([\\s\\S]*?)\\}`,
        "gu",
      ),
    ),
  ];
  if (structs.length !== 1) return result;
  const body = structs[0]![1]!;
  const field = new RegExp(
    `^\\s*([A-Za-z_]\\w*)\\s+\\*?${qualifiedType}\\b`,
    "gmu",
  );
  for (const match of body.matchAll(field)) {
    result.add(`${receiverName}.${match[1]!}`);
  }
  if (new RegExp(`^\\s*\\*?${qualifiedType}\\b`, "mu").test(body)) {
    result.add(receiverName);
  }
  return result;
}

export function requestSource(
  expression: string,
  requestParameters: readonly string[],
  line: number,
): GoTaint | undefined {
  for (const parameter of requestParameters) {
    const escaped = escapeRegularExpression(parameter);
    if (
      new RegExp(
        `\\b${escaped}\\.URL\\.Query\\s*\\(\\s*\\)\\.Get\\s*\\(`,
        "u",
      ).test(expression)
    ) {
      return { kind: "go-http-query-parameter", line, propagators: [] };
    }
    if (
      new RegExp(`\\b${escaped}\\.URL\\.Query\\s*\\(\\s*\\)\\s*\\[`, "u").test(
        expression,
      )
    ) {
      return { kind: "go-http-query-parameter", line, propagators: [] };
    }
    if (
      new RegExp(
        `\\b${escaped}\\.(?:FormValue|PostFormValue)\\s*\\(`,
        "u",
      ).test(expression)
    ) {
      return { kind: "go-http-form-value", line, propagators: [] };
    }
    if (
      new RegExp(
        `\\b${escaped}\\.(?:Form|PostForm)(?:\\.Get\\s*\\(|\\s*\\[)`,
        "u",
      ).test(expression)
    ) {
      return { kind: "go-http-form-value", line, propagators: [] };
    }
    if (new RegExp(`\\b${escaped}\\.PathValue\\s*\\(`, "u").test(expression)) {
      return { kind: "go-http-path-value", line, propagators: [] };
    }
    if (
      new RegExp(`\\b${escaped}\\.Header\\.Get\\s*\\(`, "u").test(expression)
    ) {
      return { kind: "go-http-header", line, propagators: [] };
    }
  }
  return undefined;
}

export function referencedTaint(
  expression: string,
  taints: ReadonlyMap<string, GoTaint>,
): { name: string; taint: GoTaint } | undefined {
  for (const [name, taint] of taints) {
    if (
      new RegExp(`\\b${escapeRegularExpression(name)}\\b`, "u").test(expression)
    ) {
      return { name, taint };
    }
  }
  return undefined;
}

export function fixedMapNames(function_: GoFunction): Set<string> {
  const maps = new Set<string>();
  const declarationLines = new Map<string, number>();
  for (let line = 1; line <= function_.file.lines.length; line += 1) {
    const structural = function_.structuralLines[line - 1] ?? "";
    const match =
      /\b(?:var\s+)?([A-Za-z_]\w*)\s*(?::=|=)\s*map\s*\[\s*string\s*\]\s*string\s*\{/u.exec(
        structural,
      );
    if (match !== null) {
      maps.add(match[1]!);
      declarationLines.set(match[1]!, line);
    }
  }
  for (const name of [...maps]) {
    const escaped = escapeRegularExpression(name);
    for (let line = 1; line <= function_.file.lines.length; line += 1) {
      if (line === declarationLines.get(name)) continue;
      const structural = function_.structuralLines[line - 1] ?? "";
      if (
        new RegExp(
          `^\\s*${escaped}\\s*=|\\b${escaped}\\s*\\[[^\\]]+\\]\\s*=`,
          "u",
        ).test(structural)
      ) {
        maps.delete(name);
        break;
      }
    }
  }
  return maps;
}

export function fixedMapSelection(
  expression: string,
  maps: ReadonlySet<string>,
  taints: ReadonlyMap<string, GoTaint>,
): boolean {
  const selection = /^\s*([A-Za-z_]\w*)\s*\[([\s\S]+)\]\s*$/u.exec(expression);
  return (
    selection !== null &&
    maps.has(selection[1]!) &&
    referencedTaint(selection[2]!, taints) !== undefined
  );
}

export function goAssignment(
  line: string,
): { names: string[]; value: string } | undefined {
  const match =
    /^\s*(?:var\s+)?([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::=|=)\s*([\s\S]+?)\s*;?\s*$/u.exec(
      line,
    );
  if (match === null) return undefined;
  return {
    names: match[1]!.split(",").map((name) => name.trim()),
    value: match[2]!,
  };
}

export function assignedCallResult(call: GoCall): string | undefined {
  const match =
    /(?:^|\s)([A-Za-z_]\w*)\s*(?:,\s*[A-Za-z_]\w*)*\s*(?::=|=)\s*$/u.exec(
      call.linePrefix,
    );
  return match?.[1];
}

function functionControls(
  function_: GoFunction,
  alias: string,
): Array<{ kind: string; line: number }> {
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
  for (let line = function_.startLine; line <= function_.endLine; line += 1) {
    const window = function_.structuralLines
      .slice(line - 1, Math.min(function_.endLine, line + 12))
      .join("\n");
    const current = function_.structuralLines[line - 1] ?? "";
    if (
      /\bCheckRedirect\s*:/u.test(current) &&
      new RegExp(
        `\\breturn\\s+(?:${escapeRegularExpression(alias)}\\.)?ErrUseLastResponse\\b|\\breturn\\s+(?:errors\\.)?New\\s*\\(`,
        "u",
      ).test(window)
    ) {
      add("redirects-disabled", line);
    }
    if (
      /\.Hostname\s*\(\s*\)/u.test(current) &&
      /\b(?:allowed|trusted)Hosts?\b/iu.test(window)
    ) {
      add("parsed-host-exact-allowlist", line);
    }
    if (/\b(?:LookupHost|LookupIP|LookupIPAddr)\s*\(/u.test(current)) {
      add("network-address-validation", line);
    }
    if (/\bDialContext\s*:/u.test(current)) {
      add("custom-network-dialer", line);
    }
    if (/\.Scheme\b[^\r\n]*(?:==|!=)[^\r\n]*$/u.test(current)) {
      add("allowed-url-scheme", line);
    }
  }
  return controls.slice(0, 8);
}

function analyzeFunction(
  function_: GoFunction,
  initialTaints: ReadonlyMap<string, GoTaint> = new Map(),
): FunctionSink[] {
  const alias = function_.httpAlias;
  if (alias === undefined) return [];
  const requestParameters = function_.parameters
    .filter(
      (parameter) =>
        parameter.type.replace(/\s+/gu, "") === `*${alias}.Request`,
    )
    .map((parameter) => parameter.name);
  const clientParameters = new Set(
    function_.parameters
      .filter((parameter) =>
        [`${alias}.Client`, `*${alias}.Client`].includes(
          parameter.type.replace(/\s+/gu, ""),
        ),
      )
      .map((parameter) => parameter.name),
  );
  const clients = new Set(clientParameters);
  const taints = new Map(initialTaints);
  const requestTaints = new Map<string, GoTaint>();
  const maps = fixedMapNames(function_);
  const callsByLine = new Map<number, GoCall[]>();
  for (const call of goCalls(function_)) {
    const existing = callsByLine.get(call.line) ?? [];
    existing.push(call);
    callsByLine.set(call.line, existing);
  }
  const controls = functionControls(function_, alias);
  const sinks: FunctionSink[] = [];

  for (
    let line = function_.bodyStartLine;
    line <= function_.endLine;
    line += 1
  ) {
    const structural = function_.structuralLines[line - 1] ?? "";
    const assigned = goAssignment(structural);
    if (assigned !== undefined) {
      const primary = assigned.names[0]!;
      const source = requestSource(assigned.value, requestParameters, line);
      const prior = referencedTaint(assigned.value, taints);
      const selectsFixedDestination = fixedMapSelection(
        assigned.value,
        maps,
        taints,
      );
      for (const name of assigned.names) {
        taints.delete(name);
        clients.delete(name);
        requestTaints.delete(name);
      }
      if (selectsFixedDestination) {
        taints.delete(primary);
      } else if (source !== undefined) {
        taints.set(primary, source);
      } else if (prior !== undefined) {
        taints.set(primary, {
          ...prior.taint,
          propagators: [
            ...prior.taint.propagators,
            { kind: "go-string-assignment", line, symbol: primary },
          ],
        });
      } else {
        taints.delete(primary);
      }

      const compactValue = assigned.value.replace(/\s+/gu, "");
      if (
        new RegExp(
          `^(?:&?${escapeRegularExpression(alias)}\\.Client\\{|new\\(${escapeRegularExpression(alias)}\\.Client\\)|${escapeRegularExpression(alias)}\\.DefaultClient)`,
          "u",
        ).test(compactValue)
      ) {
        clients.add(primary);
      }
    }

    for (const call of callsByLine.get(line) ?? []) {
      const sourceFor = (argument: string | undefined): GoTaint | undefined => {
        if (argument === undefined) return undefined;
        return (
          requestSource(argument, requestParameters, line) ??
          referencedTaint(argument, taints)?.taint
        );
      };
      const packageClient = new RegExp(
        `^${escapeRegularExpression(alias)}\\.(?:Get|Head|Post|PostForm)$`,
        "u",
      );
      const clientMethod = /^([A-Za-z_]\w*)\.(Get|Head|Post|PostForm)$/u.exec(
        call.name,
      );
      const defaultClientMethod = new RegExp(
        `^${escapeRegularExpression(alias)}\\.DefaultClient\\.(?:Get|Head|Post|PostForm)$`,
        "u",
      );
      if (
        packageClient.test(call.name) ||
        defaultClientMethod.test(call.name) ||
        (clientMethod !== null && clients.has(clientMethod[1]!))
      ) {
        const source = sourceFor(call.arguments[0]);
        if (source !== undefined) {
          sinks.push({ kind: "go-http-client-url", line, source, controls });
        }
        continue;
      }

      const requestConstructor = new RegExp(
        `^${escapeRegularExpression(alias)}\\.(NewRequest|NewRequestWithContext)$`,
        "u",
      ).exec(call.name);
      if (requestConstructor !== null) {
        const urlIndex = requestConstructor[1] === "NewRequest" ? 1 : 2;
        const source = sourceFor(call.arguments[urlIndex]);
        const result = assignedCallResult(call);
        if (source !== undefined && result !== undefined) {
          requestTaints.set(result, {
            ...source,
            propagators: [
              ...source.propagators,
              {
                kind: "go-http-request-construction",
                line,
                symbol: result,
              },
            ],
          });
        }
        continue;
      }

      const doClient = /^([A-Za-z_]\w*)\.Do$/u.exec(call.name);
      const defaultDo = new RegExp(
        `^${escapeRegularExpression(alias)}\\.DefaultClient\\.Do$`,
        "u",
      ).test(call.name);
      if (!defaultDo && (doClient === null || !clients.has(doClient[1]!))) {
        continue;
      }
      const request = call.arguments[0]?.trim();
      const source =
        request === undefined ? undefined : requestTaints.get(request);
      if (source !== undefined) {
        sinks.push({ kind: "go-http-client-do", line, source, controls });
      }
    }
  }
  return sinks;
}

function callerSourceForArgument(
  function_: GoFunction,
  callLine: number,
  argument: string,
): GoTaint | undefined {
  const alias = function_.httpAlias;
  if (alias === undefined) return undefined;
  const requestParameters = function_.parameters
    .filter(
      (parameter) =>
        parameter.type.replace(/\s+/gu, "") === `*${alias}.Request`,
    )
    .map((parameter) => parameter.name);
  if (requestParameters.length === 0) return undefined;
  const direct = requestSource(argument, requestParameters, callLine);
  if (direct !== undefined) return direct;
  const taints = new Map<string, GoTaint>();
  const maps = fixedMapNames(function_);
  for (let line = function_.bodyStartLine; line < callLine; line += 1) {
    const assigned = goAssignment(function_.structuralLines[line - 1] ?? "");
    if (assigned === undefined) continue;
    const primary = assigned.names[0]!;
    const source = requestSource(assigned.value, requestParameters, line);
    const prior = referencedTaint(assigned.value, taints);
    if (fixedMapSelection(assigned.value, maps, taints)) taints.delete(primary);
    else if (source !== undefined) taints.set(primary, source);
    else if (prior !== undefined) {
      taints.set(primary, {
        ...prior.taint,
        propagators: [
          ...prior.taint.propagators,
          { kind: "go-string-assignment", line, symbol: primary },
        ],
      });
    } else taints.delete(primary);
  }
  return referencedTaint(argument, taints)?.taint;
}

function sourceExcerpt(
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
  sink: FunctionSink,
  propagators: GoPropagator[],
): GoHttpSsrfRecord {
  const startLine = Math.max(1, sink.line - CONTEXT_LINES_BEFORE);
  const endLine = Math.min(
    sinkFile.lines.length,
    sink.line + CONTEXT_LINES_AFTER,
  );
  const sourceStart = Math.max(1, source.line - 2);
  const sourceEnd = Math.min(sourceFile.lines.length, source.line + 2);
  return {
    path: sinkFile.path,
    line: sink.line,
    categories: [
      "framework-dataflow:go-net-http-ssrf",
      `modeled-source:${source.kind}`,
      `modeled-sink:${sink.kind}`,
      ...sink.controls.map((control) => `candidate-control:${control.kind}`),
    ],
    priority: 119,
    startLine,
    endLine,
    excerpt: sourceExcerpt(sinkFile.lines, startLine, endLine),
    sourceExcerpt: sourceExcerpt(sourceFile.lines, sourceStart, sourceEnd),
    frameworkModel: {
      schemaVersion: "1.2",
      id: "go-net-http-ssrf",
      language: "go",
      scope,
      source: { kind: source.kind, path: sourceFile.path, line: source.line },
      sink: {
        kind: sink.kind,
        path: sinkFile.path,
        line: sink.line,
        cweIds: ["CWE-918"],
      },
      propagators: propagators.map((propagator) => ({
        ...propagator,
        path:
          propagator.kind === "go-function-argument"
            ? sourceFile.path
            : sinkFile.path,
      })),
      candidateControls: sink.controls.map((control) => ({
        ...control,
        path: sinkFile.path,
      })),
    },
  };
}

export function goHttpSsrfRecords(
  files: readonly GoHttpSourceFile[],
): GoHttpSsrfRecord[] {
  const goFiles = files.filter((file) => file.extension === ".go");
  const functions = goFiles.flatMap(goFunctions);
  const records: GoHttpSsrfRecord[] = [];
  const emitted = new Set<string>();

  for (const function_ of functions) {
    if (function_.httpAlias === undefined) continue;
    const hasRequest = function_.parameters.some(
      (parameter) =>
        parameter.type.replace(/\s+/gu, "") ===
        `*${function_.httpAlias}.Request`,
    );
    if (!hasRequest) continue;
    for (const sink of analyzeFunction(function_)) {
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
          sink.source.propagators,
        ),
      );
      if (records.length >= MAX_RECORDS) return records;
    }
  }

  const summaries: WrapperSummary[] = [];
  for (const function_ of functions) {
    if (function_.receiver !== undefined || function_.httpAlias === undefined) {
      continue;
    }
    function_.parameters.forEach((parameter, parameterIndex) => {
      if (parameter.type.replace(/\s+/gu, "") !== "string") return;
      const initial = new Map<string, GoTaint>([
        [
          parameter.name,
          {
            kind: "go-string-parameter",
            line: function_.startLine,
            propagators: [],
          },
        ],
      ]);
      for (const sink of analyzeFunction(function_, initial)) {
        summaries.push({
          file: function_.file,
          packageName: function_.packageName,
          functionName: function_.name,
          parameterName: parameter.name,
          parameterIndex,
          parameterLine: function_.startLine,
          sink,
        });
      }
    });
  }

  const functionCounts = new Map<string, number>();
  for (const function_ of functions) {
    if (function_.receiver !== undefined) continue;
    const key = `${posix.dirname(function_.file.path)}\0${function_.packageName}\0${function_.name}`;
    functionCounts.set(key, (functionCounts.get(key) ?? 0) + 1);
  }
  for (const caller of functions) {
    if (caller.httpAlias === undefined) continue;
    const calls = goCalls(caller);
    for (const summary of summaries) {
      if (
        posix.dirname(summary.file.path) !== posix.dirname(caller.file.path) ||
        summary.packageName !== caller.packageName
      ) {
        continue;
      }
      const summaryKey = `${posix.dirname(summary.file.path)}\0${summary.packageName}\0${summary.functionName}`;
      if (functionCounts.get(summaryKey) !== 1) continue;
      for (const call of calls.filter(
        (candidate) => candidate.name === summary.functionName,
      )) {
        const argument = call.arguments[summary.parameterIndex];
        if (argument === undefined) continue;
        const source = callerSourceForArgument(caller, call.line, argument);
        if (source === undefined) continue;
        const identity = `${caller.file.path}:${call.line}:${summary.file.path}:${summary.sink.line}:${summary.parameterIndex}`;
        if (emitted.has(identity)) continue;
        emitted.add(identity);
        records.push(
          record(
            caller.file,
            summary.file,
            summary.file.path === caller.file.path
              ? "same-file"
              : "cross-file-wrapper",
            source,
            summary.sink,
            [
              ...source.propagators,
              {
                kind: "go-function-argument",
                line: call.line,
                symbol: `${summary.functionName}[${summary.parameterIndex}]`,
              },
              {
                kind: "go-string-parameter",
                line: summary.parameterLine,
                symbol: summary.parameterName,
              },
              ...summary.sink.source.propagators,
            ],
          ),
        );
        if (records.length >= MAX_RECORDS) return records;
      }
    }
  }
  return records;
}
