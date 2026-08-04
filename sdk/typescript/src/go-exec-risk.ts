import { posix } from "node:path";
import {
  assignedCallResult,
  fixedMapNames,
  fixedMapSelection,
  goAssignment,
  goCalls,
  goFunctions,
  goHttpRequestParameters,
  goImportAlias,
  maskGoLines,
  referencedTaint,
  requestSource,
  type GoCall,
  type GoFunction,
  type GoHttpSourceFile,
  type GoPropagator,
  type GoTaint,
} from "./go-http-risk.js";

const CONTEXT_LINES_BEFORE = 4;
const CONTEXT_LINES_AFTER = 6;
const MAX_RECORDS = 64;
const EXEC_IMPORTS = ["os/exec", "golang.org/x/sys/execabs"] as const;

type GoExecSinkKind =
  | "go-process-executable-selection"
  | "go-process-shell-command-execution"
  | "go-process-interpreter-script-selection"
  | "go-process-indirect-argument-execution";

export interface GoExecInjectionRecord {
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
    id: "go-os-exec-command-injection";
    language: "go";
    scope: "same-file" | "cross-file-wrapper";
    source: { kind: string; path: string; line: number };
    sink: {
      kind: GoExecSinkKind;
      path: string;
      line: number;
      cweIds: readonly ["CWE-78"];
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

interface ExecRisk {
  kind: GoExecSinkKind;
  source: GoTaint;
  controls: Array<{ kind: string; line: number }>;
}

interface ExecSink extends ExecRisk {
  line: number;
}

interface PendingCommand {
  endOffset: number;
  result?: string;
  risks: ExecRisk[];
}

interface WrapperSummary {
  file: GoHttpSourceFile;
  packageName: string;
  functionName: string;
  parameterName: string;
  parameterIndex: number;
  parameterLine: number;
  sink: ExecSink;
}

interface ConstructorSpecification {
  alias: string;
  nameIndex: number;
}

interface ParsedCall extends GoCall {
  endOffset: number;
}

const POSIX_SHELLS = new Set([
  "ash",
  "bash",
  "csh",
  "dash",
  "elvish",
  "fish",
  "ion",
  "ksh",
  "mksh",
  "nu",
  "osh",
  "sh",
  "tcsh",
  "xonsh",
  "yash",
  "zsh",
]);
const POWERSHELLS = new Set(["powershell", "pwsh"]);
const INTERPRETER_FLAGS = new Map<string, ReadonlySet<string>>([
  ["node", new Set(["--eval", "--print", "-e", "-p"])],
  ["nodejs", new Set(["--eval", "--print", "-e", "-p"])],
  ["perl", new Set(["-e"])],
  ["php", new Set(["-r"])],
  ["python", new Set(["-c"])],
  ["ruby", new Set(["-e"])],
]);
const UNSAFE_GIT_SUBCOMMANDS = new Set([
  "clone",
  "fetch",
  "fetch-pack",
  "ls-remote",
  "pull",
]);
const EXECUTION_METHODS = new Set(["CombinedOutput", "Output", "Run", "Start"]);

function requestParameters(function_: GoFunction): string[] {
  return goHttpRequestParameters(function_);
}

function commandAliases(function_: GoFunction): ConstructorSpecification[] {
  const specifications: ConstructorSpecification[] = [];
  for (const [index, packagePath] of EXEC_IMPORTS.entries()) {
    const fallback = index === 0 ? "exec" : "execabs";
    const alias = goImportAlias(function_.file.lines, packagePath, fallback);
    if (alias !== undefined) specifications.push({ alias, nameIndex: 0 });
  }
  return specifications;
}

function functionControls(
  function_: GoFunction,
): Array<{ kind: string; line: number }> {
  const controls: Array<{ kind: string; line: number }> = [];
  const add = (kind: string, line: number): void => {
    if (!controls.some((item) => item.kind === kind && item.line === line)) {
      controls.push({ kind, line });
    }
  };
  for (let line = function_.startLine; line <= function_.endLine; line += 1) {
    const structural = function_.structuralLines[line - 1] ?? "";
    if (
      /\bregexp\.(?:Compile|MatchString|MustCompile)\s*\(/u.test(structural)
    ) {
      add("process-input-allowlist", line);
    }
    if (/\bstrings\.(?:HasPrefix|Contains|Index)\s*\(/u.test(structural)) {
      add("process-argument-validation", line);
    }
    if (/\bcontext\.With(?:Deadline|Timeout)\s*\(/u.test(structural)) {
      add("process-deadline", line);
    }
    if (/\b[A-Za-z_]\w*\.LookPath\s*\(/u.test(structural)) {
      add("executable-path-resolution", line);
    }
  }
  return controls.slice(0, 8);
}

function matchingParenthesis(value: string, open: number): number {
  let depth = 0;
  for (let index = open; index < value.length; index += 1) {
    if (value[index] === "(") depth += 1;
    else if (value[index] === ")") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function parsedCalls(function_: GoFunction): {
  calls: ParsedCall[];
  structural: string;
} {
  const structural = function_.structuralLines
    .slice(function_.bodyStartLine - 1, function_.endLine)
    .join("\n");
  const calls = goCalls(function_).map((call): ParsedCall => {
    const open = structural.indexOf("(", call.offset + call.name.length);
    const close = open < 0 ? -1 : matchingParenthesis(structural, open);
    return { ...call, endOffset: close < 0 ? call.offset : close + 1 };
  });
  return { calls, structural };
}

function stringLiteral(expression: string): string | undefined {
  const trimmed = expression.trim();
  const raw = /^`([^`]*)`$/u.exec(trimmed);
  if (raw !== null) return raw[1];
  if (!/^"(?:\\.|[^"\\])*"$/u.test(trimmed)) return undefined;
  try {
    return JSON.parse(trimmed) as string;
  } catch {
    return trimmed.slice(1, -1);
  }
}

function fixedStringConstants(function_: GoFunction): Map<string, string> {
  const values = new Map<string, string>();
  const lines = maskGoLines(function_.file.lines, false);
  let braceDepth = 0;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!;
    const lineNumber = index + 1;
    const insideCurrentFunction =
      lineNumber >= function_.startLine && lineNumber <= function_.endLine;
    const match =
      /^\s*const\s+([A-Za-z_]\w*)(?:\s+string)?\s*=\s*((?:"(?:\\.|[^"\\])*")|(?:`[^`]*`))\s*$/u.exec(
        line,
      );
    if (match !== null && (braceDepth === 0 || insideCurrentFunction)) {
      const value = stringLiteral(match[2]!);
      if (value !== undefined) values.set(match[1]!, value);
    }
    for (const character of function_.structuralLines[index] ?? "") {
      if (character === "{") braceDepth += 1;
      else if (character === "}") braceDepth = Math.max(0, braceDepth - 1);
    }
  }
  return values;
}

function resolvedString(
  expression: string,
  fixedStrings: ReadonlyMap<string, string>,
): string | undefined {
  const literal = stringLiteral(expression);
  if (literal !== undefined) return literal;
  const identifier = /^([A-Za-z_]\w*)$/u.exec(expression.trim())?.[1];
  return identifier === undefined ? undefined : fixedStrings.get(identifier);
}

function executableName(
  expression: string,
  fixedStrings: ReadonlyMap<string, string>,
): string | undefined {
  const literal = resolvedString(expression, fixedStrings);
  if (literal === undefined) return undefined;
  const normalized = literal.replaceAll("\\", "/");
  const basename = normalized
    .slice(normalized.lastIndexOf("/") + 1)
    .toLowerCase();
  return basename.endsWith(".exe") ? basename.slice(0, -4) : basename;
}

function isWindowsBatch(
  expression: string,
  fixedStrings: ReadonlyMap<string, string>,
): boolean {
  const literal = resolvedString(expression, fixedStrings)?.toLowerCase();
  return (
    literal?.endsWith(".bat") === true || literal?.endsWith(".cmd") === true
  );
}

function sourceFor(
  expression: string | undefined,
  line: number,
  requests: readonly string[],
  taints: ReadonlyMap<string, GoTaint>,
  maps: ReadonlySet<string>,
): GoTaint | undefined {
  if (expression === undefined || fixedMapSelection(expression, maps, taints)) {
    return undefined;
  }
  return (
    requestSource(expression, requests, line) ??
    referencedTaint(expression, taints)?.taint
  );
}

function withConstruction(
  source: GoTaint,
  line: number,
  symbol: string,
): GoTaint {
  return {
    ...source,
    propagators: [
      ...source.propagators,
      { kind: "go-process-command-construction", line, symbol },
    ],
  };
}

function fixedFlag(
  expression: string | undefined,
  fixedStrings: ReadonlyMap<string, string>,
): string | undefined {
  return expression === undefined
    ? undefined
    : resolvedString(expression, fixedStrings)?.toLowerCase();
}

function shellGrammarPositions(
  executable: string,
  arguments_: readonly string[],
  fixedStrings: ReadonlyMap<string, string>,
): number[] {
  const positions: number[] = [];
  if (POSIX_SHELLS.has(executable)) {
    const flag = arguments_.findIndex((argument) => {
      const value = fixedFlag(argument, fixedStrings);
      return (
        value === "-c" ||
        (value?.startsWith("-") === true && /^[^-]*c/iu.test(value.slice(1)))
      );
    });
    if (flag >= 0 && flag + 1 < arguments_.length) positions.push(flag + 1);
    return positions;
  }
  if (executable === "cmd") {
    const flag = arguments_.findIndex((argument) =>
      ["/c", "/k"].includes(fixedFlag(argument, fixedStrings) ?? ""),
    );
    if (flag >= 0) {
      for (let index = flag + 1; index < arguments_.length; index += 1)
        positions.push(index);
    }
    return positions;
  }
  if (POWERSHELLS.has(executable)) {
    const flag = arguments_.findIndex((argument) =>
      ["-c", "-command", "-encodedcommand", "/c"].includes(
        fixedFlag(argument, fixedStrings) ?? "",
      ),
    );
    if (flag >= 0) {
      for (let index = flag + 1; index < arguments_.length; index += 1)
        positions.push(index);
    }
    return positions;
  }
  const interpreter = /^python[\d.\-vm]*$/u.test(executable)
    ? "python"
    : executable;
  const flags = INTERPRETER_FLAGS.get(interpreter);
  if (flags !== undefined) {
    const flag = arguments_.findIndex((argument) =>
      flags.has(fixedFlag(argument, fixedStrings) ?? ""),
    );
    if (flag >= 0 && flag + 1 < arguments_.length) positions.push(flag + 1);
  }
  return positions;
}

function isScriptInterpreter(executable: string): boolean {
  const interpreter = /^python[\d.\-vm]*$/u.test(executable)
    ? "python"
    : executable;
  return (
    POSIX_SHELLS.has(executable) ||
    POWERSHELLS.has(executable) ||
    INTERPRETER_FLAGS.has(interpreter)
  );
}

function optionTerminatedBefore(
  arguments_: readonly string[],
  position: number,
  fixedStrings: ReadonlyMap<string, string>,
): boolean {
  return arguments_
    .slice(0, position)
    .some((argument) => resolvedString(argument, fixedStrings) === "--");
}

function commandRisks(
  call: GoCall,
  nameIndex: number,
  requests: readonly string[],
  taints: ReadonlyMap<string, GoTaint>,
  maps: ReadonlySet<string>,
  fixedStrings: ReadonlyMap<string, string>,
  controls: Array<{ kind: string; line: number }>,
): ExecRisk[] {
  const risks: ExecRisk[] = [];
  const name = call.arguments[nameIndex];
  const rawName = call.rawArguments[nameIndex];
  if (name === undefined || rawName === undefined) return risks;
  const executableSource = sourceFor(name, call.line, requests, taints, maps);
  if (executableSource !== undefined) {
    risks.push({
      kind: "go-process-executable-selection",
      source: withConstruction(executableSource, call.line, "executable"),
      controls,
    });
    return risks;
  }
  const executable = executableName(rawName, fixedStrings);
  if (executable === undefined) return risks;
  const arguments_ = call.arguments.slice(nameIndex + 1);
  const rawArguments = call.rawArguments.slice(nameIndex + 1);
  const grammarPositions = isWindowsBatch(rawName, fixedStrings)
    ? rawArguments.map((_argument, index) => index)
    : shellGrammarPositions(executable, rawArguments, fixedStrings);
  for (const position of grammarPositions) {
    const source = sourceFor(
      arguments_[position],
      call.line,
      requests,
      taints,
      maps,
    );
    if (source !== undefined) {
      risks.push({
        kind: "go-process-shell-command-execution",
        source: withConstruction(source, call.line, `${executable} command`),
        controls,
      });
    }
  }
  if (grammarPositions.length === 0 && isScriptInterpreter(executable)) {
    const firstScript = rawArguments.findIndex((argument) => {
      const literal = resolvedString(argument, fixedStrings);
      return literal === undefined || !literal.startsWith("-");
    });
    if (firstScript >= 0) {
      const source = sourceFor(
        arguments_[firstScript],
        call.line,
        requests,
        taints,
        maps,
      );
      if (source !== undefined) {
        risks.push({
          kind: "go-process-interpreter-script-selection",
          source: withConstruction(source, call.line, `${executable} script`),
          controls,
        });
      }
    }
  }
  const indirectPositions: number[] = [];
  if (executable === "git") {
    const subcommand = fixedFlag(rawArguments[0], fixedStrings);
    if (subcommand !== undefined && UNSAFE_GIT_SUBCOMMANDS.has(subcommand)) {
      for (let index = 1; index < arguments_.length; index += 1)
        indirectPositions.push(index);
    }
  } else if (executable === "rsync") {
    for (let index = 0; index < arguments_.length; index += 1)
      indirectPositions.push(index);
  } else if (executable === "ssh") {
    const destination = resolvedString(rawArguments[0] ?? "", fixedStrings);
    if (destination !== undefined && !destination.startsWith("-")) {
      for (let index = 1; index < arguments_.length; index += 1)
        indirectPositions.push(index);
    }
  }
  for (const position of indirectPositions) {
    if (
      optionTerminatedBefore(rawArguments, position, fixedStrings) &&
      executable !== "ssh"
    )
      continue;
    const source = sourceFor(
      arguments_[position],
      call.line,
      requests,
      taints,
      maps,
    );
    if (source !== undefined) {
      risks.push({
        kind: "go-process-indirect-argument-execution",
        source: withConstruction(source, call.line, `${executable} argument`),
        controls,
      });
    }
  }
  const unique = new Map<string, ExecRisk>();
  for (const risk of risks) {
    unique.set(`${risk.kind}:${risk.source.kind}:${risk.source.line}`, risk);
  }
  return [...unique.values()];
}

function constructor(
  call: GoCall,
  specifications: readonly ConstructorSpecification[],
): ConstructorSpecification | undefined {
  for (const specification of specifications) {
    if (call.name === `${specification.alias}.Command`) {
      return specification;
    }
    if (call.name === `${specification.alias}.CommandContext`) {
      return { ...specification, nameIndex: 1 };
    }
  }
  return undefined;
}

function analyzeFunction(
  function_: GoFunction,
  initialTaints: ReadonlyMap<string, GoTaint> = new Map(),
): ExecSink[] {
  const specifications = commandAliases(function_);
  if (specifications.length === 0) return [];
  const requests = requestParameters(function_);
  const taints = new Map(initialTaints);
  const commands = new Map<string, ExecRisk[]>();
  const maps = fixedMapNames(function_);
  const fixedStrings = fixedStringConstants(function_);
  for (const parameter of function_.parameters)
    fixedStrings.delete(parameter.name);
  const controls = functionControls(function_);
  const rawLines = maskGoLines(function_.file.lines, false);
  const parsed = parsedCalls(function_);
  const callsByLine = new Map<number, ParsedCall[]>();
  for (const call of parsed.calls) {
    const existing = callsByLine.get(call.line) ?? [];
    existing.push(call);
    callsByLine.set(call.line, existing);
  }
  const sinks: ExecSink[] = [];
  let pending: PendingCommand | undefined;

  for (
    let line = function_.bodyStartLine;
    line <= function_.endLine;
    line += 1
  ) {
    const structural = function_.structuralLines[line - 1] ?? "";
    const assigned = goAssignment(structural);
    if (assigned !== undefined) {
      const primary = assigned.names[0]!;
      const rawAssigned = goAssignment(rawLines[line - 1] ?? "");
      const exactAlias = /^([A-Za-z_]\w*)$/u.exec(assigned.value.trim())?.[1];
      const commandAlias =
        exactAlias === undefined ? undefined : commands.get(exactAlias);
      const fixedAlias =
        exactAlias === undefined ? undefined : fixedStrings.get(exactAlias);
      const fixedLiteral =
        rawAssigned === undefined
          ? undefined
          : stringLiteral(rawAssigned.value);
      const source = requestSource(assigned.value, requests, line);
      const prior = referencedTaint(assigned.value, taints);
      const fixedSelection = fixedMapSelection(assigned.value, maps, taints);
      for (const name of assigned.names) {
        taints.delete(name);
        commands.delete(name);
        fixedStrings.delete(name);
      }
      if (commandAlias !== undefined) commands.set(primary, commandAlias);
      if (fixedLiteral !== undefined) fixedStrings.set(primary, fixedLiteral);
      else if (fixedAlias !== undefined) fixedStrings.set(primary, fixedAlias);
      if (!fixedSelection && source !== undefined) {
        taints.set(primary, source);
      } else if (!fixedSelection && prior !== undefined) {
        taints.set(primary, {
          ...prior.taint,
          propagators: [
            ...prior.taint.propagators,
            { kind: "go-string-assignment", line, symbol: primary },
          ],
        });
      }
    }

    for (const call of callsByLine.get(line) ?? []) {
      if (pending !== undefined && call.offset < pending.endOffset) continue;
      if (pending !== undefined) {
        const bridge = parsed.structural.slice(pending.endOffset, call.offset);
        const method = /^([A-Za-z_]\w*)$/u.exec(call.name)?.[1];
        if (
          /^\s*\.\s*$/u.test(bridge) &&
          method !== undefined &&
          EXECUTION_METHODS.has(method)
        ) {
          for (const risk of pending.risks)
            sinks.push({ ...risk, line: call.line });
          if (pending.result !== undefined) commands.delete(pending.result);
          pending = undefined;
          continue;
        }
        pending = undefined;
      }

      const result = assignedCallResult(call);
      const specification = constructor(call, specifications);
      if (specification !== undefined) {
        const risks = commandRisks(
          call,
          specification.nameIndex,
          requests,
          taints,
          maps,
          fixedStrings,
          controls,
        );
        if (result !== undefined) {
          taints.delete(result);
          if (risks.length > 0) commands.set(result, risks);
          else commands.delete(result);
        }
        if (risks.length > 0) {
          pending = {
            endOffset: call.endOffset,
            ...(result === undefined ? {} : { result }),
            risks,
          };
        }
        continue;
      }

      const receiverCall = /^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$/u.exec(call.name);
      if (receiverCall === null) continue;
      const receiver = receiverCall[1]!;
      const method = receiverCall[2]!;
      if (!EXECUTION_METHODS.has(method)) continue;
      const risks = commands.get(receiver);
      if (risks === undefined) continue;
      for (const risk of risks) sinks.push({ ...risk, line: call.line });
    }
  }
  return sinks;
}

function callerSourceForArgument(
  function_: GoFunction,
  callLine: number,
  argument: string,
): GoTaint | undefined {
  const requests = requestParameters(function_);
  if (requests.length === 0) return undefined;
  const direct = requestSource(argument, requests, callLine);
  if (direct !== undefined) return direct;
  const taints = new Map<string, GoTaint>();
  const maps = fixedMapNames(function_);
  for (let line = function_.bodyStartLine; line < callLine; line += 1) {
    const assigned = goAssignment(function_.structuralLines[line - 1] ?? "");
    if (assigned === undefined) continue;
    const primary = assigned.names[0]!;
    const source = requestSource(assigned.value, requests, line);
    const prior = referencedTaint(assigned.value, taints);
    const fixedSelection = fixedMapSelection(assigned.value, maps, taints);
    for (const name of assigned.names) taints.delete(name);
    if (!fixedSelection && source !== undefined) taints.set(primary, source);
    else if (!fixedSelection && prior !== undefined) {
      taints.set(primary, {
        ...prior.taint,
        propagators: [
          ...prior.taint.propagators,
          { kind: "go-string-assignment", line, symbol: primary },
        ],
      });
    }
  }
  return referencedTaint(argument, taints)?.taint;
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
  sink: ExecSink,
  propagators: GoPropagator[],
): GoExecInjectionRecord {
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
      "framework-dataflow:go-os-exec-command-injection",
      `modeled-source:${source.kind}`,
      `modeled-sink:${sink.kind}`,
      ...sink.controls.map((control) => `candidate-control:${control.kind}`),
    ],
    priority: 126,
    startLine,
    endLine,
    excerpt: excerpt(sinkFile.lines, startLine, endLine),
    sourceExcerpt: excerpt(sourceFile.lines, sourceStart, sourceEnd),
    frameworkModel: {
      schemaVersion: "1.2",
      id: "go-os-exec-command-injection",
      language: "go",
      scope,
      source: { kind: source.kind, path: sourceFile.path, line: source.line },
      sink: {
        kind: sink.kind,
        path: sinkFile.path,
        line: sink.line,
        cweIds: ["CWE-78"],
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

export function goExecInjectionRecords(
  files: readonly GoHttpSourceFile[],
): GoExecInjectionRecord[] {
  const functions = files
    .filter((file) => file.extension === ".go")
    .flatMap(goFunctions);
  const records: GoExecInjectionRecord[] = [];
  const emitted = new Set<string>();

  for (const function_ of functions) {
    if (requestParameters(function_).length === 0) continue;
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
    if (
      function_.receiver !== undefined ||
      commandAliases(function_).length === 0
    )
      continue;
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
        const argument = call.arguments[summary.parameterIndex];
        if (argument === undefined) continue;
        const source = callerSourceForArgument(caller, call.line, argument);
        if (source === undefined) continue;
        const identity = `${summary.file.path}:${summary.sink.line}:${summary.sink.kind}`;
        if (emitted.has(identity)) continue;
        emitted.add(identity);
        const wrapperSource: GoTaint = {
          ...source,
          propagators: [
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
        };
        records.push(
          record(
            caller.file,
            summary.file,
            "cross-file-wrapper",
            wrapperSource,
            { ...summary.sink, source: wrapperSource },
            wrapperSource.propagators,
          ),
        );
        if (records.length >= MAX_RECORDS) return records;
      }
    }
  }
  return records;
}
