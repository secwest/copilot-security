import { posix } from "node:path";
import {
  fixedMapNames,
  goAssignment,
  goCalls,
  goFunctions,
  goHttpRequestParameters,
  goImportAlias,
  referencedTaint,
  requestSource,
  type GoFunction,
  type GoHttpSourceFile,
  type GoPropagator,
  type GoTaint,
} from "./go-http-risk.js";

const CONTEXT_LINES_BEFORE = 4;
const CONTEXT_LINES_AFTER = 6;
const MAX_RECORDS = 64;

type GoPathSinkKind =
  | "go-filesystem-read-path"
  | "go-filesystem-open-path"
  | "go-filesystem-write-path"
  | "go-filesystem-delete-path"
  | "go-filesystem-metadata-path"
  | "go-filesystem-link-source-path"
  | "go-filesystem-link-destination-path"
  | "go-filesystem-move-source-path"
  | "go-filesystem-move-destination-path"
  | "go-filesystem-root-selection"
  | "go-filesystem-walk-root"
  | "go-http-file-response-path";

export interface GoPathTraversalRecord {
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
    id: "go-http-filesystem-path";
    language: "go";
    scope: "same-file" | "cross-file-wrapper";
    source: { kind: string; path: string; line: number };
    sink: {
      kind: GoPathSinkKind;
      path: string;
      line: number;
      cweIds: readonly ["CWE-22", "CWE-23", "CWE-36", "CWE-73"];
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

interface PathSinkSpecification {
  callName: string;
  argumentIndex: number;
  kind: GoPathSinkKind;
  role: string;
}

interface PathSink {
  kind: GoPathSinkKind;
  line: number;
  argumentIndex: number;
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
  sink: PathSink;
}

function requestParameters(function_: GoFunction): string[] {
  return goHttpRequestParameters(function_);
}

function pathSinkSpecifications(
  function_: GoFunction,
): PathSinkSpecification[] {
  const result: PathSinkSpecification[] = [];
  const add = (
    alias: string,
    method: string,
    argumentIndex: number,
    kind: GoPathSinkKind,
    role: string,
  ): void => {
    result.push({
      callName: `${alias}.${method}`,
      argumentIndex,
      kind,
      role,
    });
  };

  const osAlias = goImportAlias(function_.file.lines, "os", "os");
  if (osAlias !== undefined) {
    for (const method of ["Open", "ReadFile", "ReadDir"]) {
      add(osAlias, method, 0, "go-filesystem-read-path", "read path");
    }
    add(osAlias, "OpenFile", 0, "go-filesystem-open-path", "open path");
    add(
      osAlias,
      "OpenInRoot",
      0,
      "go-filesystem-root-selection",
      "filesystem root",
    );
    add(
      osAlias,
      "OpenRoot",
      0,
      "go-filesystem-root-selection",
      "filesystem root",
    );
    for (const method of [
      "Create",
      "CreateTemp",
      "Mkdir",
      "MkdirAll",
      "MkdirTemp",
      "WriteFile",
      "Truncate",
    ]) {
      add(osAlias, method, 0, "go-filesystem-write-path", "write path");
    }
    for (const method of ["Remove", "RemoveAll"]) {
      add(osAlias, method, 0, "go-filesystem-delete-path", "delete path");
    }
    for (const method of [
      "Stat",
      "Lstat",
      "Readlink",
      "Chdir",
      "Chmod",
      "Chown",
      "Lchown",
      "Chtimes",
    ]) {
      add(osAlias, method, 0, "go-filesystem-metadata-path", "metadata path");
    }
    add(osAlias, "Rename", 0, "go-filesystem-move-source-path", "move source");
    add(
      osAlias,
      "Rename",
      1,
      "go-filesystem-move-destination-path",
      "move destination",
    );
    for (const method of ["Link", "Symlink"]) {
      add(osAlias, method, 0, "go-filesystem-link-source-path", "link source");
      add(
        osAlias,
        method,
        1,
        "go-filesystem-link-destination-path",
        "link destination",
      );
    }
  }

  const ioutilAlias = goImportAlias(
    function_.file.lines,
    "io/ioutil",
    "ioutil",
  );
  if (ioutilAlias !== undefined) {
    for (const method of ["ReadFile", "ReadDir"]) {
      add(ioutilAlias, method, 0, "go-filesystem-read-path", "read path");
    }
    for (const method of ["WriteFile", "TempFile", "TempDir"]) {
      add(ioutilAlias, method, 0, "go-filesystem-write-path", "write path");
    }
  }

  const filepathAlias = goImportAlias(
    function_.file.lines,
    "path/filepath",
    "filepath",
  );
  if (filepathAlias !== undefined) {
    for (const method of ["Walk", "WalkDir"]) {
      add(filepathAlias, method, 0, "go-filesystem-walk-root", "walk root");
    }
  }

  const httpAlias = function_.httpAlias;
  if (httpAlias !== undefined) {
    add(
      httpAlias,
      "ServeFile",
      2,
      "go-http-file-response-path",
      "response file path",
    );
    add(
      httpAlias,
      "ServeFileFS",
      3,
      "go-http-file-response-path",
      "response filesystem path",
    );
  }
  return result;
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
  const filepathAlias = goImportAlias(
    function_.file.lines,
    "path/filepath",
    "filepath",
  );
  const osAlias = goImportAlias(function_.file.lines, "os", "os");
  const fsAlias = goImportAlias(function_.file.lines, "io/fs", "fs");
  const regexpAlias = goImportAlias(function_.file.lines, "regexp", "regexp");
  const stringsAlias = goImportAlias(
    function_.file.lines,
    "strings",
    "strings",
  );
  const relativePaths = new Map<string, number>();
  if (filepathAlias !== undefined) {
    const escapedFilepath = filepathAlias.replace(
      /[.*+?^${}()|[\]\\]/gu,
      "\\$&",
    );
    for (
      let line = function_.bodyStartLine;
      line <= function_.endLine;
      line += 1
    ) {
      const assigned = goAssignment(function_.structuralLines[line - 1] ?? "");
      if (
        assigned !== undefined &&
        new RegExp(`\\b${escapedFilepath}\\.Rel\\s*\\(`, "u").test(
          assigned.value,
        )
      ) {
        relativePaths.set(assigned.names[0]!, line);
      }
    }
  }
  for (let line = function_.startLine; line <= function_.endLine; line += 1) {
    const structural = function_.structuralLines[line - 1] ?? "";
    if (filepathAlias !== undefined) {
      const prefix = `\\b${filepathAlias.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}\\.`;
      if (new RegExp(`${prefix}IsLocal\\s*\\(`, "u").test(structural)) {
        add("path-locality-check", line);
      }
      if (new RegExp(`${prefix}Localize\\s*\\(`, "u").test(structural)) {
        add("valid-local-path-conversion", line);
      }
      if (new RegExp(`${prefix}Base\\s*\\(`, "u").test(structural)) {
        add("path-basename-reduction", line);
      }
      if (new RegExp(`${prefix}(?:Clean|Abs)\\s*\\(`, "u").test(structural)) {
        add("path-normalization-only", line);
      }
      if (new RegExp(`${prefix}EvalSymlinks\\s*\\(`, "u").test(structural)) {
        add("symlink-resolution", line);
      }
      if (new RegExp(`${prefix}IsAbs\\s*\\(`, "u").test(structural)) {
        add("absolute-path-rejection", line);
      }
    }
    if (
      osAlias !== undefined &&
      new RegExp(
        `\\b${osAlias.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}\\.(?:OpenInRoot|OpenRoot)\\s*\\(`,
        "u",
      ).test(structural)
    ) {
      add("root-scoped-filesystem", line);
    }
    if (
      fsAlias !== undefined &&
      new RegExp(
        `\\b${fsAlias.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}\\.ValidPath\\s*\\(`,
        "u",
      ).test(structural)
    ) {
      add("slash-path-validation", line);
    }
    if (
      regexpAlias !== undefined &&
      new RegExp(
        `\\b${regexpAlias.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}\\.(?:Compile|MatchString|MustCompile)\\s*\\(`,
        "u",
      ).test(structural)
    ) {
      add("path-component-allowlist", line);
    }
    if (
      stringsAlias !== undefined &&
      new RegExp(
        `\\b${stringsAlias.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}\\.(?:Contains|HasPrefix|HasSuffix)\\s*\\(`,
        "u",
      ).test(structural)
    ) {
      add("path-string-validation", line);
    }
  }
  if (stringsAlias !== undefined && osAlias !== undefined) {
    const escapedStrings = stringsAlias.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    const escapedOs = osAlias.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    for (const [name, relativeLine] of relativePaths) {
      const escapedName = name.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
      let parentEqualityLine: number | undefined;
      let parentPrefixLine: number | undefined;
      for (let line = relativeLine + 1; line <= function_.endLine; line += 1) {
        const structural = function_.structuralLines[line - 1] ?? "";
        const raw = function_.file.lines[line - 1] ?? "";
        if (
          new RegExp(
            `(?:\\b${escapedName}\\s*==|==\\s*\\b${escapedName})`,
            "u",
          ).test(structural) &&
          new RegExp(
            `(?:\\b${escapedName}\\s*==\\s*["']\\.\\.["']|["']\\.\\.["']\\s*==\\s*\\b${escapedName})`,
            "u",
          ).test(raw)
        ) {
          parentEqualityLine ??= line;
        }
        if (
          new RegExp(
            `\\b${escapedStrings}\\.HasPrefix\\s*\\(\\s*${escapedName}\\s*,[\\s\\S]*?string\\s*\\(\\s*${escapedOs}\\.PathSeparator\\s*\\)`,
            "u",
          ).test(structural) &&
          new RegExp(
            `\\b${escapedStrings}\\.HasPrefix\\s*\\(\\s*${escapedName}\\s*,\\s*["']\\.\\.["']\\s*\\+\\s*string\\s*\\(\\s*${escapedOs}\\.PathSeparator\\s*\\)\\s*\\)`,
            "u",
          ).test(raw)
        ) {
          parentPrefixLine ??= line;
        }
      }
      if (parentEqualityLine !== undefined && parentPrefixLine !== undefined) {
        add(
          "relative-parent-boundary-rejection",
          Math.max(parentEqualityLine, parentPrefixLine),
        );
      }
    }
  }
  return controls.slice(0, 10);
}

function fixedPathSelection(
  expression: string,
  line: number,
  requests: readonly string[],
  maps: ReadonlySet<string>,
  taints: ReadonlyMap<string, GoTaint>,
): boolean {
  const selection = /^\s*([A-Za-z_]\w*)\s*\[([\s\S]+)\]\s*$/u.exec(expression);
  return (
    selection !== null &&
    maps.has(selection[1]!) &&
    (requestSource(selection[2]!, requests, line) !== undefined ||
      referencedTaint(selection[2]!, taints) !== undefined)
  );
}

function sourceFor(
  expression: string | undefined,
  line: number,
  requests: readonly string[],
  taints: ReadonlyMap<string, GoTaint>,
  maps: ReadonlySet<string>,
): GoTaint | undefined {
  if (
    expression === undefined ||
    fixedPathSelection(expression, line, requests, maps, taints)
  ) {
    return undefined;
  }
  return (
    requestSource(expression, requests, line) ??
    referencedTaint(expression, taints)?.taint
  );
}

function pathAssignmentKind(function_: GoFunction, expression: string): string {
  const filepathAlias = goImportAlias(
    function_.file.lines,
    "path/filepath",
    "filepath",
  );
  if (
    filepathAlias !== undefined &&
    new RegExp(
      `\\b${filepathAlias.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}\\.(?:Abs|Base|Clean|EvalSymlinks|FromSlash|Join|Localize|Rel|ToSlash)\\s*\\(`,
      "u",
    ).test(expression)
  ) {
    return "go-filesystem-path-construction";
  }
  return "go-string-assignment";
}

function analyzeFunction(
  function_: GoFunction,
  initialTaints: ReadonlyMap<string, GoTaint> = new Map(),
): PathSink[] {
  const specifications = pathSinkSpecifications(function_);
  if (specifications.length === 0) return [];
  const requests = requestParameters(function_);
  const taints = new Map(initialTaints);
  const maps = fixedMapNames(function_);
  const controls = functionControls(function_);
  const callsByLine = new Map<number, ReturnType<typeof goCalls>>();
  for (const call of goCalls(function_)) {
    const existing = callsByLine.get(call.line) ?? [];
    existing.push(call);
    callsByLine.set(call.line, existing);
  }
  const sinks: PathSink[] = [];

  for (
    let line = function_.bodyStartLine;
    line <= function_.endLine;
    line += 1
  ) {
    const assigned = goAssignment(function_.structuralLines[line - 1] ?? "");
    if (assigned !== undefined) {
      const primary = assigned.names[0]!;
      const source = requestSource(assigned.value, requests, line);
      const prior = referencedTaint(assigned.value, taints);
      const fixedSelection = fixedPathSelection(
        assigned.value,
        line,
        requests,
        maps,
        taints,
      );
      for (const name of assigned.names) taints.delete(name);
      if (!fixedSelection && source !== undefined) {
        taints.set(primary, source);
      } else if (!fixedSelection && prior !== undefined) {
        taints.set(primary, {
          ...prior.taint,
          propagators: [
            ...prior.taint.propagators,
            {
              kind: pathAssignmentKind(function_, assigned.value),
              line,
              symbol: primary,
            },
          ],
        });
      }
    }

    for (const call of callsByLine.get(line) ?? []) {
      for (const specification of specifications) {
        if (call.name !== specification.callName) continue;
        const source = sourceFor(
          call.arguments[specification.argumentIndex],
          line,
          requests,
          taints,
          maps,
        );
        if (source === undefined) continue;
        sinks.push({
          kind: specification.kind,
          line,
          argumentIndex: specification.argumentIndex,
          source: {
            ...source,
            propagators: [
              ...source.propagators,
              {
                kind: "go-filesystem-path-argument",
                line,
                symbol: `${call.name}[${specification.argumentIndex}] ${specification.role}`,
              },
            ],
          },
          controls: (specification.kind === "go-filesystem-root-selection"
            ? controls.filter(
                (control) => control.kind !== "root-scoped-filesystem",
              )
            : controls
          ).filter((control) => control.line <= line),
        });
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
    const fixedSelection = fixedPathSelection(
      assigned.value,
      line,
      requests,
      maps,
      taints,
    );
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
  sink: PathSink,
  propagators: GoPropagator[],
): GoPathTraversalRecord {
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
      "framework-dataflow:go-http-filesystem-path",
      `modeled-source:${source.kind}`,
      `modeled-sink:${sink.kind}`,
      ...sink.controls.map((control) => `candidate-control:${control.kind}`),
    ],
    priority: 124,
    startLine,
    endLine,
    excerpt: excerpt(sinkFile.lines, startLine, endLine),
    sourceExcerpt: excerpt(sourceFile.lines, sourceStart, sourceEnd),
    frameworkModel: {
      schemaVersion: "1.2",
      id: "go-http-filesystem-path",
      language: "go",
      scope,
      source: { kind: source.kind, path: sourceFile.path, line: source.line },
      sink: {
        kind: sink.kind,
        path: sinkFile.path,
        line: sink.line,
        cweIds: ["CWE-22", "CWE-23", "CWE-36", "CWE-73"],
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

export function goPathTraversalRecords(
  files: readonly GoHttpSourceFile[],
): GoPathTraversalRecord[] {
  const functions = files
    .filter((file) => file.extension === ".go")
    .flatMap(goFunctions);
  const records: GoPathTraversalRecord[] = [];
  const emitted = new Set<string>();

  for (const function_ of functions) {
    if (requestParameters(function_).length === 0) continue;
    for (const sink of analyzeFunction(function_)) {
      const identity = `${function_.file.path}:${sink.line}:${sink.kind}:${sink.argumentIndex}`;
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
      pathSinkSpecifications(function_).length === 0
    ) {
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
        const identity = `${caller.file.path}:${call.line}:${summary.file.path}:${summary.sink.line}:${summary.parameterIndex}:${summary.sink.argumentIndex}`;
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
