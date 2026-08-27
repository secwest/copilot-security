const EXPLICIT_DIRECTION_CONTROLS = new Map<number, DirectionControlDefinition>(
  [
    [
      0x202a,
      {
        name: "LEFT-TO-RIGHT EMBEDDING",
        abbreviation: "LRE",
        family: "embedding",
        role: "open",
      },
    ],
    [
      0x202b,
      {
        name: "RIGHT-TO-LEFT EMBEDDING",
        abbreviation: "RLE",
        family: "embedding",
        role: "open",
      },
    ],
    [
      0x202c,
      {
        name: "POP DIRECTIONAL FORMATTING",
        abbreviation: "PDF",
        family: "embedding",
        role: "close",
      },
    ],
    [
      0x202d,
      {
        name: "LEFT-TO-RIGHT OVERRIDE",
        abbreviation: "LRO",
        family: "override",
        role: "open",
      },
    ],
    [
      0x202e,
      {
        name: "RIGHT-TO-LEFT OVERRIDE",
        abbreviation: "RLO",
        family: "override",
        role: "open",
      },
    ],
    [
      0x2066,
      {
        name: "LEFT-TO-RIGHT ISOLATE",
        abbreviation: "LRI",
        family: "isolate",
        role: "open",
      },
    ],
    [
      0x2067,
      {
        name: "RIGHT-TO-LEFT ISOLATE",
        abbreviation: "RLI",
        family: "isolate",
        role: "open",
      },
    ],
    [
      0x2068,
      {
        name: "FIRST STRONG ISOLATE",
        abbreviation: "FSI",
        family: "isolate",
        role: "open",
      },
    ],
    [
      0x2069,
      {
        name: "POP DIRECTIONAL ISOLATE",
        abbreviation: "PDI",
        family: "isolate",
        role: "close",
      },
    ],
  ],
);

const DIRECTIONAL_MARKS = new Map<number, DirectionControlDefinition>([
  [
    0x061c,
    {
      name: "ARABIC LETTER MARK",
      abbreviation: "ALM",
      family: "mark",
      role: "mark",
    },
  ],
  [
    0x200e,
    {
      name: "LEFT-TO-RIGHT MARK",
      abbreviation: "LRM",
      family: "mark",
      role: "mark",
    },
  ],
  [
    0x200f,
    {
      name: "RIGHT-TO-LEFT MARK",
      abbreviation: "RLM",
      family: "mark",
      role: "mark",
    },
  ],
]);

const ASCII_SYNTAX = /[!%&()*+,.\/:;<=>?@[\]^{|}~-]/u;
const CONTROL_SAMPLE_HEAD = 64;
const CONTROL_SAMPLE_TAIL = 64;
const CONTROL_SAMPLE_HIGH_RISK = 64;
const MAX_EXCERPT_LINE_CODE_UNITS = 2_048;

interface DirectionControlDefinition {
  name: string;
  abbreviation: string;
  family: "embedding" | "isolate" | "mark" | "override";
  role: "close" | "mark" | "open";
}

type SourceLexicalContext = "code-like" | "comment-like" | "string-like";

interface DirectionControlOccurrence {
  codePoint: number;
  definition: DirectionControlDefinition;
  line: number;
  column: number;
  codeUnitOffset: number;
  adjacentAsciiSyntax: boolean;
  pair?: DirectionControlOccurrence;
  pairStatus:
    | "mark-adjacent-syntax"
    | "unknown-truncated"
    | "paired-cross-line"
    | "paired-same-line"
    | "unpaired-closer"
    | "unpaired-opener";
}

export interface SourceDisplayControlRiskRecord {
  path: string;
  line: number;
  categories: string[];
  priority: number;
  startLine: number;
  endLine: number;
  excerpt: string;
  sourceDisplayControl: {
    schemaVersion: "1.0";
    codePoint: string;
    name: string;
    abbreviation: string;
    family: DirectionControlDefinition["family"];
    column: number;
    pairStatus: DirectionControlOccurrence["pairStatus"];
    pairedLine?: number;
    pairedColumn?: number;
    lexicalContextHint: SourceLexicalContext;
    adjacentAsciiSyntax: boolean;
    fileControlCount: number;
    retainedControlCount: number;
    inventoryTruncated: boolean;
  };
}

/**
 * Locate source-display controls that can make logical token order differ from
 * what a reviewer sees. This pass emits review candidates rather than findings:
 * legitimate bidirectional text remains possible, while unpaired controls,
 * overrides, line-spanning pairs, and marks next to ASCII syntax rank first.
 */
export function sourceDisplayControlRiskRecords(
  path: string,
  lines: readonly string[],
): SourceDisplayControlRiskRecord[] {
  const { occurrences, totalCount, truncated } = collectOccurrences(lines);
  pairExplicitControls(occurrences);
  if (truncated) {
    for (const occurrence of occurrences) {
      if (occurrence.definition.role !== "mark") {
        occurrence.pairStatus = "unknown-truncated";
        occurrence.pair = undefined;
      }
    }
  }

  return occurrences
    .filter(
      (occurrence) =>
        occurrence.definition.role !== "mark" || occurrence.adjacentAsciiSyntax,
    )
    .map((occurrence) =>
      toRiskRecord(
        path,
        lines,
        occurrence,
        totalCount,
        occurrences.length,
        truncated,
      ),
    );
}

function collectOccurrences(lines: readonly string[]): {
  occurrences: DirectionControlOccurrence[];
  totalCount: number;
  truncated: boolean;
} {
  const head: DirectionControlOccurrence[] = [];
  const tail: DirectionControlOccurrence[] = [];
  const highRisk: DirectionControlOccurrence[] = [];
  let totalCount = 0;
  let tailCursor = 0;
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex] ?? "";
    for (let offset = 0, column = 1; offset < line.length; column += 1) {
      const codePoint = line.codePointAt(offset)!;
      const definition =
        EXPLICIT_DIRECTION_CONTROLS.get(codePoint) ??
        DIRECTIONAL_MARKS.get(codePoint);
      const width = codePoint > 0xffff ? 2 : 1;
      if (definition !== undefined) {
        const adjacentAsciiSyntax = hasAdjacentAsciiSyntax(line, offset, width);
        const occurrence: DirectionControlOccurrence = {
          codePoint,
          definition,
          line: lineIndex + 1,
          column,
          codeUnitOffset: offset,
          adjacentAsciiSyntax,
          pairStatus:
            definition.role === "mark"
              ? "mark-adjacent-syntax"
              : definition.role === "close"
                ? "unpaired-closer"
                : "unpaired-opener",
        };
        totalCount += 1;
        if (head.length < CONTROL_SAMPLE_HEAD) head.push(occurrence);
        if (tail.length < CONTROL_SAMPLE_TAIL) {
          tail.push(occurrence);
        } else {
          tail[tailCursor] = occurrence;
          tailCursor = (tailCursor + 1) % CONTROL_SAMPLE_TAIL;
        }
        if (
          highRisk.length < CONTROL_SAMPLE_HIGH_RISK &&
          (definition.family === "override" ||
            (definition.role === "mark" && adjacentAsciiSyntax))
        ) {
          highRisk.push(occurrence);
        }
      }
      offset += width;
    }
  }
  const unique = new Map<string, DirectionControlOccurrence>();
  for (const occurrence of [...head, ...highRisk, ...tail]) {
    unique.set(`${occurrence.line}:${occurrence.column}`, occurrence);
  }
  const occurrences = [...unique.values()].sort(
    (left, right) => left.line - right.line || left.column - right.column,
  );
  return {
    occurrences,
    totalCount,
    truncated: totalCount > occurrences.length,
  };
}

function pairExplicitControls(occurrences: DirectionControlOccurrence[]): void {
  const stack: DirectionControlOccurrence[] = [];
  for (const occurrence of occurrences) {
    if (occurrence.definition.role === "mark") continue;
    if (occurrence.definition.role === "open") {
      stack.push(occurrence);
      continue;
    }

    const openerIndex = matchingOpenerIndex(stack, occurrence);
    if (openerIndex < 0) continue;
    const opener = stack[openerIndex]!;
    stack.splice(
      openerIndex,
      occurrence.codePoint === 0x2069 ? stack.length - openerIndex : 1,
    );
    opener.pair = occurrence;
    occurrence.pair = opener;
    const pairStatus =
      opener.line === occurrence.line
        ? "paired-same-line"
        : "paired-cross-line";
    opener.pairStatus = pairStatus;
    occurrence.pairStatus = pairStatus;
  }
}

function matchingOpenerIndex(
  stack: readonly DirectionControlOccurrence[],
  closer: DirectionControlOccurrence,
): number {
  for (let index = stack.length - 1; index >= 0; index -= 1) {
    const family = stack[index]!.definition.family;
    if (closer.codePoint === 0x2069) {
      if (family === "isolate") return index;
      continue;
    }
    if (family === "isolate") return -1;
    if (family === "embedding" || family === "override") return index;
  }
  return -1;
}

function toRiskRecord(
  path: string,
  lines: readonly string[],
  occurrence: DirectionControlOccurrence,
  fileControlCount: number,
  retainedControlCount: number,
  inventoryTruncated: boolean,
): SourceDisplayControlRiskRecord {
  const categories = ["source-bidi-explicit-control"];
  if (occurrence.pairStatus.startsWith("unpaired")) {
    categories.push("source-bidi-unpaired-control");
  }
  if (occurrence.definition.family === "override") {
    categories.push("source-bidi-override-control");
  }
  if (occurrence.pairStatus === "paired-cross-line") {
    categories.push("source-bidi-cross-line-control");
  }
  if (inventoryTruncated) {
    categories.push("source-bidi-inventory-truncated");
  }
  if (occurrence.definition.role === "mark") {
    categories.push("source-bidi-mark-adjacent-syntax");
  }

  const startLine = Math.max(1, occurrence.line - 2);
  const endLine = Math.min(lines.length, occurrence.line + 2);
  const pair = occurrence.pair;
  return {
    path: path.replaceAll("\\", "/"),
    line: occurrence.line,
    categories,
    priority: riskPriority(occurrence),
    startLine,
    endLine,
    excerpt: sourceExcerpt(lines, startLine, endLine, occurrence),
    sourceDisplayControl: {
      schemaVersion: "1.0",
      codePoint: `U+${occurrence.codePoint.toString(16).toUpperCase().padStart(4, "0")}`,
      name: occurrence.definition.name,
      abbreviation: occurrence.definition.abbreviation,
      family: occurrence.definition.family,
      column: occurrence.column,
      pairStatus: occurrence.pairStatus,
      ...(pair === undefined
        ? {}
        : { pairedLine: pair.line, pairedColumn: pair.column }),
      lexicalContextHint: lexicalContext(
        lines[occurrence.line - 1] ?? "",
        occurrence.codeUnitOffset,
      ),
      adjacentAsciiSyntax: occurrence.adjacentAsciiSyntax,
      fileControlCount,
      retainedControlCount,
      inventoryTruncated,
    },
  };
}

function riskPriority(occurrence: DirectionControlOccurrence): number {
  if (occurrence.pairStatus.startsWith("unpaired")) return 100;
  if (occurrence.pairStatus === "unknown-truncated") return 99;
  if (occurrence.definition.family === "override") return 98;
  if (occurrence.pairStatus === "paired-cross-line") return 96;
  if (occurrence.definition.role === "mark") return 94;
  return 82;
}

function hasAdjacentAsciiSyntax(
  line: string,
  offset: number,
  width: number,
): boolean {
  const before = offset === 0 ? "" : line.slice(offset - 1, offset);
  const after = line.slice(offset + width, offset + width + 1);
  return ASCII_SYNTAX.test(before) || ASCII_SYNTAX.test(after);
}

function lexicalContext(line: string, offset: number): SourceLexicalContext {
  const prefix = line.slice(0, offset);
  const lineComment = earliestCommentOffset(prefix);
  if (lineComment >= 0) return "comment-like";
  if (insideQuotedText(prefix)) return "string-like";
  return "code-like";
}

function earliestCommentOffset(prefix: string): number {
  const offsets = [prefix.indexOf("//"), prefix.indexOf("/*")].filter(
    (offset) => offset >= 0,
  );
  const hash = prefix.search(/(?:^|\s)#/u);
  if (hash >= 0) offsets.push(hash);
  const sql = prefix.search(/(?:^|\s)--/u);
  if (sql >= 0) offsets.push(sql);
  return offsets.length === 0 ? -1 : Math.min(...offsets);
}

function insideQuotedText(prefix: string): boolean {
  for (const quote of ['"', "'", "`"]) {
    let count = 0;
    for (let index = 0; index < prefix.length; index += 1) {
      if (prefix[index] !== quote) continue;
      let slashes = 0;
      for (
        let before = index - 1;
        before >= 0 && prefix[before] === "\\";
        before -= 1
      ) {
        slashes += 1;
      }
      if (slashes % 2 === 0) count += 1;
    }
    if (count % 2 === 1) return true;
  }
  return false;
}

function sourceExcerpt(
  lines: readonly string[],
  startLine: number,
  endLine: number,
  occurrence: DirectionControlOccurrence,
): string {
  return lines
    .slice(startLine - 1, endLine)
    .map((line, offset) => {
      const lineNumber = startLine + offset;
      const focus =
        lineNumber === occurrence.line ? occurrence.codeUnitOffset : undefined;
      return `${lineNumber}: ${boundedExcerptLine(line, focus)}`;
    })
    .join("\n");
}

function boundedExcerptLine(line: string, focus?: number): string {
  if (line.length <= MAX_EXCERPT_LINE_CODE_UNITS) return line;
  if (focus === undefined) {
    return `${line.slice(0, MAX_EXCERPT_LINE_CODE_UNITS)}…`;
  }
  const halfWindow = Math.floor(MAX_EXCERPT_LINE_CODE_UNITS / 2);
  const start = Math.max(
    0,
    Math.min(line.length - MAX_EXCERPT_LINE_CODE_UNITS, focus - halfWindow),
  );
  const end = start + MAX_EXCERPT_LINE_CODE_UNITS;
  return `${start > 0 ? "…" : ""}${line.slice(start, end)}${end < line.length ? "…" : ""}`;
}
