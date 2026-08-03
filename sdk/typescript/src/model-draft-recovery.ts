import { randomUUID } from "node:crypto";
import { lstat, open, readFile, rename, rm } from "node:fs/promises";
import { join } from "node:path";
import { parse } from "yaml";
import { IncompleteScanError } from "./errors.js";

const MALFORMED_DRAFT_REPAIR_LIMIT_BYTES = 8 * 1024 * 1024;
const DRAFT_LIMIT_BYTES = {
  "scan-manifest.json": 16 * 1024 * 1024,
  "findings.json": 128 * 1024 * 1024,
  "coverage.json": 32 * 1024 * 1024,
} as const;
const DRAFT_NAMES = Object.keys(DRAFT_LIMIT_BYTES) as Array<
  keyof typeof DRAFT_LIMIT_BYTES
>;

interface PendingDraftRepair {
  path: string;
  contents: string;
  name: (typeof DRAFT_NAMES)[number];
}

/**
 * Normalize a narrowly bounded model-authored object-literal draft into JSON.
 * The canonical workbench schemas and evidence checks remain authoritative.
 */
export async function normalizeMalformedScanDrafts(
  scanDirectory: string,
): Promise<readonly string[]> {
  const repairs: PendingDraftRepair[] = [];
  for (const name of DRAFT_NAMES) {
    const path = join(scanDirectory, name);
    const metadata = await lstat(path).catch(() => null);
    if (
      metadata === null ||
      !metadata.isFile() ||
      metadata.isSymbolicLink() ||
      metadata.size === 0
    ) {
      throw new IncompleteScanError(
        `Copilot did not produce a regular, non-empty ${name} draft.`,
      );
    }
    if (metadata.size > DRAFT_LIMIT_BYTES[name]) {
      throw new IncompleteScanError(
        `${name} exceeds its ${DRAFT_LIMIT_BYTES[name]}-byte contract limit.`,
      );
    }

    const source = await readFile(path, "utf8");
    try {
      JSON.parse(source);
      continue;
    } catch {}
    if (metadata.size > MALFORMED_DRAFT_REPAIR_LIMIT_BYTES) {
      throw new IncompleteScanError(
        `Malformed ${name} exceeds the ${MALFORMED_DRAFT_REPAIR_LIMIT_BYTES}-byte host repair limit.`,
      );
    }

    const normalized = normalizeObjectLiteralDraft(source, name);
    repairs.push({
      path,
      contents: `${JSON.stringify(normalized, null, 2)}\n`,
      name,
    });
  }

  const temporaryPaths: string[] = [];
  try {
    for (const repair of repairs) {
      const temporaryPath = `${repair.path}.repair-${randomUUID()}.tmp`;
      temporaryPaths.push(temporaryPath);
      const handle = await open(temporaryPath, "wx", 0o600);
      try {
        await handle.writeFile(repair.contents, "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }
    }
    for (const [index, repair] of repairs.entries()) {
      await rename(temporaryPaths[index]!, repair.path);
    }
  } finally {
    await Promise.all(
      temporaryPaths.map((path) =>
        rm(path, { force: true }).catch(() => undefined),
      ),
    );
  }
  return repairs.map((repair) => repair.name);
}

function normalizeObjectLiteralDraft(source: string, name: string): unknown {
  const quotedCodeFields = source.replace(
    /([,{]\s*code\s*:\s*)(.*?)(,\s*explanation\s*:)/gu,
    (_match, prefix: string, value: string, suffix: string) => {
      const trimmed = value.trim();
      if (
        (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
        (trimmed.startsWith("'") && trimmed.endsWith("'"))
      ) {
        return `${prefix}${trimmed}${suffix}`;
      }
      return `${prefix}${JSON.stringify(trimmed)}${suffix}`;
    },
  );
  const normalizedFlowScalars = normalizeFlowMappingScalars(quotedCodeFields);
  let value: unknown;
  try {
    value = parse(normalizedFlowScalars, {
      maxAliasCount: 0,
      merge: false,
      schema: "core",
      strict: true,
      stringKeys: true,
      uniqueKeys: true,
    });
  } catch (error) {
    throw new IncompleteScanError(
      `Copilot produced malformed ${name} that bounded host normalization could not parse.`,
      { cause: error },
    );
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new IncompleteScanError(
      `Copilot produced malformed ${name} with a non-object document root.`,
    );
  }
  return value;
}

function normalizeFlowMappingScalars(source: string): string {
  let output = "";
  let index = 0;
  let quote: '"' | "'" | null = null;
  let escaped = false;
  while (index < source.length) {
    const character = source[index]!;
    if (quote !== null) {
      output += character;
      if (quote === '"' && escaped) {
        escaped = false;
      } else if (quote === '"' && character === "\\") {
        escaped = true;
      } else if (character === quote) {
        if (quote === "'" && source[index + 1] === "'") {
          output += source[index + 1];
          index += 1;
        } else {
          quote = null;
        }
      }
      index += 1;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      output += character;
      index += 1;
      continue;
    }
    if (character !== "{" && character !== ",") {
      output += character;
      index += 1;
      continue;
    }

    let keyStart = index + 1;
    while (/\s/u.test(source[keyStart] ?? "")) keyStart += 1;
    const keyMatch = /^[A-Za-z_][\w-]*/u.exec(source.slice(keyStart));
    if (keyMatch === null) {
      output += character;
      index += 1;
      continue;
    }
    let colon = keyStart + keyMatch[0].length;
    while (/\s/u.test(source[colon] ?? "")) colon += 1;
    if (source[colon] !== ":") {
      output += character;
      index += 1;
      continue;
    }

    output += `${source.slice(index, colon + 1)} `;
    let valueStart = colon + 1;
    while (/\s/u.test(source[valueStart] ?? "")) valueStart += 1;
    const valuePrefix = source[valueStart];
    if (
      valuePrefix === "{" ||
      valuePrefix === "[" ||
      valuePrefix === '"' ||
      valuePrefix === "'"
    ) {
      index = valueStart;
      continue;
    }
    const valueEnd = flowScalarEnd(source, valueStart);
    const scalar = source.slice(valueStart, valueEnd).trim();
    output += isJsonScalarLiteral(scalar) ? scalar : JSON.stringify(scalar);
    index = valueEnd;
  }
  return output;
}

function flowScalarEnd(source: string, start: number): number {
  for (let index = start; index < source.length; index += 1) {
    const character = source[index];
    if (character === "}" || character === "]") return index;
    if (character !== ",") continue;
    let next = index + 1;
    while (/\s/u.test(source[next] ?? "")) next += 1;
    const nextKey = /^[A-Za-z_][\w-]*/u.exec(source.slice(next));
    if (nextKey === null) continue;
    let colon = next + nextKey[0].length;
    while (/\s/u.test(source[colon] ?? "")) colon += 1;
    if (source[colon] === ":") return index;
  }
  return source.length;
}

function isJsonScalarLiteral(value: string): boolean {
  return /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)$/u.test(
    value,
  );
}
