export interface EvidenceLocation {
  path: string;
  startLine: number;
  endLine?: number;
  role?: "source" | "sink";
}

const DEFAULT_LINE_TOLERANCE = 3;

export function isSubstantiveValidation(value: unknown): boolean {
  if (!isNonemptyRecord(value)) return false;
  const narrative = hasSubstantiveField(value, [
    "evidence",
    "explanation",
    "rationale",
    "summary",
  ]);
  if (!narrative) return false;
  return (
    hasNonplaceholderField(value, ["method"]) ||
    hasSubstantiveField(value, [
      "exploitWitness",
      "exploit_witness",
      "poc",
      "reproduce_steps",
      "reproduction",
    ]) ||
    hasSubstantiveStringArray(value, [
      "assertions",
      "evidenceRefs",
      "observations",
    ]) ||
    hasSubstantiveField(value, [
      "counterEvidence",
      "counterevidence",
      "negativeControl",
      "negative_control",
    ]) ||
    hasSubstantiveStringArray(value, [
      "counterEvidence",
      "counterevidence",
      "limitations",
    ])
  );
}

export function isSubstantiveAttackPath(value: unknown): boolean {
  if (!isNonemptyRecord(value)) return false;
  const narrative = hasSubstantiveField(value, [
    "exploit",
    "impact",
    "outcome",
    "summary",
  ]);
  if (!narrative) return false;

  const dataflow = value["dataflow"];
  const structuredDataflow =
    isRecord(dataflow) &&
    hasNonplaceholderField(dataflow, ["source"]) &&
    hasNonplaceholderField(dataflow, ["sink"]) &&
    hasNonplaceholderField(dataflow, ["outcome"]);
  const topLevelDataflow =
    hasNonplaceholderField(value, ["source"]) &&
    hasNonplaceholderField(value, ["sink"]) &&
    hasNonplaceholderField(value, ["outcome"]);
  const reachability = value["reachability"];
  const structuredReachability =
    isRecord(reachability) &&
    hasNonplaceholderField(reachability, ["attacker"]) &&
    hasNonplaceholderField(reachability, ["entrypoint", "outcome"]);
  const compactBoundaryChain =
    hasNonplaceholderField(value, ["source"]) &&
    hasSubstantiveField(value, ["exploit"]) &&
    (hasSubstantiveField(value, ["impact"]) ||
      hasSubstantiveStringArray(value, [
        "controlsBroken",
        "controls_broken",
        "brokenControls",
        "broken_controls",
        "controlBreaks",
        "control_breaks",
      ]));

  return (
    structuredDataflow ||
    topLevelDataflow ||
    structuredReachability ||
    compactBoundaryChain ||
    hasSubstantiveSequence(value["steps"])
  );
}

export function isSubstantiveCodeEvidence(
  value: unknown,
  findingLocations: readonly EvidenceLocation[],
): boolean {
  if (!Array.isArray(value)) return false;
  const substantive = value.flatMap((evidence) => {
    if (!isRecord(evidence)) return [];
    const path = optionalString(evidence["path"]);
    const startLine = positiveInteger(evidence["startLine"]);
    const endLine =
      evidence["endLine"] === undefined
        ? startLine
        : positiveInteger(evidence["endLine"]);
    if (
      path === undefined ||
      startLine === null ||
      endLine === null ||
      endLine < startLine ||
      !isSubstantiveText(evidence["code"], 3) ||
      !isSubstantiveText(evidence["explanation"])
    ) {
      return [];
    }
    const role = endpointRole(evidence["role"]);
    return [
      { path, startLine, endLine, ...(role === undefined ? {} : { role }) },
    ];
  });
  if (
    !substantive.some((evidence) =>
      findingLocations.some((location) =>
        locationsOverlap(evidence, location, DEFAULT_LINE_TOLERANCE),
      ),
    )
  ) {
    return false;
  }

  const endpoints = findingLocations.filter(
    (location) => location.role === "source" || location.role === "sink",
  );
  return endpoints.every((location) =>
    substantive.some(
      (evidence) =>
        evidence.role === location.role &&
        locationsOverlap(evidence, location, DEFAULT_LINE_TOLERANCE),
    ),
  );
}

function endpointRole(value: unknown): "source" | "sink" | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim().toLowerCase();
  return normalized === "source" || normalized === "sink"
    ? normalized
    : undefined;
}

function locationsOverlap(
  left: EvidenceLocation,
  right: EvidenceLocation,
  tolerance: number,
): boolean {
  if (normalizePath(left.path) !== normalizePath(right.path)) return false;
  const leftEnd = left.endLine ?? left.startLine;
  const rightEnd = right.endLine ?? right.startLine;
  const distance =
    left.startLine > rightEnd
      ? left.startLine - rightEnd
      : right.startLine > leftEnd
        ? right.startLine - leftEnd
        : 0;
  return distance <= tolerance;
}

function hasSubstantiveField(
  value: Record<string, unknown>,
  fields: readonly string[],
): boolean {
  return fields.some((field) => isSubstantiveText(value[field]));
}

function hasNonplaceholderField(
  value: Record<string, unknown>,
  fields: readonly string[],
): boolean {
  return fields.some((field) => isSubstantiveText(value[field], 3));
}

function hasSubstantiveStringArray(
  value: Record<string, unknown>,
  fields: readonly string[],
): boolean {
  return fields.some((field) => {
    const entries = value[field];
    return (
      Array.isArray(entries) &&
      entries.some((entry) => isSubstantiveText(entry, 3))
    );
  });
}

function hasSubstantiveSequence(value: unknown): boolean {
  if (!Array.isArray(value) || value.length < 2) return false;
  return value.every((step) => {
    if (isSubstantiveText(step, 8)) return true;
    return (
      isRecord(step) &&
      hasSubstantiveField(step, [
        "action",
        "description",
        "outcome",
        "source",
        "summary",
      ])
    );
  });
}

function isSubstantiveText(value: unknown, minimumLength = 20): boolean {
  const text = optionalString(value);
  if (text === undefined || text.length < minimumLength) return false;
  return !/^(?:n\/?a|none|not tested|placeholder|tbd|todo|unknown)$/iu.test(
    text,
  );
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : undefined;
}

function positiveInteger(value: unknown): number | null {
  return Number.isSafeInteger(value) && Number(value) > 0
    ? Number(value)
    : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonemptyRecord(value: unknown): value is Record<string, unknown> {
  return isRecord(value) && Object.keys(value).length > 0;
}

function normalizePath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\/+/u, "");
}
