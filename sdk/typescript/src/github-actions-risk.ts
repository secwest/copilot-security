import {
  isMap,
  isNode,
  isScalar,
  isSeq,
  LineCounter,
  parseDocument,
  type Pair,
} from "yaml";

const CONTEXT_LINES_BEFORE = 3;
const CONTEXT_LINES_AFTER = 5;

interface CandidateControl {
  kind: string;
  path: string;
  line: number;
}

export interface GithubActionsPrivilegeRecord {
  path: string;
  line: number;
  categories: string[];
  priority: number;
  startLine: number;
  endLine: number;
  excerpt: string;
  sourceExcerpt: string;
  frameworkModel: {
    schemaVersion: "1.2";
    id: "github-actions-privileged-pr-code-execution";
    language: "github-actions-yaml";
    scope: "same-file";
    source: {
      kind: "privileged-pull-request-trigger";
      path: string;
      line: number;
    };
    sink: {
      kind: "untrusted-workspace-code-execution";
      path: string;
      line: number;
      cweIds: readonly ["CWE-829"];
    };
    propagators: Array<{
      kind: "untrusted-checkout-request";
      path: string;
      line: number;
      symbol: string;
    }>;
    candidateControls: CandidateControl[];
  };
}

interface RequestedCheckout {
  line: number;
  path: string;
  controls: CandidateControl[];
}

interface ExecutionStep {
  line: number;
  workingDirectory?: string;
  run?: string;
  localAction?: string;
}

function mapPair(node: unknown, key: string): Pair | undefined {
  if (!isMap(node)) return undefined;
  return node.items.find(
    (pair) => isScalar(pair.key) && pair.key.value === key,
  );
}

function scalarText(node: unknown): string | undefined {
  if (!isScalar(node)) return undefined;
  const { value } = node;
  return typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
    ? String(value)
    : undefined;
}

function nodeLine(node: unknown, counter: LineCounter): number | undefined {
  if (!isNode(node) || node.range === null || node.range === undefined) {
    return undefined;
  }
  return counter.linePos(node.range[0]).line;
}

function pairLine(pair: Pair | undefined, counter: LineCounter): number {
  return nodeLine(pair?.key, counter) ?? nodeLine(pair?.value, counter) ?? 1;
}

function privilegedPullRequestTriggerLine(
  root: unknown,
  counter: LineCounter,
): number | undefined {
  const trigger = mapPair(root, "on");
  if (trigger === undefined) return undefined;
  const scalar = scalarText(trigger.value);
  if (scalar === "pull_request_target") {
    return nodeLine(trigger.value, counter) ?? pairLine(trigger, counter);
  }
  if (isSeq(trigger.value)) {
    const item = trigger.value.items.find(
      (candidate) => scalarText(candidate) === "pull_request_target",
    );
    return item === undefined ? undefined : nodeLine(item, counter);
  }
  const event = mapPair(trigger.value, "pull_request_target");
  return event === undefined ? undefined : pairLine(event, counter);
}

function normalizeWorkspacePath(value: string | undefined): string | undefined {
  if (value === undefined || value.trim() === "") return ".";
  const normalized = value
    .trim()
    .replaceAll("\\", "/")
    .replace(/^\.\//u, "")
    .replace(/\/+$/u, "");
  if (
    normalized === "" ||
    normalized === "." ||
    normalized.startsWith("/") ||
    normalized.split("/").some((part) => part === "..") ||
    normalized.includes("${{")
  ) {
    return normalized === "" || normalized === "." ? "." : undefined;
  }
  return normalized;
}

function untrustedPullRequestRef(
  reference: string | undefined,
  repository: string | undefined,
): boolean {
  const forkRepository =
    repository !== undefined &&
    /github\.event\.pull_request\.head\.repo\.full_name/iu.test(
      repository.replace(/\s+/gu, ""),
    );
  if (forkRepository) return true;
  if (reference === undefined) return false;
  const normalized = reference.replace(/\s+/gu, "");
  if (
    /github\.event\.pull_request\.head\.sha/iu.test(normalized) ||
    /refs\/pull\/\$\{\{github\.event\.pull_request\.(?:number|id)\}\}\/(?:head|merge)/iu.test(
      normalized,
    ) ||
    /refs\/pull\/[^/]+\/(?:head|merge)/iu.test(normalized)
  ) {
    return true;
  }
  const mutableHead =
    /github\.event\.pull_request\.head\.ref|github\.head_ref/iu.test(
      normalized,
    );
  return mutableHead && forkRepository;
}

function immutablePullRequestCommit(reference: string | undefined): boolean {
  return (
    reference !== undefined &&
    /github\.event\.pull_request\.head\.sha/iu.test(
      reference.replace(/\s+/gu, ""),
    )
  );
}

function booleanScalar(node: unknown): boolean | undefined {
  if (!isScalar(node)) return undefined;
  if (node.value === true || node.value === false) return node.value;
  if (typeof node.value !== "string") return undefined;
  if (node.value.toLowerCase() === "true") return true;
  if (node.value.toLowerCase() === "false") return false;
  return undefined;
}

function checkoutRequest(
  step: unknown,
  path: string,
  counter: LineCounter,
): RequestedCheckout | "trusted-checkout" | undefined {
  const uses = mapPair(step, "uses");
  const action = scalarText(uses?.value);
  const checkout = /^actions\/checkout@(.+)$/iu.exec(action ?? "");
  if (checkout === null) return undefined;
  const revision = checkout[1]!;
  const version = /^v?(\d+)(?:\b|\.)/iu.exec(revision);
  if (version === null && !/^[a-f0-9]{40}$/iu.test(revision)) return undefined;

  const inputs = mapPair(step, "with")?.value;
  const referencePair = mapPair(inputs, "ref");
  const repositoryPair = mapPair(inputs, "repository");
  const checkoutPathPair = mapPair(inputs, "path");
  const unsafePair = mapPair(inputs, "allow-unsafe-pr-checkout");
  const credentialsPair = mapPair(inputs, "persist-credentials");
  const reference = scalarText(referencePair?.value);
  const repository = scalarText(repositoryPair?.value);
  const workspacePath = normalizeWorkspacePath(
    scalarText(checkoutPathPair?.value),
  );
  if (workspacePath === undefined) return undefined;
  if (!untrustedPullRequestRef(reference, repository)) {
    return "trusted-checkout";
  }

  const controls: CandidateControl[] = [];
  const major = version === null ? undefined : Number.parseInt(version[1]!, 10);
  const explicitlyUnsafe = booleanScalar(unsafePair?.value);
  if (major !== undefined && major >= 7 && explicitlyUnsafe !== true) {
    controls.push({
      kind: "checkout-v7-fork-protection",
      path,
      line: pairLine(uses, counter),
    });
  }
  if (booleanScalar(credentialsPair?.value) === false) {
    controls.push({
      kind: "checkout-credentials-not-persisted",
      path,
      line: pairLine(credentialsPair, counter),
    });
  }
  if (immutablePullRequestCommit(reference)) {
    controls.push({
      kind: "immutable-pr-commit",
      path,
      line: pairLine(referencePair, counter),
    });
  }
  return {
    line: pairLine(uses, counter),
    path: workspacePath,
    controls,
  };
}

function permissionControl(
  workflowPermission: Pair | undefined,
  jobPermission: Pair | undefined,
  path: string,
  counter: LineCounter,
): CandidateControl | undefined {
  const permission = jobPermission ?? workflowPermission;
  if (permission === undefined) return undefined;
  const value = permission.value;
  const scalar = scalarText(value)?.toLowerCase();
  const readOnly =
    scalar === "read-all" ||
    (isMap(value) &&
      value.items.every((pair) => {
        const permissionValue = scalarText(pair.value)?.toLowerCase();
        return permissionValue === "read" || permissionValue === "none";
      }));
  return readOnly
    ? {
        kind: "explicit-read-only-token",
        path,
        line: pairLine(permission, counter),
      }
    : undefined;
}

function permissionAllowsWrite(permission: Pair | undefined): boolean {
  if (permission === undefined) return false;
  const scalar = scalarText(permission.value)?.toLowerCase();
  return (
    scalar === "write-all" ||
    (isMap(permission.value) &&
      permission.value.items.some(
        (pair) => scalarText(pair.value)?.toLowerCase() === "write",
      ))
  );
}

function jobReviewControls(
  job: unknown,
  path: string,
  counter: LineCounter,
): CandidateControl[] {
  const controls: CandidateControl[] = [];
  const condition = mapPair(job, "if");
  const expression = scalarText(condition?.value) ?? "";
  if (
    /pull_request\.labels|labels\.\*\.name|safe[-_ ]to[-_ ]test/iu.test(
      expression,
    )
  ) {
    controls.push({
      kind: "mutable-review-label-gate",
      path,
      line: pairLine(condition, counter),
    });
  }
  const environment = mapPair(job, "environment");
  if (environment !== undefined) {
    controls.push({
      kind: "deployment-environment-gate",
      path,
      line: pairLine(environment, counter),
    });
  }
  return controls;
}

function workspaceExecution(run: string): boolean {
  const command = run.replace(/\\\r?\n/gu, " ");
  const commandBoundary = "(?:^|[\\n;&|]\\s*)";
  const packageCommand = new RegExp(
    `${commandBoundary}(?:sudo\\s+)?(?:npm|pnpm|yarn|bun)\\s+(ci|install|run|test|exec|x)\\b([^\\n;&|]*)`,
    "gimu",
  );
  for (const match of command.matchAll(packageCommand)) {
    const operation = match[1]?.toLowerCase();
    const argumentsText = match[2] ?? "";
    if (
      (operation === "ci" || operation === "install") &&
      /(?:^|\s)--ignore-scripts(?:\s|$|=true)/iu.test(argumentsText)
    ) {
      continue;
    }
    return true;
  }
  const runners = [
    "(?:make|gmake)(?:\\s|$)",
    "(?:mvn|mvnw|gradle|gradlew)(?:\\s|$)",
    "dotnet\\s+(?:build|publish|restore|run|test)\\b",
    "cargo\\s+(?:build|run|test)\\b",
    "go\\s+(?:generate|run|test)\\b",
    "(?:pytest|tox|nox)(?:\\s|$)",
    "(?:bash|sh|zsh|pwsh|powershell|cmd)\\s+(?![-/~]|[A-Za-z]:[\\\\/])(?:\\./)?[^\\s;|]+",
    "(?:node|python3?|ruby|perl)\\s+(?:(?:-m\\s+(?:pytest|unittest|tox|nox)\\b)|(?![-/~]|[A-Za-z]:[\\\\/])(?:\\./)?[^\\s;|]+)",
    "\\./[A-Za-z0-9_.-]+",
  ];
  return runners.some((runner) =>
    new RegExp(`${commandBoundary}(?:sudo\\s+)?${runner}`, "imu").test(command),
  );
}

function executionStep(
  step: unknown,
  counter: LineCounter,
  defaultWorkingDirectory?: string,
): ExecutionStep | undefined {
  const runPair = mapPair(step, "run");
  const run = scalarText(runPair?.value);
  const workingDirectoryPair = mapPair(step, "working-directory");
  const workingDirectory =
    workingDirectoryPair === undefined
      ? defaultWorkingDirectory
      : normalizeWorkspacePath(scalarText(workingDirectoryPair.value));
  if (run !== undefined && workspaceExecution(run)) {
    return {
      line: pairLine(runPair, counter),
      ...(workingDirectory === undefined ? {} : { workingDirectory }),
      run,
    };
  }
  const usesPair = mapPair(step, "uses");
  const uses = scalarText(usesPair?.value);
  if (uses?.startsWith("./")) {
    return {
      line: pairLine(usesPair, counter),
      localAction: uses.replace(/^\.\//u, ""),
    };
  }
  return undefined;
}

function defaultRunWorkingDirectory(container: unknown): {
  defined: boolean;
  value?: string;
} {
  const workingDirectory = mapPair(
    mapPair(mapPair(container, "defaults")?.value, "run")?.value,
    "working-directory",
  );
  if (workingDirectory === undefined) return { defined: false };
  const value = normalizeWorkspacePath(scalarText(workingDirectory.value));
  return value === undefined ? { defined: true } : { defined: true, value };
}

function pathApplies(checkoutPath: string, execution: ExecutionStep): boolean {
  if (checkoutPath === ".") return true;
  if (
    execution.workingDirectory === checkoutPath ||
    execution.workingDirectory?.startsWith(`${checkoutPath}/`) === true ||
    execution.localAction === checkoutPath ||
    execution.localAction?.startsWith(`${checkoutPath}/`) === true
  ) {
    return true;
  }
  if (execution.run === undefined) return false;
  const escaped = checkoutPath.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return new RegExp(
    `(?:\\bcd\\s+|--(?:prefix|project|workdir(?:ectory)?)\\s+|\\./)${escaped}(?:/|\\b)`,
    "iu",
  ).test(execution.run);
}

function distinctControls(controls: CandidateControl[]): CandidateControl[] {
  return controls.filter(
    (control, index, all) =>
      all.findIndex(
        (candidate) =>
          candidate.kind === control.kind &&
          candidate.path === control.path &&
          candidate.line === control.line,
      ) === index,
  );
}

function nodeText(node: unknown, source: string): string {
  if (!isNode(node) || node.range === null || node.range === undefined) {
    return "";
  }
  return source.slice(node.range[0], node.range[2]);
}

export function githubActionsPrivilegeRecords(
  path: string,
  lines: readonly string[],
  source: string,
): GithubActionsPrivilegeRecord[] {
  if (!/^\.github\/workflows\/[^/]+\.ya?ml$/iu.test(path)) return [];
  const counter = new LineCounter();
  const document = parseDocument(source, {
    lineCounter: counter,
    prettyErrors: false,
    strict: true,
    uniqueKeys: true,
    version: "1.2",
  });
  if (document.errors.length > 0 || !isMap(document.contents)) return [];
  const triggerLine = privilegedPullRequestTriggerLine(
    document.contents,
    counter,
  );
  if (triggerLine === undefined) return [];
  const jobs = mapPair(document.contents, "jobs")?.value;
  if (!isMap(jobs)) return [];
  const workflowPermission = mapPair(document.contents, "permissions");
  const workflowWorkingDirectory = defaultRunWorkingDirectory(
    document.contents,
  );
  const workflowEnvironmentText = nodeText(
    mapPair(document.contents, "env")?.value,
    source,
  );
  const records: GithubActionsPrivilegeRecord[] = [];

  for (const jobPair of jobs.items) {
    const job = jobPair.value;
    if (!isMap(job)) continue;
    const steps = mapPair(job, "steps")?.value;
    if (!isSeq(steps)) continue;
    const jobWorkingDirectory = defaultRunWorkingDirectory(job);
    const effectiveWorkingDirectory = jobWorkingDirectory.defined
      ? jobWorkingDirectory.value
      : workflowWorkingDirectory.value;
    const controls = jobReviewControls(job, path, counter);
    const jobPermission = mapPair(job, "permissions");
    const permissions = permissionControl(
      workflowPermission,
      jobPermission,
      path,
      counter,
    );
    if (permissions !== undefined) controls.push(permissions);
    const rawJob = nodeText(job, source);
    const baseCategories = ["github-actions-privileged-pr-code-execution"];
    if (/\$\{\{\s*secrets\./iu.test(`${workflowEnvironmentText}\n${rawJob}`)) {
      baseCategories.push("github-actions-explicit-secret-access");
    }
    if (permissionAllowsWrite(jobPermission ?? workflowPermission)) {
      baseCategories.push("github-actions-write-token-permission");
    }

    const activeCheckouts: RequestedCheckout[] = [];
    for (const step of steps.items) {
      const checkout = checkoutRequest(step, path, counter);
      if (checkout === "trusted-checkout") {
        const trustedPath = normalizeWorkspacePath(
          scalarText(mapPair(mapPair(step, "with")?.value, "path")?.value),
        );
        if (trustedPath !== undefined) {
          for (let index = activeCheckouts.length - 1; index >= 0; index -= 1) {
            const activePath = activeCheckouts[index]?.path;
            if (
              activePath === trustedPath ||
              trustedPath === "." ||
              activePath?.startsWith(`${trustedPath}/`) === true
            ) {
              activeCheckouts.splice(index, 1);
            }
          }
        }
        continue;
      }
      if (checkout !== undefined) {
        for (let index = activeCheckouts.length - 1; index >= 0; index -= 1) {
          if (activeCheckouts[index]?.path === checkout.path) {
            activeCheckouts.splice(index, 1);
          }
        }
        activeCheckouts.push(checkout);
        continue;
      }
      const execution = executionStep(step, counter, effectiveWorkingDirectory);
      if (execution === undefined) continue;
      for (const requested of activeCheckouts) {
        if (!pathApplies(requested.path, execution)) continue;
        const startLine = Math.max(1, execution.line - CONTEXT_LINES_BEFORE);
        const endLine = Math.min(
          lines.length,
          execution.line + CONTEXT_LINES_AFTER,
        );
        const sourceStart = Math.max(1, triggerLine - 2);
        const sourceEnd = Math.min(lines.length, triggerLine + 2);
        records.push({
          path,
          line: execution.line,
          categories: [...baseCategories],
          priority: 125,
          startLine,
          endLine,
          excerpt: lines.slice(startLine - 1, endLine).join("\n"),
          sourceExcerpt: lines.slice(sourceStart - 1, sourceEnd).join("\n"),
          frameworkModel: {
            schemaVersion: "1.2",
            id: "github-actions-privileged-pr-code-execution",
            language: "github-actions-yaml",
            scope: "same-file",
            source: {
              kind: "privileged-pull-request-trigger",
              path,
              line: triggerLine,
            },
            sink: {
              kind: "untrusted-workspace-code-execution",
              path,
              line: execution.line,
              cweIds: ["CWE-829"],
            },
            propagators: [
              {
                kind: "untrusted-checkout-request",
                path,
                line: requested.line,
                symbol: `workspace=${requested.path}`,
              },
            ],
            candidateControls: distinctControls([
              ...controls,
              ...requested.controls,
            ]),
          },
        });
      }
    }
  }
  return records;
}
