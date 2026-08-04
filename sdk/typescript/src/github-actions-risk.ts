import {
  isAlias,
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

interface TrustedCheckout {
  trusted: true;
  line: number;
  path: string;
  cleans: boolean;
}

interface ExecutionStep {
  line: number;
  workingDirectory?: string;
  run?: string;
  localAction?: string;
}

export interface GithubActionsSourceFile {
  path: string;
  lines: readonly string[];
  text: string;
}

export interface GithubActionsArtifactPoisoningRecord {
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
    id: "github-actions-artifact-poisoning-code-execution";
    language: "github-actions-yaml";
    scope: "cross-file";
    source: {
      kind: "untrusted-pull-request-artifact-upload";
      path: string;
      line: number;
    };
    sink: {
      kind: "privileged-artifact-code-execution";
      path: string;
      line: number;
      cweIds: readonly ["CWE-829"];
    };
    propagators: Array<{
      kind:
        | "untrusted-pull-request-checkout"
        | "triggering-run-artifact-download";
      path: string;
      line: number;
      symbol: string;
    }>;
    candidateControls: CandidateControl[];
  };
}

interface ParsedWorkflow {
  root: unknown;
  counter: LineCounter;
}

interface ArtifactProducer {
  workflowName: string;
  workflowPath: string;
  workflowLines: readonly string[];
  checkoutLine: number;
  uploadLine: number;
  artifactName: string;
  artifactPath: string;
}

interface ArtifactDownload {
  line: number;
  artifactName?: string;
  path: string;
}

interface ActiveArtifact {
  producer: ArtifactProducer;
  downloadLine: number;
  path: string;
}

function mapPair(node: unknown, key: string): Pair | undefined {
  if (!isMap(node)) return undefined;
  return node.items.find(
    (pair) => isScalar(pair.key) && pair.key.value === key,
  );
}

function containsAlias(node: unknown): boolean {
  if (isAlias(node)) return true;
  if (isMap(node)) {
    return node.items.some(
      (pair) => containsAlias(pair.key) || containsAlias(pair.value),
    );
  }
  return isSeq(node) && node.items.some((item) => containsAlias(item));
}

function parseWorkflow(source: string): ParsedWorkflow | undefined {
  const counter = new LineCounter();
  const document = parseDocument(source, {
    lineCounter: counter,
    prettyErrors: false,
    strict: true,
    uniqueKeys: true,
    version: "1.2",
  });
  if (
    document.errors.length > 0 ||
    !isMap(document.contents) ||
    containsAlias(document.contents)
  ) {
    return undefined;
  }
  return { root: document.contents, counter };
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

function eventTriggerLine(
  root: unknown,
  eventName: string,
  counter: LineCounter,
): number | undefined {
  const trigger = mapPair(root, "on");
  if (trigger === undefined) return undefined;
  const scalar = scalarText(trigger.value);
  if (scalar === eventName) {
    return nodeLine(trigger.value, counter) ?? pairLine(trigger, counter);
  }
  if (isSeq(trigger.value)) {
    const item = trigger.value.items.find(
      (candidate) => scalarText(candidate) === eventName,
    );
    return item === undefined ? undefined : nodeLine(item, counter);
  }
  const event = mapPair(trigger.value, eventName);
  return event === undefined ? undefined : pairLine(event, counter);
}

function privilegedPullRequestTriggerLine(
  root: unknown,
  counter: LineCounter,
): number | undefined {
  return eventTriggerLine(root, "pull_request_target", counter);
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

function normalizeArtifactPath(value: string | undefined): string | undefined {
  if (value === undefined) return ".";
  const runnerTemp = /^\$\{\{\s*runner\.temp\s*\}\}(?:[\\/](.*))?$/iu.exec(
    value.trim(),
  );
  if (runnerTemp === null) return normalizeWorkspacePath(value);
  const suffix = normalizeWorkspacePath(runnerTemp[1]);
  if (suffix === undefined) return undefined;
  return suffix === "." ? "@runner-temp" : `@runner-temp/${suffix}`;
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
): RequestedCheckout | TrustedCheckout | undefined {
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
  const cleanPair = mapPair(inputs, "clean");
  const reference = scalarText(referencePair?.value);
  const repository = scalarText(repositoryPair?.value);
  const workspacePath = normalizeWorkspacePath(
    scalarText(checkoutPathPair?.value),
  );
  if (workspacePath === undefined) return undefined;
  if (!untrustedPullRequestRef(reference, repository)) {
    return {
      trusted: true,
      line: pairLine(uses, counter),
      path: workspacePath,
      cleans: booleanScalar(cleanPair?.value) !== false,
    };
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
  pathNormalizer: (
    value: string | undefined,
  ) => string | undefined = normalizeWorkspacePath,
): ExecutionStep | undefined {
  const runPair = mapPair(step, "run");
  const run = scalarText(runPair?.value);
  const workingDirectoryPair = mapPair(step, "working-directory");
  const workingDirectory =
    workingDirectoryPair === undefined
      ? defaultWorkingDirectory
      : pathNormalizer(scalarText(workingDirectoryPair.value));
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
};
function defaultRunWorkingDirectory(
  container: unknown,
  pathNormalizer?: (value: string | undefined) => string | undefined,
): { defined: boolean; value?: string };
function defaultRunWorkingDirectory(
  container: unknown,
  pathNormalizer: (
    value: string | undefined,
  ) => string | undefined = normalizeWorkspacePath,
): { defined: boolean; value?: string } {
  const workingDirectory = mapPair(
    mapPair(mapPair(container, "defaults")?.value, "run")?.value,
    "working-directory",
  );
  if (workingDirectory === undefined) return { defined: false };
  const value = pathNormalizer(scalarText(workingDirectory.value));
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
  if (checkoutPath.startsWith("@runner-temp")) {
    const suffix = checkoutPath.slice("@runner-temp".length);
    const escapedSuffix = suffix.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    return new RegExp(
      `\\$\\{\\{\\s*runner\\.temp\\s*\\}\\}${escapedSuffix}(?:/|\\b)`,
      "iu",
    ).test(execution.run.replaceAll("\\", "/"));
  }
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

function officialAction(action: string | undefined, identity: string): boolean {
  if (action === undefined) return false;
  const prefix = `${identity}@`;
  if (!action.toLowerCase().startsWith(prefix.toLowerCase())) return false;
  const revision = action.slice(prefix.length);
  return (
    /^v?\d+(?:\b|\.)/iu.test(revision) || /^[a-f0-9]{40}$/iu.test(revision)
  );
}

function stringList(node: unknown): string[] {
  const scalar = scalarText(node);
  if (scalar !== undefined) return [scalar];
  if (!isSeq(node)) return [];
  return node.items
    .map((item) => scalarText(item))
    .filter((item): item is string => item !== undefined);
}

function workflowName(root: unknown): string | undefined {
  const name = scalarText(mapPair(root, "name")?.value)?.trim();
  return name === undefined || name === "" || name.includes("${{")
    ? undefined
    : name;
}

function workflowRunProducerNames(
  root: unknown,
  counter: LineCounter,
): { line: number; names: string[] } | undefined {
  const trigger = mapPair(root, "on");
  const event = mapPair(trigger?.value, "workflow_run");
  if (event === undefined || !isMap(event.value)) return undefined;
  const names = stringList(mapPair(event.value, "workflows")?.value).filter(
    (name) => name.trim() !== "" && !name.includes("${{"),
  );
  if (names.length === 0) return undefined;
  const types = mapPair(event.value, "types");
  if (
    types !== undefined &&
    !stringList(types.value).some((type) => type.toLowerCase() === "completed")
  ) {
    return undefined;
  }
  return { line: pairLine(event, counter), names };
}

function pullRequestCheckout(
  step: unknown,
  counter: LineCounter,
): { line: number; path: string } | TrustedCheckout | undefined {
  const uses = mapPair(step, "uses");
  if (!officialAction(scalarText(uses?.value), "actions/checkout")) {
    return undefined;
  }
  const inputs = mapPair(step, "with")?.value;
  const checkoutPath = normalizeWorkspacePath(
    scalarText(mapPair(inputs, "path")?.value),
  );
  if (checkoutPath === undefined) return undefined;
  const reference = scalarText(mapPair(inputs, "ref")?.value);
  const repository = scalarText(mapPair(inputs, "repository")?.value);
  const normalizedReference = reference?.replace(/\s+/gu, "") ?? "";
  const currentRepository =
    repository === undefined ||
    /\$\{\{\s*github\.repository\s*\}\}/iu.test(repository);
  const untrusted =
    untrustedPullRequestRef(reference, repository) ||
    (currentRepository &&
      (reference === undefined ||
        /(?:^|[^.])github\.sha\b|github\.event\.pull_request\.(?:head|merge_commit_sha)/iu.test(
          normalizedReference,
        )));
  if (untrusted) {
    return { line: pairLine(uses, counter), path: checkoutPath };
  }
  return {
    trusted: true,
    line: pairLine(uses, counter),
    path: checkoutPath,
    cleans: booleanScalar(mapPair(inputs, "clean")?.value) !== false,
  };
}

function artifactUpload(
  step: unknown,
  counter: LineCounter,
): { line: number; name: string; path: string } | undefined {
  const uses = mapPair(step, "uses");
  if (!officialAction(scalarText(uses?.value), "actions/upload-artifact")) {
    return undefined;
  }
  const inputs = mapPair(step, "with")?.value;
  const name = scalarText(mapPair(inputs, "name")?.value)?.trim();
  const artifactPath = normalizeWorkspacePath(
    scalarText(mapPair(inputs, "path")?.value),
  );
  if (
    name === undefined ||
    name === "" ||
    name.includes("${{") ||
    artifactPath === undefined
  ) {
    return undefined;
  }
  return { line: pairLine(uses, counter), name, path: artifactPath };
}

function triggeringRunArtifactDownload(
  step: unknown,
  counter: LineCounter,
): ArtifactDownload | undefined {
  const uses = mapPair(step, "uses");
  if (!officialAction(scalarText(uses?.value), "actions/download-artifact")) {
    return undefined;
  }
  const inputs = mapPair(step, "with")?.value;
  const runId = scalarText(mapPair(inputs, "run-id")?.value)?.replace(
    /\s+/gu,
    "",
  );
  const token = scalarText(mapPair(inputs, "github-token")?.value)?.replace(
    /\s+/gu,
    "",
  );
  if (
    !/github\.event\.workflow_run\.id/iu.test(runId ?? "") ||
    !/(?:secrets\.github_token|github\.token)/iu.test(token ?? "")
  ) {
    return undefined;
  }
  const name = scalarText(mapPair(inputs, "name")?.value)?.trim();
  if (name !== undefined && (name === "" || name.includes("${{"))) {
    return undefined;
  }
  const downloadPath = normalizeArtifactPath(
    scalarText(mapPair(inputs, "path")?.value),
  );
  if (downloadPath === undefined) return undefined;
  return {
    line: pairLine(uses, counter),
    ...(name === undefined ? {} : { artifactName: name }),
    path: downloadPath,
  };
}

function workspaceContains(workspace: string, candidate: string): boolean {
  return (
    workspace === "." ||
    candidate === workspace ||
    candidate.startsWith(`${workspace}/`)
  );
}

function joinedWorkspacePath(parent: string, child: string): string {
  return parent === "." ? child : `${parent}/${child}`;
}

function clearCoveredPaths<T extends { path: string }>(
  active: T[],
  trustedPath: string,
): void {
  for (let index = active.length - 1; index >= 0; index -= 1) {
    const activePath = active[index]?.path;
    if (
      activePath === trustedPath ||
      trustedPath === "." ||
      activePath?.startsWith(`${trustedPath}/`) === true
    ) {
      active.splice(index, 1);
    }
  }
}

function artifactProducers(
  files: readonly GithubActionsSourceFile[],
): ArtifactProducer[] {
  const producers: ArtifactProducer[] = [];
  for (const file of files) {
    if (!/^\.github\/workflows\/[^/]+\.ya?ml$/iu.test(file.path)) continue;
    const parsed = parseWorkflow(file.text);
    if (parsed === undefined) continue;
    const triggerLine = eventTriggerLine(
      parsed.root,
      "pull_request",
      parsed.counter,
    );
    const name = workflowName(parsed.root);
    const jobs = mapPair(parsed.root, "jobs")?.value;
    if (triggerLine === undefined || name === undefined || !isMap(jobs)) {
      continue;
    }
    for (const jobPair of jobs.items) {
      const steps = mapPair(jobPair.value, "steps")?.value;
      if (!isSeq(steps)) continue;
      const activeCheckouts: Array<{ line: number; path: string }> = [];
      for (const step of steps.items) {
        const checkout = pullRequestCheckout(step, parsed.counter);
        if (checkout !== undefined && "trusted" in checkout) {
          if (checkout.cleans)
            clearCoveredPaths(activeCheckouts, checkout.path);
          continue;
        }
        if (checkout !== undefined) {
          clearCoveredPaths(activeCheckouts, checkout.path);
          activeCheckouts.push(checkout);
          continue;
        }
        const upload = artifactUpload(step, parsed.counter);
        if (upload === undefined) continue;
        for (const active of activeCheckouts) {
          if (!workspaceContains(active.path, upload.path)) continue;
          producers.push({
            workflowName: name,
            workflowPath: file.path,
            workflowLines: file.lines,
            checkoutLine: active.line,
            uploadLine: upload.line,
            artifactName: upload.name,
            artifactPath: upload.path,
          });
        }
      }
    }
  }
  return producers;
}

export function githubActionsArtifactPoisoningRecords(
  files: readonly GithubActionsSourceFile[],
): GithubActionsArtifactPoisoningRecord[] {
  const producers = artifactProducers(files);
  if (producers.length === 0) return [];
  const records: GithubActionsArtifactPoisoningRecord[] = [];
  for (const file of files) {
    if (!/^\.github\/workflows\/[^/]+\.ya?ml$/iu.test(file.path)) continue;
    const parsed = parseWorkflow(file.text);
    if (parsed === undefined) continue;
    const workflowRun = workflowRunProducerNames(parsed.root, parsed.counter);
    const jobs = mapPair(parsed.root, "jobs")?.value;
    if (workflowRun === undefined || !isMap(jobs)) continue;
    const matchingProducers = producers.filter((producer) =>
      workflowRun.names.includes(producer.workflowName),
    );
    if (matchingProducers.length === 0) continue;
    const workflowPermission = mapPair(parsed.root, "permissions");
    const workflowEnvironmentText = nodeText(
      mapPair(parsed.root, "env")?.value,
      file.text,
    );
    const workflowWorkingDirectory = defaultRunWorkingDirectory(
      parsed.root,
      normalizeArtifactPath,
    );

    for (const jobPair of jobs.items) {
      const job = jobPair.value;
      const steps = mapPair(job, "steps")?.value;
      if (!isMap(job) || !isSeq(steps)) continue;
      const jobPermission = mapPair(job, "permissions");
      const controls = jobReviewControls(job, file.path, parsed.counter);
      const permissions = permissionControl(
        workflowPermission,
        jobPermission,
        file.path,
        parsed.counter,
      );
      if (permissions !== undefined) controls.push(permissions);
      const rawJob = nodeText(job, file.text);
      const categories = ["github-actions-artifact-poisoning-code-execution"];
      if (
        /\$\{\{\s*secrets\./iu.test(`${workflowEnvironmentText}\n${rawJob}`)
      ) {
        categories.push("github-actions-explicit-secret-access");
      }
      if (permissionAllowsWrite(jobPermission ?? workflowPermission)) {
        categories.push("github-actions-write-token-permission");
      }
      const jobWorkingDirectory = defaultRunWorkingDirectory(
        job,
        normalizeArtifactPath,
      );
      const effectiveWorkingDirectory = jobWorkingDirectory.defined
        ? jobWorkingDirectory.value
        : workflowWorkingDirectory.value;
      const activeArtifacts: ActiveArtifact[] = [];

      for (const step of steps.items) {
        const checkout = checkoutRequest(step, file.path, parsed.counter);
        if (checkout !== undefined && "trusted" in checkout) {
          if (checkout.cleans)
            clearCoveredPaths(activeArtifacts, checkout.path);
          continue;
        }
        const download = triggeringRunArtifactDownload(step, parsed.counter);
        if (download !== undefined) {
          for (const producer of matchingProducers) {
            if (
              download.artifactName !== undefined &&
              download.artifactName !== producer.artifactName
            ) {
              continue;
            }
            const artifactPath =
              download.artifactName === undefined
                ? joinedWorkspacePath(download.path, producer.artifactName)
                : download.path;
            clearCoveredPaths(activeArtifacts, artifactPath);
            activeArtifacts.push({
              producer,
              downloadLine: download.line,
              path: artifactPath,
            });
          }
          continue;
        }
        const execution = executionStep(
          step,
          parsed.counter,
          effectiveWorkingDirectory,
          normalizeArtifactPath,
        );
        if (execution === undefined) continue;
        for (const artifact of activeArtifacts) {
          if (!pathApplies(artifact.path, execution)) continue;
          const startLine = Math.max(1, execution.line - CONTEXT_LINES_BEFORE);
          const endLine = Math.min(
            file.lines.length,
            execution.line + CONTEXT_LINES_AFTER,
          );
          const sourceStart = Math.max(1, artifact.producer.uploadLine - 3);
          const sourceEnd = Math.min(
            artifact.producer.workflowLines.length,
            artifact.producer.uploadLine + 4,
          );
          records.push({
            path: file.path,
            line: execution.line,
            categories: [...categories],
            priority: 130,
            startLine,
            endLine,
            excerpt: file.lines.slice(startLine - 1, endLine).join("\n"),
            sourceExcerpt: artifact.producer.workflowLines
              .slice(sourceStart - 1, sourceEnd)
              .join("\n"),
            frameworkModel: {
              schemaVersion: "1.2",
              id: "github-actions-artifact-poisoning-code-execution",
              language: "github-actions-yaml",
              scope: "cross-file",
              source: {
                kind: "untrusted-pull-request-artifact-upload",
                path: artifact.producer.workflowPath,
                line: artifact.producer.uploadLine,
              },
              sink: {
                kind: "privileged-artifact-code-execution",
                path: file.path,
                line: execution.line,
                cweIds: ["CWE-829"],
              },
              propagators: [
                {
                  kind: "untrusted-pull-request-checkout",
                  path: artifact.producer.workflowPath,
                  line: artifact.producer.checkoutLine,
                  symbol: `artifact=${artifact.producer.artifactName};path=${artifact.producer.artifactPath}`,
                },
                {
                  kind: "triggering-run-artifact-download",
                  path: file.path,
                  line: artifact.downloadLine,
                  symbol: `artifact=${artifact.producer.artifactName};workspace=${artifact.path}`,
                },
              ],
              candidateControls: distinctControls(controls),
            },
          });
        }
      }
    }
  }
  return records;
}

export function githubActionsPrivilegeRecords(
  path: string,
  lines: readonly string[],
  source: string,
): GithubActionsPrivilegeRecord[] {
  if (!/^\.github\/workflows\/[^/]+\.ya?ml$/iu.test(path)) return [];
  const parsed = parseWorkflow(source);
  if (parsed === undefined) return [];
  const { root, counter } = parsed;
  const triggerLine = privilegedPullRequestTriggerLine(root, counter);
  if (triggerLine === undefined) return [];
  const jobs = mapPair(root, "jobs")?.value;
  if (!isMap(jobs)) return [];
  const workflowPermission = mapPair(root, "permissions");
  const workflowWorkingDirectory = defaultRunWorkingDirectory(root);
  const workflowEnvironmentText = nodeText(mapPair(root, "env")?.value, source);
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
      if (checkout !== undefined && "trusted" in checkout) {
        if (checkout.cleans) {
          const trustedPath = checkout.path;
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
