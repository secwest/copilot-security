import { formatUsd, type ScanCost } from "./cost.js";

/** Base error for Copilot Security SDK failures. */
export class CopilotSecurityError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class ConfigurationError extends CopilotSecurityError {}
export class AuthenticationRequiredError extends CopilotSecurityError {}
export class PluginBootstrapError extends CopilotSecurityError {}
export class PluginPythonUnavailableError extends PluginBootstrapError {}
export class InvalidTargetError extends CopilotSecurityError {}
export class OutputDirectoryError extends CopilotSecurityError {}
export type ProtectedScanPathKind = "output" | "temporary" | "runtime";

export class OutputInsideProtectedRootError extends OutputDirectoryError {
  public constructor(
    public readonly outputDirectory: string,
    public readonly protectedRoot: string,
    public readonly pathKind: ProtectedScanPathKind = "output",
  ) {
    super(
      `Scan ${pathKind} directory must be outside the protected scan root: ${outputDirectory}`,
    );
  }
}
export class IncompleteScanError extends CopilotSecurityError {}
export class ModelTurnDeadlineExceededError extends IncompleteScanError {
  public readonly timeoutMilliseconds: number;

  public constructor(timeoutMilliseconds: number) {
    super(
      `Copilot model turn exceeded the ${timeoutMilliseconds} millisecond scanner deadline.`,
    );
    this.timeoutMilliseconds = timeoutMilliseconds;
  }
}
export class ModelTransportInterruptedError extends IncompleteScanError {
  public constructor() {
    super("Copilot model transport ended before the scanner turn completed.");
  }
}
export class SafetyClassifierRetriesExhaustedError extends IncompleteScanError {
  public constructor(
    public readonly promptAttempts: number,
    options?: ErrorOptions,
  ) {
    super(
      `Copilot safety filtering rejected the authorized defensive scan after ${promptAttempts} prompt attempts.`,
      options,
    );
  }
}
export class CompleteDraftArtifactsError extends IncompleteScanError {}
export class ScanClosureIncompleteError extends IncompleteScanError {
  public constructor(
    public readonly findingQualityGapCount: number,
    public readonly coverageGapCount: number,
    options?: ErrorOptions,
  ) {
    super(
      `Copilot correction left ${findingQualityGapCount} finding-quality gap(s) and ${coverageGapCount} coverage gap(s) after the bounded repair turn.`,
      options,
    );
  }
}
export class ContractValidationError extends CopilotSecurityError {}
export type SourceDiscoveryOperation =
  | "enumerate"
  | "inspect"
  | "canonicalize"
  | "read";

export class SourceDiscoveryError extends IncompleteScanError {
  public readonly repositoryPath: string;

  public constructor(
    public readonly operation: SourceDiscoveryOperation,
    repositoryPath: string,
    options?: ErrorOptions,
  ) {
    const normalizedPath = repositoryPath.replaceAll("\\", "/") || ".";
    const codePoints = [...normalizedPath];
    const boundedPath =
      codePoints.length <= 512
        ? normalizedPath
        : `${codePoints.slice(0, 512).join("")}…`;
    super(
      `Source discovery could not ${operation} repository path ${JSON.stringify(boundedPath)}; scan coverage is incomplete.`,
      options,
    );
    this.repositoryPath = boundedPath;
  }
}
export class ScanInterruptedError extends CopilotSecurityError {
  public readonly scanDir: string;

  public constructor(message: string, scanDir: string, options?: ErrorOptions) {
    super(message, options);
    this.scanDir = scanDir;
  }
}

export class ScanCostLimitExceededError extends ScanInterruptedError {
  public readonly maxCostUsd: number;
  public readonly cost: Readonly<ScanCost>;

  public constructor(
    maxCostUsd: number,
    cost: Readonly<ScanCost>,
    scanDir: string,
  ) {
    super(
      `Scan stopped: estimated cost ${formatUsd(cost.estimatedUsd)} exceeded the ${formatUsd(maxCostUsd)} limit; partial output remains at ${scanDir}.`,
      scanDir,
    );
    this.maxCostUsd = maxCostUsd;
    this.cost = cost;
  }
}
