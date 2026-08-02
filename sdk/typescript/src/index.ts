export { CopilotSecurity, scanAuthentication } from "./api.js";
export { estimateScanCost } from "./cost.js";
export type { ScanCost } from "./cost.js";
export { evaluateBenchmark } from "./benchmark.js";
export type {
  BenchmarkCase,
  BenchmarkCaseResult,
  BenchmarkFindingExpectation,
  BenchmarkLocationExpectation,
  BenchmarkManifest,
  BenchmarkMatch,
  BenchmarkMetrics,
  BenchmarkReport,
  BenchmarkRunResult,
  BenchmarkThresholdResult,
  BenchmarkThresholds,
} from "./benchmark.js";
export type {
  CopilotSecurityMetadata,
  ScanAuthMode,
  ScanAuthentication,
  ScanOptions,
  ScanPreflight,
  ScanReconnectDetails,
} from "./api.js";
export type { ScanWorkerPhase, ScanWorkerStatus } from "./worker-progress.js";
export { CopilotLoginHandle } from "./auth.js";
export type { AccountStatus, LoginResult } from "./auth.js";

export {
  AuthenticationRequiredError,
  CopilotSecurityError,
  ConfigurationError,
  ContractValidationError,
  IncompleteScanError,
  InvalidTargetError,
  ModelTransportInterruptedError,
  ModelTurnDeadlineExceededError,
  OutputDirectoryError,
  OutputInsideProtectedRootError,
  PluginBootstrapError,
  PluginPythonUnavailableError,
  ScanClosureIncompleteError,
  ScanCostLimitExceededError,
  ScanInterruptedError,
} from "./errors.js";
export type { ProtectedScanPathKind } from "./errors.js";
export {
  DEFAULT_COPILOT_CONFIG,
  mergedCopilotConfig,
  writeCopilotConfig,
} from "./config.js";
export type { CopilotSecurityConfig, JsonObject, JsonValue } from "./config.js";
export { loadContract, requireScanFile } from "./contract.js";
export type { LoadedContract, ScanExpectation } from "./contract.js";
export type * from "./models.js";
export { ScanResult } from "./result.js";
export type { ScanResultOptions, TurnResultMetadata } from "./result.js";
export {
  bootstrapPlugin,
  bundledPluginRoot,
  copilotSecurityCredentialHome,
  copilotSecurityStateDirectory,
  cleanupSdkDirectory,
  createIsolatedHome,
  createMarketplace,
  extractPluginZip,
  importAmbientAuth,
  MARKETPLACE_NAME,
  pluginExecutionEnvironment,
  pluginMetadata,
  PLUGIN_NAME,
  prepareCopilotSecurityCredentialHome,
  prepareOutputDir,
  resolveCopilotCommand,
  resolvePluginPath,
  resolvePluginPython,
  validateOutputDir,
} from "./runtime.js";
export type {
  CopilotCommand,
  PluginInstall,
  PluginPythonOptions,
  ProcessEnvironment,
} from "./runtime.js";
export {
  DiffTarget,
  normalizeRepository,
  normalizeTarget,
  repositoryRevision,
  validateMode,
} from "./targets.js";
export type { NormalizedTarget, ScanMode, ScanTarget } from "./targets.js";
export { BUNDLED_PLUGIN_VERSION, VERSION } from "./version.js";
