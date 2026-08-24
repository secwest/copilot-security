import { statSync } from "node:fs";
import { join } from "node:path";
import type {
  CoverageDocument,
  FindingsDocument,
  ScanManifest,
} from "./models.js";
import { estimateScanCost, type ScanCost } from "./cost.js";

export interface TurnResultMetadata {
  id?: string;
  status?: string;
  model?: string;
  durationMs?: number;
  finalResponse?: string;
  usage?: unknown;
  [key: string]: unknown;
}

export interface ScanResultOptions {
  manifest: ScanManifest;
  findings: FindingsDocument;
  coverage: CoverageDocument;
  scanDir: string;
  threadId: string;
  turnResult: TurnResultMetadata;
  sarifPath?: string | null;
}

export class ScanResult {
  public readonly manifest: ScanManifest;
  public readonly findings: FindingsDocument;
  public readonly coverage: CoverageDocument;
  public readonly scanDir: string;
  public readonly threadId: string;
  public readonly turnResult: Readonly<TurnResultMetadata>;
  public readonly cost: Readonly<ScanCost> | null;
  public readonly sarifPath: string | null;

  public constructor(options: ScanResultOptions) {
    this.manifest = options.manifest;
    this.findings = options.findings;
    this.coverage = options.coverage;
    this.scanDir = options.scanDir;
    this.threadId = options.threadId;
    this.turnResult = options.turnResult;
    this.cost = estimateScanCost(
      options.turnResult.model,
      options.turnResult.usage,
    );
    if (options.sarifPath !== undefined) {
      this.sarifPath = options.sarifPath;
    } else {
      const defaultSarifPath = join(
        options.scanDir,
        "exports",
        "results.sarif",
      );
      try {
        this.sarifPath = statSync(defaultSarifPath, {
          throwIfNoEntry: false,
        })?.isFile()
          ? defaultSarifPath
          : null;
      } catch {
        this.sarifPath = null;
      }
    }
  }

  public get reportPath(): string {
    return join(this.scanDir, "report.md");
  }

  public get pluginVersion(): string {
    return this.manifest.scan.producer.version;
  }

  public get manifestPath(): string {
    return join(this.scanDir, "scan-manifest.json");
  }

  public get findingsPath(): string {
    return join(this.scanDir, "findings.json");
  }

  public get coveragePath(): string {
    return join(this.scanDir, "coverage.json");
  }

  public get artifactsDir(): string {
    return join(this.scanDir, "artifacts");
  }

  public get externalSarifSeedCoveragePath(): string | null {
    const reference = this.coverage.surfaces
      .find((surface) => surface.id === "external-sarif-seed-closure")
      ?.receiptRefs.find(
        (path) =>
          path === "artifacts/03_coverage/external_sarif_seed_coverage.json",
      );
    return reference === undefined
      ? null
      : join(this.scanDir, ...reference.split("/"));
  }

  public toJSON(): Record<string, unknown> {
    return {
      manifest: this.manifest,
      findings: this.findings,
      coverage: this.coverage,
      scanDir: this.scanDir,
      threadId: this.threadId,
      reportPath: this.reportPath,
      artifactsDir: this.artifactsDir,
      externalSarifSeedCoveragePath: this.externalSarifSeedCoveragePath,
      sarifPath: this.sarifPath,
      cost: this.cost,
      turn: this.turnResult,
    };
  }
}
