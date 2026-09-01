import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import {
  buildFindingQualityGapInventory,
  buildResidualRiskInventory,
} from "../src/residual-risk.js";

interface FrameworkRecord {
  frameworkModel?: {
    id: string;
    source: { kind: string; path: string; line: number };
    sink: { kind: string; path: string; line: number; cweIds: string[] };
    propagators: Array<{
      kind: string;
      path: string;
      line: number;
      symbol?: string;
    }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function sendFileRecords(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-express-sendfile-path-disclosure",
    );
}

async function fixtureRecords(name: string): Promise<FrameworkRecord[]> {
  return sendFileRecords(
    await buildResidualRiskInventory(join(benchmarkRoot, "fixtures", name)),
  );
}

async function scanSource(
  source: string,
  options: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    sourcePath?: string;
  } = {},
): Promise<FrameworkRecord[]> {
  const repository = await mkdtemp(join(tmpdir(), "express-sendfile-model-"));
  temporaryPaths.push(repository);
  await writeFile(
    join(repository, "package.json"),
    JSON.stringify({
      name: "express-sendfile-model",
      private: true,
      type: "module",
      dependencies: options.dependencies ?? { express: "5.2.1" },
      devDependencies: options.devDependencies,
    }),
  );
  const path = join(repository, options.sourcePath ?? "server.js");
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, source);
  return sendFileRecords(await buildResidualRiskInventory(repository));
}

function downloadRoute(
  options: {
    importLine?: string;
    instance?: string;
    path?: string;
    route?: string;
    sink?: string;
  } = {},
): string {
  return [
    options.importLine ?? 'import express from "express";',
    options.instance ?? "const app = express();",
    options.route ?? 'app.get("/download", (request, response) => {',
    options.path ?? "  const requestedPath = request.query.path;",
    options.sink ?? "  return response.sendFile(requestedPath);",
    "});",
  ].join("\n");
}

describe("Express sendFile path-disclosure model", () => {
  test("keeps a strict executable exploit/control benchmark contract", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "node-express-sendfile-path-disclosure-manifest.json",
        ),
        "utf8",
      ),
    );
    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }: { id: string }) => id)).toEqual([
      "node-express-sendfile-path-disclosure",
      "node-express-root-confined-sendfile",
    ]);
    expect(manifest.cases[0].expected[0]).toMatchObject({
      id: "node-express-sendfile-path-disclosure",
      cwe: ["CWE-22"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(
      manifest.cases[0].expected[0].requiredValidationTextAnyOf,
    ).toHaveLength(8);
    expect(
      manifest.cases[0].expected[0].requiredAttackPathTextAnyOf,
    ).toHaveLength(6);
    expect(manifest.cases[0].expected[0].forbiddenText.length).toBeGreaterThan(
      0,
    );
    expect(manifest.cases[1].expected).toEqual([]);
  });

  test("detects the vulnerable fixture and rejects the fixed-root twin", async () => {
    const vulnerable = await fixtureRecords(
      "node-express-sendfile-path-disclosure",
    );
    const control = await fixtureRecords("node-express-root-confined-sendfile");
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]?.frameworkModel).toMatchObject({
      id: "node-express-sendfile-path-disclosure",
      source: {
        kind: "express-request-query-string",
        path: "src/server.js",
        line: 6,
      },
      sink: {
        kind: "express-response-sendfile-filesystem-read",
        path: "src/server.js",
        line: 7,
        cweIds: ["CWE-22"],
      },
      propagators: expect.arrayContaining([
        expect.objectContaining({
          kind: "express-runtime-dependency",
          symbol: "express@5.2.1:manifest-exact",
        }),
        expect.objectContaining({
          kind: "express-literal-route-registration",
          symbol: "/download",
        }),
      ]),
      candidateControls: [
        expect.objectContaining({
          kind: "express-sendfile-root-option-absent",
          line: 7,
        }),
      ],
    });
    expect(control).toHaveLength(0);
  });

  test("supports Express 4 Router route parameters and named handlers", async () => {
    const source = [
      'const express = require("express");',
      "const router = express.Router();",
      "function download(request, response) {",
      "  const requestedPath = request.params.file;",
      "  return response.sendFile(requestedPath);",
      "}",
      'router.get("/download/:file", download);',
    ].join("\n");
    const records = await scanSource(source, {
      dependencies: { express: "4.22.1" },
      sourcePath: "server.cjs",
    });
    expect(records).toHaveLength(1);
    expect(records[0]?.frameworkModel).toMatchObject({
      source: { kind: "express-request-route-parameter", line: 4 },
      sink: { line: 5 },
      propagators: expect.arrayContaining([
        expect.objectContaining({
          kind: "express-router-factory-binding",
          symbol: "router",
        }),
      ]),
    });
  });

  test("recognizes exact missing-root signatures", async () => {
    for (const sink of [
      "  return response.sendFile(requestedPath);",
      '  return response.sendFile(requestedPath, { dotfiles: "deny" });',
      "  return response.sendFile(requestedPath, (error) => void error);",
      "  return response.sendFile(requestedPath, {}, done);",
    ]) {
      expect(await scanSource(downloadRoute({ sink }))).toHaveLength(1);
    }
  });

  test("executes real Express disclosure and root-confinement witnesses", () => {
    const outputs = [
      "node-express-sendfile-path-disclosure",
      "node-express-root-confined-sendfile",
    ].map((fixture) => {
      const result = spawnSync(
        "node",
        [join(benchmarkRoot, "fixtures", fixture, "examples", "witness.mjs")],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            COPILOT_SECURITY_EXPRESS_MODULE_URL: pathToFileURL(
              join(process.cwd(), "node_modules", "express", "index.js"),
            ).href,
          },
          shell: false,
        },
      );
      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      return JSON.parse(result.stdout);
    });
    expect(outputs).toEqual([
      {
        allowed_file_served: true,
        attack_disclosed_outside_file: true,
        attack_status: 200,
        control: false,
        listener_started: false,
        network_request_sent: false,
      },
      {
        allowed_file_served: true,
        attack_disclosed_outside_file: false,
        attack_status: 404,
        control: true,
        listener_started: false,
        network_request_sent: false,
      },
    ]);
  });

  test("accepts only fixed absolute roots as a complete control", async () => {
    for (const source of [
      downloadRoute({
        sink: '  return response.sendFile(requestedPath, { root: "/srv/downloads" });',
      }),
      [
        'import express from "express";',
        'const DOWNLOAD_ROOT = "C:\\\\service\\\\downloads";',
        "const app = express();",
        'app.get("/download", (request, response) => {',
        "  const requestedPath = request.query.path;",
        "  return response.sendFile(requestedPath, { root: DOWNLOAD_ROOT });",
        "});",
      ].join("\n"),
      [
        'import express from "express";',
        'const OPTIONS = { root: "/srv/downloads", dotfiles: "deny" };',
        "const app = express();",
        'app.get("/download", (request, response) => {',
        "  const requestedPath = request.query.path;",
        "  return response.sendFile(requestedPath, OPTIONS);",
        "});",
      ].join("\n"),
    ]) {
      expect(await scanSource(source)).toHaveLength(0);
    }
  });

  test("fails closed on ambiguous root and options expressions", async () => {
    for (const sink of [
      "  return response.sendFile(requestedPath, options);",
      "  return response.sendFile(requestedPath, { ...options });",
      "  return response.sendFile(requestedPath, { root: process.env.DOWNLOAD_ROOT });",
      '  return response.sendFile(requestedPath, { root: "downloads" });',
      "  return response.sendFile(requestedPath, { [optionName]: root });",
      "  return response.sendFile(requestedPath, rootOrCallback);",
    ]) {
      expect(await scanSource(downloadRoute({ sink }))).toHaveLength(0);
    }
    for (const mutation of [
      "OPTIONS.root = request.query.root;",
      'OPTIONS["root"] = request.query.root;',
      "Object.assign(OPTIONS, { root: request.query.root });",
    ]) {
      const source = [
        'import express from "express";',
        'const OPTIONS = { root: "/srv/downloads" };',
        "const app = express();",
        'app.get("/download", (request, response) => {',
        "  const requestedPath = request.query.path;",
        `  ${mutation}`,
        "  return response.sendFile(requestedPath, OPTIONS);",
        "});",
      ].join("\n");
      expect(await scanSource(source)).toHaveLength(0);
    }
  });

  test("requires exact production dependencies and official identities", async () => {
    const dependencyCases: Array<Record<string, string>> = [
      { express: "3.21.2" },
      { express: "^5.2.0" },
      {},
    ];
    for (const dependencies of dependencyCases) {
      expect(await scanSource(downloadRoute(), { dependencies })).toHaveLength(
        0,
      );
    }
    expect(
      await scanSource(downloadRoute(), {
        dependencies: {},
        devDependencies: { express: "5.2.1" },
      }),
    ).toHaveLength(0);
    expect(
      await scanSource(
        downloadRoute({ importLine: 'import express from "./express.js";' }),
      ),
    ).toHaveLength(0);
    expect(
      await scanSource(downloadRoute(), { sourcePath: "test/server.test.js" }),
    ).toHaveLength(0);
  });

  test("rejects rebound framework and request-response identities", async () => {
    expect(
      await scanSource(
        downloadRoute().replace(
          "const app = express();",
          "express = localFactory;\nconst app = express();",
        ),
      ),
    ).toHaveLength(0);
    for (const mutation of ["app = otherApp;", "app.get = localGet;"]) {
      const source = downloadRoute().replace(
        'app.get("/download",',
        `${mutation}\napp.get("/download",`,
      );
      expect(await scanSource(source)).toHaveLength(0);
    }
    for (const mutation of [
      "  request = trustedRequest;",
      "  response = otherResponse;",
      "  response.sendFile = localSendFile;",
    ]) {
      const source = downloadRoute().replace(
        "  const requestedPath",
        `${mutation}\n  const requestedPath`,
      );
      expect(await scanSource(source)).toHaveLength(0);
    }
  });

  test("retains path.resolve because it preserves attacker absolute-path selection", async () => {
    expect(
      await scanSource(
        downloadRoute({
          path: "  const requestedPath = path.resolve(request.query.path);",
        }),
      ),
    ).toHaveLength(1);
  });

  test("requires a literal route and query or route-parameter flow", async () => {
    for (const source of [
      downloadRoute().replace('"/download"', "routePath"),
      downloadRoute({
        path: '  const requestedPath = "/srv/public/readme.txt";',
      }),
      downloadRoute({ path: "  const requestedPath = request.body.path;" }),
      downloadRoute({
        sink: "  return otherResponse.sendFile(requestedPath);",
      }),
    ]) {
      expect(await scanSource(source)).toHaveLength(0);
    }
  });

  test("requires filesystem boundary evidence in validation and attack path", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "node-express-sendfile-path-disclosure",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(join(tmpdir(), "sendfile-quality-"));
    temporaryPaths.push(scanDirectory);
    const finding: any = {
      occurrenceId: "occ_express_sendfile",
      taxonomy: { cwe: ["CWE-22"] },
      locations: [
        { path: "src/server.js", startLine: 6, role: "source" },
        { path: "src/server.js", startLine: 7, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "path-source",
          path: "src/server.js",
          startLine: 6,
          code: "const requestedPath = request.query.path;",
          explanation: "The route reads a remote path.",
          role: "source",
        },
        {
          id: "path-sink",
          path: "src/server.js",
          startLine: 7,
          code: "return response.sendFile(requestedPath);",
          explanation: "Express reads the selected file.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A request path reaches sendFile.",
        method: "source review",
        evidence: ["path-source", "path-sink"],
      },
      attackPath: {
        summary: "A request path reaches sendFile.",
        dataflow: {
          source: "path-source",
          sink: "path-sink",
          outcome: "file read",
        },
        evidenceRefs: ["path-source", "path-sink"],
      },
    };
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );
    const incomplete = await buildFindingQualityGapInventory(
      scanDirectory,
      repository,
      inventory,
    );
    expect(incomplete).toContain("missing_model_specific_validation_evidence");
    expect(incomplete).toContain("missing_model_specific_attack_path_evidence");

    const contract =
      "Express 5 registers the literal GET /download handler. Its request.query path is a remote path passed to response.sendFile, crossing a filesystem read into the host filesystem. With the root option absent, an attacker-selected absolute path can select files readable with the service account permissions. A fixed absolute root is the framework-native control. This is CWE-22 path traversal and possible file disclosure.";
    finding.validation.summary = contract;
    finding.attackPath.summary = contract;
    await writeFile(
      join(scanDirectory, "findings.json"),
      JSON.stringify({ findings: [finding] }),
    );
    const complete = await buildFindingQualityGapInventory(
      scanDirectory,
      repository,
      inventory,
    );
    expect(complete).not.toContain(
      "missing_model_specific_validation_evidence",
    );
    expect(complete).not.toContain(
      "missing_model_specific_attack_path_evidence",
    );
  });

  test("teaches the reviewer the exact Express filesystem boundary", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"node-express-sendfile-path-disclosure"}}',
    );
    expect(prompt).toContain("node-express-sendfile-path-disclosure");
    expect(prompt).toContain("response.sendFile");
    expect(prompt).toContain("fixed operator-owned absolute root");
    expect(prompt).toContain("attacker-selected absolute host path");
    expect(prompt).toContain("service-account read permissions");
    expect(prompt).toContain("CWE-22");
    expect(prompt).toContain("inert temporary marker files");
  });
});
